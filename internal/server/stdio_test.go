//go:build linux || darwin

package server

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/byward-dev/byward/internal/audit"
	"github.com/byward-dev/byward/internal/config"
	"github.com/byward-dev/byward/internal/logging"
	"github.com/byward-dev/byward/internal/mcpsession"
	"github.com/byward-dev/byward/internal/resource"
	"github.com/byward-dev/byward/internal/token"
	"github.com/byward-dev/byward/internal/upstream/stdio"
)

// fakeStdio builds the fake stdio upstream once for the package, into fakeStdioDir (#298).
var fakeStdio = sync.OnceValues(func() (string, error) {
	dir, err := os.MkdirTemp("", "fakestdio-")
	if err != nil {
		return "", err
	}
	fakeStdioDir = dir // before the build, so a failed one is removed too
	bin := filepath.Join(dir, "fakestdio")
	out, err := exec.Command("go", "build", "-o", bin, "../testutil/fakestdio").CombinedOutput() //nolint:gosec // G204: fixed go command; bin is our temp path
	if err != nil {
		return "", &buildError{out: string(out), err: err}
	}
	return bin, nil
})

type buildError struct {
	out string
	err error
}

func (e *buildError) Error() string {
	return "build fake stdio upstream: " + e.err.Error() + "\n" + e.out
}

// stdioProxy serves the fake stdio upstream behind Guard and the wired session binding, as New
// would, with users alice and bob.
func stdioProxy(t *testing.T, env ...string) (*httptest.Server, *config.Config, *syncBuffer) {
	t.Helper()
	return stdioProxyRunning(t, []string{"-mcp"}, env...)
}

// stdioProxyRunning is stdioProxy with the fake upstream's flags.
func stdioProxyRunning(t *testing.T, flags []string, env ...string) (*httptest.Server, *config.Config, *syncBuffer) {
	t.Helper()
	bin, err := fakeStdio()
	if err != nil {
		t.Fatal(err)
	}
	envFile := filepath.Join(t.TempDir(), "upstream-env")
	if err := os.WriteFile(envFile, []byte("FOO=bar\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	all := append(authEnv(t), "BYWARD_PUBLIC_URL=https://mcp.example.com/mcp", "BYWARD_UPSTREAM_ENV_FILE="+envFile)
	cfg, _, err := config.Load(append([]string{"--", bin}, flags...), append(all, env...), os.ReadFile)
	if err != nil {
		t.Fatal(err)
	}
	logs := &syncBuffer{}
	log := slog.New(slog.NewJSONHandler(logs, nil))
	o := Observability{Audit: audit.New(log, nil, time.Now)}
	up, err := newUpstream(cfg, log, o, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = up.shutdown(ctx)
	})
	a, err := buildAuth(cfg, log, o)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { stop(t, a) })
	srv := httptest.NewServer(Handler(cfg, log, up.handler, twoUsers{"tok-alice": "tid:alice", "tok-bob": "tid:bob"}, nil, a.sessions, o))
	t.Cleanup(srv.Close)
	return srv, cfg, logs
}

// mcpPost sends one JSON-RPC message and returns the response and its SSE data lines.
func mcpPost(t *testing.T, srv *httptest.Server, token, session, body string, header ...string) (*http.Response, []string) {
	t.Helper()
	r, _ := http.NewRequest(http.MethodPost, srv.URL+"/mcp", strings.NewReader(body))
	r.Host = "mcp.example.com"
	r.Header.Set("Authorization", "Bearer "+token)
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Accept", "application/json, text/event-stream")
	if session != "" {
		r.Header.Set(mcpsession.Header, session)
	}
	for i := 0; i+1 < len(header); i += 2 {
		r.Header.Set(header[i], header[i+1])
	}
	res, err := http.DefaultClient.Do(r)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = res.Body.Close() }()
	var events []string
	sc := bufio.NewScanner(res.Body)
	for sc.Scan() {
		if d, ok := strings.CutPrefix(sc.Text(), "data: "); ok {
			events = append(events, d)
		}
	}
	_, _ = io.Copy(io.Discard, res.Body)
	return res, events
}

const initializeBody = `{"jsonrpc":"2.0","id":0,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"t","version":"0"}}}`

// processEnv returns the environment of the session's upstream process.
func processEnv(t *testing.T, srv *httptest.Server, token, session string) []string {
	t.Helper()
	res, events := mcpPost(t, srv, token, session, `{"jsonrpc":"2.0","id":1,"method":"env"}`)
	var m struct{ Result []string }
	if res.StatusCode != http.StatusOK || len(events) != 1 || json.Unmarshal([]byte(events[0]), &m) != nil {
		t.Fatalf("env: status %d, events %q", res.StatusCode, events)
	}
	return m.Result
}

// Invariant 13 for stdio: each legacy-era session has its own process, acting for the user who
// started it, and its session ID is usable by that user only.
func TestEachStdioMCPSessionIsItsOwnUpstreamProcessBoundToItsUserWithNoTokenOrProxySetting(t *testing.T) {
	srv, cfg, logs := stdioProxy(t)
	res, _ := mcpPost(t, srv, "tok-alice", "", initializeBody)
	id := res.Header.Get(mcpsession.Header)
	if res.StatusCode != http.StatusOK || !strings.HasPrefix(id, mcpsession.Prefix) {
		t.Fatalf("initialize: %d, session %q; want a sealed ID", res.StatusCode, id)
	}
	ring, err := token.LoadKeyRing(cfg.KeysDir)
	if err != nil {
		t.Fatal(err)
	}
	box, _ := token.NewBox(ring, "mcp-session", nil)
	plain, err := box.Open(strings.TrimPrefix(id, mcpsession.Prefix))
	var bound struct{ S, U, X string }
	if err != nil || json.Unmarshal(plain, &bound) != nil || bound.U != "tid:alice" || bound.X != "stdio:fakestdio" || len(bound.S) != 43 {
		t.Fatalf("the session ID opens as %s (%v); want alice, stdio:fakestdio and a proxy-issued session", plain, err)
	}

	env := processEnv(t, srv, "tok-alice", id)
	for _, want := range []string{"BYWARD_SUBJECT=tid:alice", "BYWARD_ISSUER=https://mcp.example.com", "FOO=bar"} {
		if !slices.Contains(env, want) {
			t.Errorf("upstream env lacks %s: %q", want, env)
		}
	}
	for _, kv := range env {
		k, _, _ := strings.Cut(kv, "=")
		if strings.Contains(kv, "tok-alice") || (strings.HasPrefix(k, "BYWARD_") && k != "BYWARD_SUBJECT" && k != "BYWARD_ISSUER") {
			t.Errorf("upstream env carries %q: no token or proxy setting may reach it", k)
		}
	}

	if res, _ := mcpPost(t, srv, "tok-bob", id, `{"jsonrpc":"2.0","id":1,"method":"env"}`); res.StatusCode != http.StatusNotFound {
		t.Fatalf("bob with alice's session: %d, want 404", res.StatusCode)
	}
	if !strings.Contains(logs.String(), `"event":"session_rejected"`) {
		t.Fatal("bob's attempt was not audited")
	}
	res, _ = mcpPost(t, srv, "tok-bob", "", initializeBody)
	bobID := res.Header.Get(mcpsession.Header)
	if !slices.Contains(processEnv(t, srv, "tok-bob", bobID), "BYWARD_SUBJECT=tid:bob") {
		t.Fatal("bob's session does not run as bob")
	}
	if !slices.Contains(processEnv(t, srv, "tok-alice", id), "BYWARD_SUBJECT=tid:alice") {
		t.Fatal("alice's session changed user")
	}
}

func TestEvictionAtTheUserCapIsAuditedAndEndsTheEvictedMCPSession(t *testing.T) {
	srv, _, logs := stdioProxy(t, "BYWARD_STDIO_MAX_PROCESSES_PER_USER=1")
	first, _ := mcpPost(t, srv, "tok-alice", "", initializeBody)
	if second, _ := mcpPost(t, srv, "tok-alice", "", initializeBody); second.StatusCode != http.StatusOK {
		t.Fatalf("second session: %d, want 200 after evicting the idle first one", second.StatusCode)
	}
	var rec struct {
		Reason  string
		UserKey string `json:"user_key"`
	}
	deadline := time.Now().Add(10 * time.Second)
	for {
		if line, ok := auditRecord(logs.String(), "process_evicted"); ok {
			if err := json.Unmarshal([]byte(line), &rec); err != nil {
				t.Fatal(err)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("no process_evicted audit record")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if rec.Reason != "user_cap" || rec.UserKey != "tid:alice" {
		t.Fatalf("eviction record has reason %q, user %q; want user_cap and tid:alice", rec.Reason, rec.UserKey)
	}
	if res, _ := mcpPost(t, srv, "tok-alice", first.Header.Get(mcpsession.Header), `{"jsonrpc":"2.0","id":1,"method":"env"}`); res.StatusCode != http.StatusNotFound {
		t.Fatalf("the evicted session: %d, want 404", res.StatusCode)
	}
}

func TestMissingStdioCommandFailsStartupNamingTheImagePattern(t *testing.T) {
	cfg, _, err := config.Load([]string{"--", "node", "server.js"},
		[]string{"BYWARD_PUBLIC_URL=http://127.0.0.1:8080/mcp", "BYWARD_INSECURE_NO_AUTH=true", "PATH=/nonexistent"}, os.ReadFile)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", "/nonexistent")
	_, err = New(cfg, slog.New(slog.DiscardHandler))
	if err == nil || !strings.Contains(err.Error(), "BYWARD_UPSTREAM_COMMAND") || !strings.Contains(err.Error(), "COPY --from=ghcr.io/byward-dev/byward") {
		t.Fatalf("New = %v, want an error naming the setting and the COPY --from pattern", err)
	}
}

// auditRecord returns the first audit record for event in JSON log output.
func auditRecord(logs, event string) (string, bool) {
	for _, line := range strings.Split(logs, "\n") {
		var r struct{ Event string }
		if json.Unmarshal([]byte(line), &r) == nil && r.Event == event {
			return line, true
		}
	}
	return "", false
}

// New and Run with a stdio upstream and no authentication: the process runs as the anonymous user,
// the gauge counts it, and Run stops it.
func TestStdioUpstreamWithoutAuthenticationRunsAsTheAnonymousUserAndStopsWithRun(t *testing.T) {
	bin, err := fakeStdio()
	if err != nil {
		t.Fatal(err)
	}
	cfg, _, err := config.Load([]string{"--", bin, "-mcp"}, []string{"BYWARD_PUBLIC_URL=http://127.0.0.1:8080/mcp",
		"BYWARD_INSECURE_NO_AUTH=true", "BYWARD_LISTEN=127.0.0.1:0", "BYWARD_INTERNAL_LISTEN=127.0.0.1:0"}, os.ReadFile)
	if err != nil {
		t.Fatal(err)
	}
	s, err := New(cfg, discard)
	if err != nil {
		t.Fatal(err)
	}
	front := httptest.NewServer(s.Public.Handler)
	t.Cleanup(front.Close)
	post := func(session, body string) *http.Response {
		r, _ := http.NewRequest(http.MethodPost, front.URL+"/mcp", strings.NewReader(body))
		r.Host = "127.0.0.1:8080"
		r.Header.Set("Accept", "application/json, text/event-stream")
		if session != "" {
			r.Header.Set(mcpsession.Header, session)
		}
		res, err := http.DefaultClient.Do(r)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = res.Body.Close() })
		return res
	}
	res := post("", initializeBody)
	_, _ = io.Copy(io.Discard, res.Body)
	env, _ := io.ReadAll(post(res.Header.Get(mcpsession.Header), `{"jsonrpc":"2.0","id":1,"method":"env"}`).Body)
	for _, want := range []string{"BYWARD_SUBJECT=anonymous", "BYWARD_ISSUER=urn:byward:no-auth"} {
		if !strings.Contains(string(env), want) {
			t.Fatalf("upstream env lacks %s: %s", want, env)
		}
	}
	gauge := func() string {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
		req.Host = "127.0.0.1:9090" // the internal listener accepts IP literals and localhost only
		s.Internal.Handler.ServeHTTP(rec, req)
		for _, line := range strings.Split(rec.Body.String(), "\n") {
			if strings.HasPrefix(line, "byward_stdio_processes ") {
				return line
			}
		}
		return "no byward_stdio_processes"
	}
	if got := gauge(); got != "byward_stdio_processes 1" {
		t.Fatalf("gauge %q with one MCP session", got)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := Run(ctx, s, discard); err != nil {
		t.Fatal(err)
	}
	if got := gauge(); got != "byward_stdio_processes 0" {
		t.Fatalf("gauge %q after Run returned: the upstream processes were left running", got)
	}
}

func TestUpstreamProcessActsForTheTokensSubjectUnderTheProxysIssuerAndNeedsASubject(t *testing.T) {
	cfg := &config.Config{PublicURL: &url.URL{Scheme: "https", Host: "mcp.example.com", Path: "/mcp"}}
	identity := stdioIdentity(cfg)
	if _, ok := identity(httptest.NewRequest(http.MethodPost, "/mcp", nil)); ok {
		t.Fatal("a request without an identity has a stdio identity")
	}
	users := identities{"tok-alice": {Subject: "tid:alice", GrantID: "grant-a", ClientID: "client-a"}, "tok-empty": {}}
	for token, want := range map[string]stdio.Identity{
		// The grant and client are the request's, for the process's downstream token (ADR-0017).
		"tok-alice": {Subject: "tid:alice", Issuer: "https://mcp.example.com", Grant: "grant-a", Client: "client-a"},
		"tok-empty": {}, // no subject: no user, so no process may start for it
	} {
		var got stdio.Identity
		var ok, reached bool
		resource.Guard(resource.Metadata{Resource: cfg.PublicURL}, users, nil,
			http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) { reached = true; got, ok = identity(r) })).
			ServeHTTP(httptest.NewRecorder(), withBearer(httptest.NewRequest(http.MethodPost, "/mcp", nil), token))
		if !reached {
			t.Fatalf("%s: Guard refused the request, so this test proves nothing", token)
		}
		if ok != (want.Subject != "") || (ok && got != want) {
			t.Fatalf("%s: identity %+v, %v; want %+v", token, got, ok, want)
		}
	}
}

// identities is a token validator that knows each token's whole identity.
type identities map[string]resource.Identity

func (u identities) Validate(_ context.Context, tok string) (resource.Identity, error) {
	if id, ok := u[tok]; ok {
		return id, nil
	}
	return resource.Identity{}, resource.ErrInvalid
}

func TestLooseUpstreamEnvFileRefusesToStartInEveryMode(t *testing.T) {
	bin, err := fakeStdio()
	if err != nil {
		t.Fatal(err)
	}
	envFile := filepath.Join(t.TempDir(), "upstream-env")
	if err := os.WriteFile(envFile, []byte("API_KEY=sk-live\n"), 0o644); err != nil { //nolint:gosec // G306: the loose mode is the point
		t.Fatal(err)
	}
	for name, env := range map[string][]string{
		"authenticated": append(authEnv(t), "BYWARD_PUBLIC_URL=https://mcp.example.com/mcp"),
		"no auth":       {"BYWARD_PUBLIC_URL=http://127.0.0.1:8080/mcp", "BYWARD_INSECURE_NO_AUTH=true"},
	} {
		t.Run(name, func(t *testing.T) {
			cfg, _, err := config.Load([]string{"--", bin, "-mcp"}, append(env, "BYWARD_UPSTREAM_ENV_FILE="+envFile), os.ReadFile)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := New(cfg, discard); err == nil || !strings.Contains(err.Error(), "BYWARD_UPSTREAM_ENV_FILE") {
				t.Fatalf("New = %v, want a refusal naming BYWARD_UPSTREAM_ENV_FILE", err)
			}
		})
	}
}

// #180, through Run: shutting down fails readiness and ends an open subscriptions/listen with its
// completion result under the client's own id before the stream closes, not by cutting it off
// (2026-07-28 subscriptions).
func TestShutdownFailsReadinessAndEndsAnOpenListenWithItsCompletionResultBeforeItsStreamCloses(t *testing.T) {
	for name, internal := range map[string]string{"with the internal listener": "127.0.0.1:0", "without it": ""} {
		t.Run(name, func(t *testing.T) { shutdownEndsAnOpenListen(t, internal) })
	}
}

func shutdownEndsAnOpenListen(t *testing.T, internalListen string) {
	bin, err := fakeStdio()
	if err != nil {
		t.Fatal(err)
	}
	cfg, _, err := config.Load([]string{"--", bin, "-modern"}, []string{"BYWARD_PUBLIC_URL=http://127.0.0.1:8080/mcp",
		"BYWARD_INSECURE_NO_AUTH=true", "BYWARD_LISTEN=127.0.0.1:0", "BYWARD_INTERNAL_LISTEN=" + internalListen}, os.ReadFile)
	if err != nil {
		t.Fatal(err)
	}
	logs := &listenWatcher{listening: make(chan struct{})}
	log := logging.New(logs, "json")
	s, err := New(cfg, log)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- Run(ctx, s, log) }()
	select {
	case <-logs.listening:
	case err := <-done:
		t.Fatalf("Run returned before listening: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not log its listening address within 5s")
	}
	body := `{"jsonrpc":"2.0","id":"L","method":"subscriptions/listen","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28",` +
		`"io.modelcontextprotocol/clientCapabilities":{}},"notifications":{"toolsListChanged":true}}}`
	r, _ := http.NewRequest(http.MethodPost, "http://"+listenLine.FindStringSubmatch(logs.String())[1]+"/mcp", strings.NewReader(body))
	r.Host = "127.0.0.1:8080"
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Accept", "application/json, text/event-stream")
	r.Header.Set("MCP-Protocol-Version", "2026-07-28")
	r.Header.Set("Mcp-Method", "subscriptions/listen")
	res, err := http.DefaultClient.Do(r)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = res.Body.Close() }()
	events := make(chan string)
	go func() {
		defer close(events)
		sc := bufio.NewScanner(res.Body)
		for sc.Scan() {
			if d, ok := strings.CutPrefix(sc.Text(), "data: "); ok {
				events <- d
			}
		}
	}()
	next := func(what string) (string, bool) {
		select {
		case d, ok := <-events:
			return d, ok
		case <-time.After(10 * time.Second):
			t.Fatalf("no %s within 10s", what)
			return "", false
		}
	}
	if ack, _ := next("acknowledgement"); !strings.Contains(ack, "notifications/subscriptions/acknowledged") {
		t.Fatalf("status %d, first event %s; want the acknowledgement", res.StatusCode, ack)
	}
	cancel()
	var rest []string
	for d, ok := next("completion result or end of stream"); ok; d, ok = next("end of stream") {
		rest = append(rest, d)
	}
	const complete = `{"jsonrpc":"2.0","id":"L","result":{"resultType":"complete","_meta":{"io.modelcontextprotocol/subscriptionId":"L"}}}`
	if len(rest) != 1 || !sameJSONValue(rest[0], complete) {
		t.Fatalf("after shutdown the listen got %q, want its completion result only, under its own id", rest)
	}
	probes := http.NewServeMux() // the upstream's drain comes with readiness failing, not instead of it
	s.Health.Register(probes)
	if code, body := getBody(t, probes, "x", "/readyz"); code != http.StatusServiceUnavailable || !strings.Contains(body, `"draining":"fail"`) {
		t.Fatalf("/readyz is %d %s once shutdown has begun, want 503 with draining failing", code, body)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Run did not return after cancel")
	}
}

// sameJSONValue reports whether got and want are the same JSON value, whatever the key order.
func sameJSONValue(got, want string) bool {
	var g, w any
	return json.Unmarshal([]byte(got), &g) == nil && json.Unmarshal([]byte(want), &w) == nil && reflect.DeepEqual(g, w)
}

// Invariant 13 in the modern era: each user's requests run in that user's own upstream process,
// through the real Guard and session binding, and no token reaches it.
func TestModernEraRequestsRunInTheUsersOwnUpstreamProcessWithNoToken(t *testing.T) {
	srv, _, _ := stdioProxyRunning(t, []string{"-modern"})
	env := func(token string) []string {
		body := `{"jsonrpc":"2.0","id":1,"method":"env","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}}}}`
		res, events := mcpPost(t, srv, token, "", body, "MCP-Protocol-Version", "2026-07-28", "Mcp-Method", "env")
		var m struct{ Result []string }
		if res.StatusCode != http.StatusOK || len(events) != 1 || json.Unmarshal([]byte(events[0]), &m) != nil {
			t.Fatalf("modern env: status %d, events %q", res.StatusCode, events)
		}
		return m.Result
	}
	for token, user := range map[string]string{"tok-alice": "tid:alice", "tok-bob": "tid:bob"} {
		got := env(token)
		if !slices.Contains(got, "BYWARD_SUBJECT="+user) {
			t.Fatalf("%s's modern request ran as %q", user, got)
		}
		for _, kv := range got {
			if strings.Contains(kv, "tok-") {
				t.Fatalf("a token reached the upstream process: %q", kv)
			}
		}
	}
}

func TestTheStdioUpstreamGetsTheStreamIdleTimeoutAndEachEvictionIsAuditedWithItsOpenStreams(t *testing.T) {
	cfg, _, err := config.Load([]string{"--", "/bin/server"}, append(authEnv(t), "BYWARD_PUBLIC_URL=https://mcp.example.com/mcp",
		"BYWARD_STDIO_STREAM_IDLE_TIMEOUT=15m"), os.ReadFile)
	if err != nil {
		t.Fatal(err)
	}
	logs := &syncBuffer{}
	log := logging.New(logs, "json") // the production logger: it drops any field it does not allow
	sc := stdioConfig(cfg, "server", log, Observability{Audit: audit.New(log, nil, time.Now)})
	if sc.StreamIdleTimeout != 15*time.Minute {
		t.Fatalf("stream idle timeout %s, want the configured 15m", sc.StreamIdleTimeout)
	}
	sc.Evicted(stdio.Eviction{ID: stdio.Identity{Subject: "tid:alice"}, Reason: "upstream_cap", OpenStreams: 2})
	line, ok := auditRecord(logs.String(), "process_evicted")
	var rec struct {
		Reason      string
		UserKey     string `json:"user_key"`
		OpenStreams int    `json:"open_streams"`
	}
	if !ok || json.Unmarshal([]byte(line), &rec) != nil {
		t.Fatalf("no process_evicted audit record in %q", logs.String())
	}
	if rec.Reason != "upstream_cap" || rec.UserKey != "tid:alice" || rec.OpenStreams != 2 {
		t.Fatalf("record %+v, want upstream_cap for tid:alice with 2 open streams", rec)
	}
}
