package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/byward-dev/byward/internal/audit"
	"github.com/byward-dev/byward/internal/config"
	"github.com/byward-dev/byward/internal/health"
	"github.com/byward-dev/byward/internal/logging"
	"github.com/byward-dev/byward/internal/resource"
	"github.com/byward-dev/byward/internal/testutil/fakeupstream"
	"github.com/byward-dev/byward/internal/token"
)

// goodToken is distinctive so a leak check cannot match ordinary text.
const goodToken = "tok-good-7f3a"

type acceptGood struct{}

func (acceptGood) Validate(_ context.Context, tok string) (resource.Identity, error) {
	if tok == goodToken {
		return resource.Identity{Subject: "tid:oid"}, nil
	}
	return resource.Identity{}, resource.ErrInvalid
}

type env struct {
	srv  *httptest.Server
	up   *fakeupstream.Server
	logs *syncBuffer
}

// syncBuffer is written by the server's goroutines and read by the test.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// start runs the proxy on a test listener; the public URL's host is set as the request Host.
func start(t *testing.T, extraEnv ...string) env {
	t.Helper()
	up := fakeupstream.New()
	t.Cleanup(up.Close)
	cfg, _, err := config.Load(nil, append(authEnv(t), append([]string{
		"BYWARD_PUBLIC_URL=https://mcp.example.com/mcp",
		"BYWARD_UPSTREAM_URL=" + up.URL + "/mcp",
		"BYWARD_ALLOWED_ORIGINS=https://app.example",
	}, extraEnv...)...), os.ReadFile)
	if err != nil {
		t.Fatal(err)
	}
	logs := &syncBuffer{}
	log := slog.New(slog.NewJSONHandler(logs, nil))
	srv := httptest.NewServer(Handler(cfg, log, acceptGood{}, nil, nil, Observability{Audit: audit.New(log, nil, time.Now)}))
	t.Cleanup(srv.Close)
	return env{srv, up, logs}
}

func (e env) do(t *testing.T, method, path string, body io.Reader, hdr map[string]string) *http.Response {
	t.Helper()
	r, err := http.NewRequest(method, e.srv.URL+path, body)
	if err != nil {
		t.Fatal(err)
	}
	r.Host = "mcp.example.com"
	for k, v := range hdr {
		r.Header.Set(k, v)
	}
	res, err := http.DefaultClient.Do(r)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = res.Body.Close() })
	return res
}

func TestUnauthenticatedPostGets401WhoseMetadataResolves(t *testing.T) {
	e := start(t)
	res := e.do(t, "POST", "/mcp", strings.NewReader(`{}`), nil)
	www := res.Header.Get("WWW-Authenticate")
	if res.StatusCode != 401 || !strings.Contains(www, `resource_metadata="https://mcp.example.com/.well-known/oauth-protected-resource/mcp"`) {
		t.Fatalf("code=%d www=%q", res.StatusCode, www)
	}
	for _, p := range []string{"/.well-known/oauth-protected-resource/mcp", "/.well-known/oauth-protected-resource"} {
		res := e.do(t, "GET", p, nil, nil)
		var d struct{ Resource string }
		if err := json.NewDecoder(res.Body).Decode(&d); err != nil || res.StatusCode != 200 || d.Resource != "https://mcp.example.com/mcp" {
			t.Fatalf("%s: code=%d resource=%q err=%v", p, res.StatusCode, d.Resource, err)
		}
	}
	if len(e.up.Requests()) != 0 {
		t.Fatal("unauthenticated request reached the upstream")
	}
}

func TestValidTokenIsRelayedWithoutIt(t *testing.T) {
	e := start(t)
	res := e.do(t, "POST", "/mcp", strings.NewReader(`{"jsonrpc":"2.0"}`), map[string]string{"Authorization": "Bearer " + goodToken, "Content-Type": "application/json"})
	b, _ := io.ReadAll(res.Body)
	if res.StatusCode != 200 || string(b) != `{"jsonrpc":"2.0"}` {
		t.Fatalf("code=%d body=%s", res.StatusCode, b)
	}
	got, _ := e.up.Last()
	if got.Header.Get("Authorization") != "" {
		t.Fatal("token passed through to the upstream")
	}
	if strings.Contains(e.logs.String(), goodToken) {
		t.Fatalf("token logged: %s", e.logs)
	}
}

func TestChecksRunBeforeAuthentication(t *testing.T) {
	e := start(t)
	// Wrong Origin: 403 even without a token.
	if res := e.do(t, "POST", "/mcp", nil, map[string]string{"Origin": "https://evil.example"}); res.StatusCode != 403 {
		t.Fatalf("origin: got %d", res.StatusCode)
	}
	if res := e.do(t, "POST", "/mcp", nil, map[string]string{"Origin": "https://app.example"}); res.StatusCode != 401 {
		t.Fatalf("allowed origin without token: got %d", res.StatusCode)
	}
	// Wrong Host: 421 on every route.
	for _, p := range []string{"/mcp", "/.well-known/oauth-protected-resource"} {
		r, _ := http.NewRequest("GET", e.srv.URL+p, nil)
		r.Host = "attacker.example"
		res, err := http.DefaultClient.Do(r)
		if err != nil {
			t.Fatal(err)
		}
		_ = res.Body.Close()
		if res.StatusCode != http.StatusMisdirectedRequest {
			t.Fatalf("%s host: got %d", p, res.StatusCode)
		}
	}
}

func TestAllowedHostsAccepted(t *testing.T) {
	e := start(t, "BYWARD_ALLOWED_HOSTS=proxy.internal:8080")
	r, _ := http.NewRequest("GET", e.srv.URL+"/.well-known/oauth-protected-resource", nil)
	r.Host = "proxy.internal:8080"
	res, err := http.DefaultClient.Do(r)
	if err != nil {
		t.Fatal(err)
	}
	_ = res.Body.Close()
	if res.StatusCode != 200 {
		t.Fatalf("got %d", res.StatusCode)
	}
}

func TestBodyOverLimitIs413AndAtLimitPasses(t *testing.T) {
	cases := []struct {
		name    string
		size    int
		chunked bool
		want    int
	}{
		{"at the limit, content-length", MaxMCPBody, false, http.StatusOK},
		{"over the limit, content-length", MaxMCPBody + 1, false, http.StatusRequestEntityTooLarge},
		{"at the limit, chunked", MaxMCPBody, true, http.StatusOK},
		{"over the limit, chunked", MaxMCPBody + 1, true, http.StatusRequestEntityTooLarge},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e := start(t)
			var body io.Reader = bytes.NewReader(make([]byte, c.size))
			if c.chunked {
				body = io.NopCloser(body) // hides the length, so the client sends chunked
			}
			r, _ := http.NewRequest("POST", e.srv.URL+"/mcp", body)
			r.Host = "mcp.example.com"
			r.Header.Set("Authorization", "Bearer "+goodToken)
			res, err := http.DefaultClient.Do(r)
			if err != nil {
				t.Fatal(err)
			}
			_ = res.Body.Close()
			if res.StatusCode != c.want {
				t.Fatalf("got %d want %d", res.StatusCode, c.want)
			}
			if c.want == http.StatusRequestEntityTooLarge && !c.chunked && len(e.up.Requests()) != 0 {
				t.Fatal("a body declared over the limit reached the upstream")
			}
		})
	}
}

// go-sdk servers reject a Host other than their own (DNS-rebinding protection, verified with
// go-sdk v1.8.0), so the public Host must never reach the upstream.
func TestUpstreamSeesItsOwnHost(t *testing.T) {
	e := start(t)
	e.do(t, "POST", "/mcp", strings.NewReader(`{}`), map[string]string{"Authorization": "Bearer " + goodToken})
	got, ok := e.up.Last()
	if !ok || got.Host != strings.TrimPrefix(e.up.URL, "http://") {
		t.Fatalf("upstream saw Host %q, want %q", got.Host, strings.TrimPrefix(e.up.URL, "http://"))
	}
}

func TestUnknownOrAmbiguousPathsNeverReachTheUpstream(t *testing.T) {
	e := start(t)
	cases := map[string]int{
		"/":             http.StatusNotFound,
		"/mcp/extra":    http.StatusNotFound,
		"/debug/pprof/": http.StatusNotFound,
		"/mcp;x":        http.StatusNotFound,
		"/MCP":          http.StatusNotFound,
		"/mcp/":         http.StatusNotFound,
		"/mcp%2F..":     http.StatusNotFound,
	}
	for p, want := range cases {
		if res := e.do(t, "GET", p, nil, map[string]string{"Authorization": "Bearer " + goodToken}); res.StatusCode != want {
			t.Errorf("%s: got %d want %d", p, res.StatusCode, want)
		}
	}
	if len(e.up.Requests()) != 0 {
		t.Fatal("an unknown or ambiguous path reached the upstream")
	}
}

func TestOnlyStreamableHTTPMethodsReachTheUpstream(t *testing.T) {
	e := start(t)
	for _, m := range []string{"TRACE", "PUT", "PATCH", "OPTIONS"} {
		res := e.do(t, m, "/mcp", nil, map[string]string{"Authorization": "Bearer " + goodToken})
		if res.StatusCode != http.StatusMethodNotAllowed {
			t.Errorf("%s: got %d want 405", m, res.StatusCode)
		}
	}
	if len(e.up.Requests()) != 0 {
		t.Fatal("a disallowed method reached the upstream")
	}
	for _, m := range []string{"GET", "POST", "DELETE"} {
		if res := e.do(t, m, "/mcp", nil, map[string]string{"Authorization": "Bearer " + goodToken}); res.StatusCode != 200 {
			t.Errorf("%s: got %d", m, res.StatusCode)
		}
	}
}

func TestNewConfiguresHardenedLimitsAndLoopbackBind(t *testing.T) {
	cfg := loadConfig(t, "https://m.example/mcp")
	s, err := New(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	for name, srv := range map[string]*http.Server{"public": s.Public, "internal": s.Internal} {
		for field, unset := range map[string]bool{"ReadHeaderTimeout": srv.ReadHeaderTimeout == 0, "ReadTimeout": srv.ReadTimeout == 0,
			"IdleTimeout": srv.IdleTimeout == 0, "MaxHeaderBytes": srv.MaxHeaderBytes == 0} {
			if unset {
				t.Errorf("%s listener: %s is unset", name, field)
			}
		}
	}
	if s.Internal.Addr != "127.0.0.1:9090" {
		t.Fatalf("default internal bind = %q", s.Internal.Addr)
	}
	if s.Public.Addr != "127.0.0.1:8080" {
		t.Fatalf("default bind = %q", s.Public.Addr)
	}
}

func TestRecovererHidesPanicDetails(t *testing.T) {
	var logs bytes.Buffer
	h := recoverer(slog.New(slog.NewJSONHandler(&logs, nil)), http.HandlerFunc(func(http.ResponseWriter, *http.Request) { panic("boom") }))
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("Authorization", "Bearer secret")
	h.ServeHTTP(w, r)
	if w.Code != 500 || strings.Contains(w.Body.String(), "boom") || strings.Contains(logs.String(), "secret") {
		t.Fatalf("code=%d body=%q logs=%s", w.Code, w.Body, logs.String())
	}
}

func TestRecovererLetsAbortedHandlersAbort(t *testing.T) {
	var logs bytes.Buffer
	h := recoverer(slog.New(slog.NewJSONHandler(&logs, nil)), http.HandlerFunc(func(http.ResponseWriter, *http.Request) { panic(http.ErrAbortHandler) }))
	defer func() {
		if p := recover(); p != http.ErrAbortHandler { //nolint:errorlint // sentinel compared as net/http does
			t.Fatalf("panic = %v, want http.ErrAbortHandler", p)
		}
		if logs.Len() != 0 {
			t.Fatalf("an aborted handler was logged: %s", logs.String())
		}
	}()
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/", nil))
}

func TestRunShutsDownOnCancel(t *testing.T) {
	cfg := loadConfig(t, "https://m.example/mcp", "BYWARD_LISTEN=127.0.0.1:0", "BYWARD_INTERNAL_LISTEN=127.0.0.1:0")
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	srv, err := New(cfg, log)
	if err != nil {
		t.Fatal(err)
	}
	go func() { done <- Run(ctx, srv, log) }()
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return after cancel")
	}
}

func TestAdmitCapsRequestsAndStreamsSeparately(t *testing.T) {
	release := make(chan struct{})
	entered := make(chan struct{}, 4)
	h := admit(1, 1, nil, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		entered <- struct{}{}
		<-release
	}))
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	t.Cleanup(func() { close(release) })
	call := func(method string) {
		go func() {
			r, _ := http.NewRequest(method, srv.URL, nil)
			if res, err := http.DefaultClient.Do(r); err == nil {
				_ = res.Body.Close()
			}
		}()
		<-entered
	}
	call("GET")  // holds the only stream slot
	call("POST") // a POST still gets in: streams do not use request slots
	for _, m := range []string{"GET", "POST"} {
		r, _ := http.NewRequest(m, srv.URL, nil)
		res, err := http.DefaultClient.Do(r)
		if err != nil {
			t.Fatal(err)
		}
		_ = res.Body.Close()
		if res.StatusCode != http.StatusServiceUnavailable || res.Header.Get("Retry-After") == "" {
			t.Fatalf("%s over its cap: got %d", m, res.StatusCode)
		}
	}
}

func TestServerSentEventsStreamThroughTheWholeChain(t *testing.T) {
	e := start(t)
	next := make(chan struct{})
	e.up.Handler = func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, "data: one\n\n")
		w.(http.Flusher).Flush()
		<-next
	}
	t.Cleanup(func() { close(next) })
	res := e.do(t, "GET", "/mcp", nil, map[string]string{"Authorization": "Bearer " + goodToken, "Accept": "text/event-stream"})
	buf := make([]byte, len("data: one\n\n"))
	if _, err := io.ReadFull(res.Body, buf); err != nil || string(buf) != "data: one\n\n" {
		t.Fatalf("first event not flushed through the middleware chain: %q %v", buf, err)
	}
}

func TestNoAuthServesTheUpstreamWithoutMetadataOrChallenge(t *testing.T) {
	up := fakeupstream.New()
	t.Cleanup(up.Close)
	cfg, _, err := config.Load(nil, []string{
		"BYWARD_INSECURE_NO_AUTH=true",
		"BYWARD_PUBLIC_URL=http://localhost:8080/mcp",
		"BYWARD_UPSTREAM_URL=" + up.URL + "/mcp",
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(Handler(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)), resource.NoTokens{}, nil, nil, Observability{}))
	t.Cleanup(srv.Close)
	do := func(method, path, host string, hdr map[string]string) *http.Response {
		r, _ := http.NewRequest(method, srv.URL+path, strings.NewReader(`{"jsonrpc":"2.0"}`))
		r.Host = host
		for k, v := range hdr {
			r.Header.Set(k, v)
		}
		res, err := http.DefaultClient.Do(r)
		if err != nil {
			t.Fatal(err)
		}
		_ = res.Body.Close()
		return res
	}
	if res := do("POST", "/mcp", "localhost:8080", map[string]string{"Authorization": "Bearer anything"}); res.StatusCode != 200 || res.Header.Get("WWW-Authenticate") != "" {
		t.Fatalf("anonymous POST: %d %q", res.StatusCode, res.Header.Get("WWW-Authenticate"))
	}
	if got, _ := up.Last(); got.Header.Get("Authorization") != "" {
		t.Fatal("an inbound Authorization header reached the upstream")
	}
	for _, p := range []string{"/.well-known/oauth-protected-resource", "/.well-known/oauth-protected-resource/mcp"} {
		if res := do("GET", p, "localhost:8080", nil); res.StatusCode != http.StatusNotFound {
			t.Fatalf("%s: got %d, want 404 (no metadata without auth)", p, res.StatusCode)
		}
	}
	if res := do("POST", "/mcp", "evil.example", nil); res.StatusCode != http.StatusMisdirectedRequest {
		t.Fatalf("DNS rebinding Host: got %d", res.StatusCode)
	}
	if res := do("POST", "/mcp", "localhost:8080", map[string]string{"Origin": "https://evil.example"}); res.StatusCode != http.StatusForbidden {
		t.Fatalf("foreign Origin: got %d", res.StatusCode)
	}
	// The conformance rebinding scenario sends the server's own origin and expects success.
	if res := do("POST", "/mcp", "localhost:8080", map[string]string{"Origin": "http://localhost:8080"}); res.StatusCode != 200 {
		t.Fatalf("own Origin: got %d", res.StatusCode)
	}
	do("POST", "/mcp?access_token=leak&x=1", "localhost:8080", nil)
	if got, _ := up.Last(); strings.Contains(got.RawQuery, "access_token") || got.RawQuery != "x=1" {
		t.Fatalf("query token reached the upstream: %q", got.RawQuery)
	}
}

func TestOwnOriginIsAlwaysAllowed(t *testing.T) {
	e := start(t)
	if res := e.do(t, "POST", "/mcp", nil, map[string]string{"Origin": "https://mcp.example.com", "Authorization": "Bearer " + goodToken}); res.StatusCode != 200 {
		t.Fatalf("same-origin request: got %d", res.StatusCode)
	}
	if res := e.do(t, "POST", "/mcp", nil, map[string]string{"Origin": "https://mcp.example.com.evil.example"}); res.StatusCode != http.StatusForbidden {
		t.Fatalf("look-alike origin: got %d", res.StatusCode)
	}
}

func TestNewNamesTheSettingAtFault(t *testing.T) {
	cases := []struct {
		name, setting, doc string
		value              func(t *testing.T) string
	}{
		{"empty keys dir", "BYWARD_KEYS_DIR", "docs/how-to/sealing-keys.md", func(t *testing.T) string { return t.TempDir() }},
		{"malformed clients file", "BYWARD_STATIC_CLIENTS_FILE", "docs/reference/static-clients.md", func(t *testing.T) string {
			p := filepath.Join(t.TempDir(), "clients.json")
			if err := os.WriteFile(p, []byte(`{"clients":`), 0o600); err != nil {
				t.Fatal(err)
			}
			return p
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			environ := append(authEnv(t), "BYWARD_PUBLIC_URL=https://m.example/mcp", "BYWARD_UPSTREAM_URL=http://u/mcp")
			path := c.value(t)
			for i, kv := range environ {
				if strings.HasPrefix(kv, c.setting+"=") {
					environ[i] = c.setting + "=" + path
				}
			}
			cfg, _, err := config.Load(nil, environ, os.ReadFile)
			if err != nil {
				t.Fatal(err)
			}
			_, err = New(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
			if err == nil || !strings.HasPrefix(err.Error(), c.setting+":") || !strings.Contains(err.Error(), path) || !strings.Contains(err.Error(), c.doc) {
				t.Fatalf("err = %v, want it to start with %q and name %s and %s", err, c.setting+":", path, c.doc)
			}
		})
	}
}

// With authentication, New must hand the revocation-list sync to Run (background_test.go shows
// that Run runs it and that it keeps tokens valid); without it every token is refused 30 s after
// startup.
func TestNewInAuthModeHandsTheRevocationSyncToRun(t *testing.T) {
	cfg, _, err := config.Load(nil, append(authEnv(t), "BYWARD_PUBLIC_URL=https://mcp.example.com/mcp", "BYWARD_UPSTREAM_URL=http://u/mcp"), os.ReadFile)
	if err != nil {
		t.Fatal(err)
	}
	s, err := New(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	if s.background == nil {
		t.Fatal("New in auth mode gives Run no background work")
	}
}

func TestNewServesTheBrokerRoutes(t *testing.T) {
	cfg := loadConfig(t, "https://mcp.example.com/mcp")
	s, err := New(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(s.Public.Handler)
	t.Cleanup(ts.Close)
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	get := func(path string) *http.Response {
		r, _ := http.NewRequest("GET", ts.URL+path, nil)
		r.Host = "mcp.example.com"
		res, err := client.Do(r)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = res.Body.Close() })
		return res
	}
	res := get("/.well-known/oauth-authorization-server")
	var m struct{ Issuer string }
	if err := json.NewDecoder(res.Body).Decode(&m); err != nil || res.StatusCode != 200 || m.Issuer != "https://mcp.example.com" {
		t.Fatalf("metadata: %d issuer=%q err=%v", res.StatusCode, m.Issuer, err)
	}
	// Without PKCE the broker answers itself (no IdP call): a redirect back to the registered client.
	res = get("/authorize?client_id=test-app&redirect_uri=http%3A%2F%2F127.0.0.1%2Fcallback&response_type=code")
	loc, _ := url.Parse(res.Header.Get("Location"))
	if res.StatusCode != http.StatusFound || !strings.HasPrefix(loc.String(), "http://127.0.0.1/callback?") ||
		loc.Query().Get("error") != "invalid_request" || loc.Query().Get("iss") != "https://mcp.example.com" {
		t.Fatalf("authorize: %d %s", res.StatusCode, loc)
	}
}

func getBody(t *testing.T, h http.Handler, host, path string) (int, string) {
	t.Helper()
	r := httptest.NewRequest("GET", path, nil)
	r.Host = host
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w.Code, w.Body.String()
}

// ADR-0018 §2 on the internal listener: listed names pass (Prometheus by a Service name), foreign
// names get 421 and are counted as host_rejected.
func TestInternalListenerAcceptsListedHostsAndAuditsRejections(t *testing.T) {
	cfg := loadConfig(t, "https://mcp.example.com/mcp", "BYWARD_ALLOWED_HOSTS=byward-metrics.monitoring.svc")
	s, err := New(cfg, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	if code, _ := getBody(t, s.Internal.Handler, "byward-metrics.monitoring.svc:9090", "/metrics"); code != 200 {
		t.Errorf("internal /metrics by a BYWARD_ALLOWED_HOSTS name = %d, want 200", code)
	}
	if code, _ := getBody(t, s.Internal.Handler, "rebind.attacker.example:9090", "/metrics"); code != http.StatusMisdirectedRequest {
		t.Errorf("internal /metrics for a foreign host name = %d, want 421", code)
	}
	_, metrics := getBody(t, s.Internal.Handler, "127.0.0.1:9090", "/metrics")
	if !strings.Contains(metrics, `byward_audit_events_total{event="host_rejected",outcome="failure"} 1`) {
		t.Errorf("the internal listener's rejection must be audited as host_rejected:\n%s", metrics)
	}
}

// ADR-0018 §7: BYWARD_UPSTREAM_HEADER_TIMEOUT reaches the relay; a stalled upstream is answered.
func TestStalledUpstreamIsAnsweredAfterTheConfiguredHeaderTimeout(t *testing.T) {
	up := fakeupstream.New()
	release := make(chan struct{})
	t.Cleanup(up.Close)
	t.Cleanup(func() { close(release) }) // runs before up.Close
	up.Handler = func(_ http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-release:
		}
	}
	cfg, _, err := config.Load(nil, []string{
		"BYWARD_INSECURE_NO_AUTH=true",
		"BYWARD_PUBLIC_URL=http://localhost:8080/mcp",
		"BYWARD_UPSTREAM_URL=" + up.URL + "/mcp",
		"BYWARD_UPSTREAM_HEADER_TIMEOUT=1s",
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	s, err := New(cfg, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest("POST", "/mcp", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"slow"}}`))
	r.Host = "localhost:8080"
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Accept", "application/json, text/event-stream")
	w := httptest.NewRecorder()
	done := make(chan struct{})
	go func() { defer close(done); s.Public.Handler.ServeHTTP(w, r) }()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("still waiting for the stalled upstream: BYWARD_UPSTREAM_HEADER_TIMEOUT did not reach the relay")
	}
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"isError":true`) || !strings.Contains(w.Body.String(), "did not answer in time") {
		t.Fatalf("got %d %q, want the timeout tool error", w.Code, w.Body)
	}
}

// ADR-0018 §10, ADR-0021 §8 and §10: metrics and probes only on the internal listener.
func TestInternalListenerServesProbesAndMetricsAndThePublicOneDoesNot(t *testing.T) {
	cfg := loadConfig(t, "https://mcp.example.com/mcp")
	s, err := New(cfg, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	if code, _ := getBody(t, s.Internal.Handler, "127.0.0.1:9090", "/livez"); code != 200 {
		t.Errorf("internal /livez = %d, want 200", code)
	}
	if code, _ := getBody(t, s.Internal.Handler, "rebind.attacker.example:9090", "/metrics"); code != http.StatusMisdirectedRequest {
		t.Errorf("internal /metrics for a foreign host name = %d, want 421 (DNS rebinding)", code)
	}
	if code, _ := getBody(t, s.Internal.Handler, "127.0.0.1:9090", "/readyz"); code != 200 {
		t.Errorf("internal /readyz = %d, want 200", code)
	}
	// A public request is timed under its fixed route name.
	getBody(t, s.Public.Handler, "mcp.example.com", "/mcp")
	code, body := getBody(t, s.Internal.Handler, "127.0.0.1:9090", "/metrics")
	if code != 200 {
		t.Errorf("internal /metrics = %d, want 200", code)
	}
	for _, want := range []string{"byward_build_info", `route="/mcp",status_class="4xx"`} {
		if !strings.Contains(body, want) {
			t.Errorf("internal /metrics lacks %s (the public request must be timed under its route)", want)
		}
	}
	for _, p := range []string{"/metrics", "/livez", "/readyz"} {
		if code, _ := getBody(t, s.Public.Handler, "mcp.example.com", p); code != http.StatusNotFound {
			t.Errorf("public %s = %d, want 404", p, code)
		}
	}
}

func TestEmptyInternalListenTurnsTheInternalListenerOff(t *testing.T) {
	cfg := loadConfig(t, "https://m.example/mcp", "BYWARD_INTERNAL_LISTEN=")
	s, err := New(cfg, slog.New(slog.DiscardHandler))
	if err != nil || s.Internal != nil {
		t.Fatalf("internal server = %v, err %v; want none", s.Internal, err)
	}
}

func TestStartupAuditsKeysAndStaticClients(t *testing.T) {
	cfg := loadConfig(t, "https://m.example/mcp")
	var logs bytes.Buffer
	if _, err := New(cfg, logging.New(&logs, "json")); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"event":"key_loaded","outcome":"success","reason":"signing","key_id":"2026-11-06"`, `"event":"client_registered","outcome":"success","reason":"static","client_id":"test-app"`} {
		if !strings.Contains(logs.String(), want) {
			t.Errorf("startup audit lacks %s:\n%s", want, logs.String())
		}
	}
}

var listenLine = regexp.MustCompile(`"msg":"listening","listen":"([^"]+)"`)

// listenWatcher is a log sink that closes listening when the public listener's address is logged.
type listenWatcher struct {
	syncBuffer
	listening chan struct{}
	once      sync.Once
}

func (w *listenWatcher) Write(p []byte) (int, error) {
	n, err := w.syncBuffer.Write(p)
	if listenLine.Match(p) {
		w.once.Do(func() { close(w.listening) })
	}
	return n, err
}

// ADR-0021 §10: on shutdown /readyz fails before the public listener closes, and the internal
// listener (probes, metrics) closes only after the public one, so the drain is visible.
// Shutdown runs RegisterOnShutdown callbacks in goroutines, so each asserts the state it sees.
func TestRunDrainsReadinessBeforeShutdownAndClosesTheInternalListenerLast(t *testing.T) {
	cfg, _, err := config.Load(nil, append(authEnv(t), "BYWARD_PUBLIC_URL=https://m.example/mcp", "BYWARD_UPSTREAM_URL=http://u/mcp",
		"BYWARD_LISTEN=127.0.0.1:0", "BYWARD_INTERNAL_LISTEN=127.0.0.1:0"), os.ReadFile)
	if err != nil {
		t.Fatal(err)
	}
	logs := &listenWatcher{listening: make(chan struct{})}
	log := logging.New(logs, "json")
	s, err := New(cfg, log)
	if err != nil {
		t.Fatal(err)
	}
	probes := http.NewServeMux()
	s.Health.Register(probes)
	var wg sync.WaitGroup
	wg.Add(2)
	var readyzAtPublicShutdown int
	var publicDialAtInternalShutdown error
	s.Public.RegisterOnShutdown(func() {
		defer wg.Done()
		readyzAtPublicShutdown, _ = getBody(t, probes, "x", "/readyz")
	})
	s.Internal.RegisterOnShutdown(func() {
		defer wg.Done()
		m := listenLine.FindStringSubmatch(logs.String())
		if m == nil {
			publicDialAtInternalShutdown = errors.New("no listening line")
			return
		}
		c, err := net.DialTimeout("tcp", m[1], time.Second)
		if err == nil {
			_ = c.Close()
			publicDialAtInternalShutdown = errors.New("the public listener still accepts connections")
		}
	})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- Run(ctx, s, log) }()
	select {
	case <-logs.listening:
	case err := <-done:
		t.Fatalf("Run returned before listening: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not log its listening address within 5s")
	}
	// One completed connection proves Serve is accepting, so Shutdown has a listener to close.
	addr := listenLine.FindStringSubmatch(logs.String())[1]
	if c, err := net.DialTimeout("tcp", addr, 5*time.Second); err != nil {
		t.Fatalf("public listener %s not accepting before cancel: %v", addr, err)
	} else {
		_ = c.Close()
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return after cancel")
	}
	callbacks := make(chan struct{})
	go func() { wg.Wait(); close(callbacks) }()
	select {
	case <-callbacks:
	case <-time.After(5 * time.Second):
		t.Fatal("a server's Shutdown never ran its RegisterOnShutdown callback")
	}
	if readyzAtPublicShutdown != http.StatusServiceUnavailable {
		t.Errorf("/readyz was %d when the public listener began shutting down, want 503 (drain first)", readyzAtPublicShutdown)
	}
	if publicDialAtInternalShutdown != nil {
		t.Errorf("internal listener shut down before the public one was closed: %v", publicDialAtInternalShutdown)
	}
}

// ADR-0021 §5 through the real handler: rejections from one source are logged up to the burst and
// counted in metrics beyond it.
func TestRejectionsFromOneSourceAreRateLimitedButStillCounted(t *testing.T) {
	cfg := loadConfig(t, "https://mcp.example.com/mcp")
	var logs bytes.Buffer
	s, err := New(cfg, logging.New(&logs, "json"))
	if err != nil {
		t.Fatal(err)
	}
	logs.Reset() // startup records
	for range 15 {
		getBody(t, s.Public.Handler, "evil.example", "/mcp")
	}
	if n := strings.Count(logs.String(), `"event":"host_rejected"`); n != 10 {
		t.Errorf("logged %d host_rejected records from one source, want the burst of 10", n)
	}
	_, metrics := getBody(t, s.Internal.Handler, "127.0.0.1:9090", "/metrics")
	if !strings.Contains(metrics, `byward_audit_events_total{event="host_rejected",outcome="failure"} 15`) {
		t.Errorf("metrics must count all 15 rejections:\n%s", metrics)
	}
}

// ADR-0021 §8: label values come from the route table, never from the request.
func TestRouteLabelsNeverCarryRequestDetails(t *testing.T) {
	cfg := loadConfig(t, "https://mcp.example.com/mcp")
	s, err := New(cfg, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{"/mcp?user=alice", "/no-such-route-alice", "/callback/entra?state=alice"} {
		getBody(t, s.Public.Handler, "mcp.example.com", p)
	}
	_, metrics := getBody(t, s.Internal.Handler, "127.0.0.1:9090", "/metrics")
	if strings.Contains(metrics, "alice") {
		t.Fatalf("a request detail reached a label:\n%s", metrics)
	}
	for _, want := range []string{`route="/mcp"`, `route="other"`, `route="/callback/entra"`} {
		if !strings.Contains(metrics, want) {
			t.Errorf("metrics lack %s", want)
		}
	}
}

type pingStore struct{ err error }

func (p pingStore) Ping(context.Context) error { return p.err }

// ADR-0021 §10: /readyz is the keys and the store, never the IdP; a store that cannot be reached
// makes it fail without putting the error in the body.
func TestReadinessIsKeysAndStoreOnly(t *testing.T) {
	ring, err := token.LoadKeyRing(loadConfig(t, "https://m.example/mcp").KeysDir)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		name     string
		st       pinger
		wantCode int
		wantBody string
	}{
		{"store reachable", pingStore{nil}, 200, `{"checks":{"keys":"ok","store":"ok"},"status":"ok"}`},
		{"store down", pingStore{errors.New("dial /var/lib/db: refused")}, 503, `{"checks":{"keys":"ok","store":"fail"},"status":"unavailable"}`},
	} {
		t.Run(c.name, func(t *testing.T) {
			mux := http.NewServeMux()
			health.New(slog.New(slog.DiscardHandler), readiness(ring, c.st)...).Register(mux)
			code, body := getBody(t, mux, "x", "/readyz")
			if code != c.wantCode || strings.TrimSpace(body) != c.wantBody {
				t.Fatalf("readyz = %d %s, want %d %s (exactly keys and store, no IdP, no error text)", code, body, c.wantCode, c.wantBody)
			}
		})
	}
}

// The wired broker shows the consent page with the operator's wording and accepts an answer that
// carries the public origin: a wrong Origin wiring would refuse every real Allow.
func TestTheServerShowsTheOperatorsConsentPageAndDenyReturnsToTheApp(t *testing.T) {
	env := append(authEnv(t), "BYWARD_PUBLIC_URL=https://mcp.example.com/mcp", "BYWARD_UPSTREAM_URL=http://u/mcp",
		"BYWARD_OPERATOR_NAME=Contoso IT", "BYWARD_SCOPE_DESCRIPTION=Read your dashboards.", "BYWARD_RESOURCE_NAME=Team dashboards")
	cfg, _, err := config.Load(nil, env, os.ReadFile)
	if err != nil {
		t.Fatal(err)
	}
	s, err := New(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(s.Public.Handler)
	t.Cleanup(ts.Close)
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	q := url.Values{"client_id": {"test-app"}, "redirect_uri": {"http://127.0.0.1/callback"}, "response_type": {"code"},
		"code_challenge": {strings.Repeat("A", 43)}, "code_challenge_method": {"S256"}, "state": {"s"}}
	r, _ := http.NewRequest("GET", ts.URL+"/authorize?"+q.Encode(), nil)
	r.Host = "mcp.example.com"
	res, err := client.Do(r)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(res.Body)
	_ = res.Body.Close()
	m := regexp.MustCompile(`name="flow" value="([^"]+)"`).FindSubmatch(body)
	if res.StatusCode != http.StatusOK || m == nil || len(res.Cookies()) != 1 {
		t.Fatalf("authorize: %d, cookies %v: %s", res.StatusCode, res.Cookies(), body)
	}
	text := strings.Join(strings.Fields(html.UnescapeString(regexp.MustCompile(`<[^>]*>`).ReplaceAllString(string(body), " "))), " ")
	for _, want := range []string{"Read your dashboards.", "Run by Contoso IT.", "wants to use Team dashboards as you", "openid"} {
		if !strings.Contains(text, want) {
			t.Errorf("consent page lacks %q in %q", want, text)
		}
	}
	css, _ := http.NewRequest("GET", ts.URL+"/assets/page.css", nil)
	css.Host = "mcp.example.com"
	cres, err := client.Do(css)
	if err != nil {
		t.Fatal(err)
	}
	_ = cres.Body.Close()
	if cres.StatusCode != http.StatusOK || cres.Header.Get("Content-Type") != "text/css; charset=utf-8" {
		t.Errorf("stylesheet through the server: %d %q", cres.StatusCode, cres.Header.Get("Content-Type"))
	}
	form := url.Values{"flow": {html.UnescapeString(string(m[1]))}, "action": {"deny"}}
	r, _ = http.NewRequest("POST", ts.URL+"/consent", strings.NewReader(form.Encode()))
	r.Host = "mcp.example.com"
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("Origin", "https://mcp.example.com")
	r.AddCookie(res.Cookies()[0])
	res, err = client.Do(r)
	if err != nil {
		t.Fatal(err)
	}
	_ = res.Body.Close()
	if loc, _ := url.Parse(res.Header.Get("Location")); res.StatusCode != http.StatusFound || loc.Query().Get("error") != "access_denied" ||
		loc.Scheme+"://"+loc.Host+loc.Path != "http://127.0.0.1/callback" || loc.Query().Get("state") != "s" {
		t.Fatalf("deny: %d %s, want the app's callback with access_denied and its state", res.StatusCode, loc)
	}
}

func TestNewWarnsAboutGenericWordingOnlyWithoutAScopeDescription(t *testing.T) {
	for _, c := range []struct {
		name  string
		extra []string
		warn  bool
	}{
		{"no scope description warns", nil, true},
		{"a scope description is quiet", []string{"BYWARD_SCOPE_DESCRIPTION=Read your dashboards."}, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			env := append(authEnv(t), "BYWARD_PUBLIC_URL=https://mcp.example.com/mcp", "BYWARD_UPSTREAM_URL=http://u/mcp")
			cfg, _, err := config.Load(nil, append(env, c.extra...), os.ReadFile)
			if err != nil {
				t.Fatal(err)
			}
			logs := &syncBuffer{}
			if _, err := New(cfg, slog.New(slog.NewJSONHandler(logs, nil))); err != nil {
				t.Fatal(err)
			}
			if got := strings.Contains(logs.String(), `"setting":"BYWARD_SCOPE_DESCRIPTION"`); got != c.warn {
				t.Fatalf("warning logged: %v, want %v: %s", got, c.warn, logs)
			}
		})
	}
}

// ADR-0018 §6 and §8 end to end: behind a trusted proxy each forwarded client has its own
// /authorize budget; from an untrusted peer, X-Forwarded-For cannot buy a fresh budget.
func TestOAuthRateLimitsKeyOnTheResolvedClientAddress(t *testing.T) {
	cfg := loadConfig(t, "https://mcp.example.com/mcp", "BYWARD_TRUSTED_PROXIES=10.0.0.0/8", "BYWARD_OAUTH_RATE_LIMITS=authorize=2")
	logs := &syncBuffer{}
	s, err := New(cfg, logging.New(logs, "json"))
	if err != nil {
		t.Fatal(err)
	}
	// An unknown client: the broker rejects it (400) after the limit and before any IdP call, so the
	// test makes no network request.
	q := url.Values{"client_id": {"nobody"}}
	authorize := func(peer, xff string) string {
		r := httptest.NewRequest("GET", "/authorize?"+q.Encode(), nil)
		r.Host = "mcp.example.com"
		r.RemoteAddr = peer + ":4000"
		if xff != "" {
			r.Header.Set("X-Forwarded-For", xff)
		}
		w := httptest.NewRecorder()
		s.Public.Handler.ServeHTTP(w, r)
		switch w.Code {
		case http.StatusTooManyRequests:
			return "limited"
		case http.StatusBadRequest:
			return "passed"
		}
		return fmt.Sprintf("unexpected %d", w.Code)
	}
	got := []string{
		authorize("10.0.0.1", "198.51.100.1"), authorize("10.0.0.1", "198.51.100.1"), authorize("10.0.0.1", "198.51.100.1"),
		authorize("10.0.0.1", "198.51.100.2"),
		authorize("203.0.113.5", "1.1.1.1"), authorize("203.0.113.5", "2.2.2.2"), authorize("203.0.113.5", "3.3.3.3"),
		// IPv6 clients behind the proxy share their /64 (ADR-0018 §8).
		authorize("10.0.0.1", "2001:db8:1:2::1"), authorize("10.0.0.1", "2001:db8:1:2::2"), authorize("10.0.0.1", "2001:db8:1:2:ffff::3"),
	}
	want := []string{"passed", "passed", "limited", "passed", "passed", "passed", "limited", "passed", "passed", "limited"}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("authorize results = %v, want %v (budget 2 per resolved client address)", got, want)
	}
	var limitedLine string
	for _, line := range strings.Split(logs.String(), "\n") {
		if strings.Contains(line, `"event":"rate_limited"`) && strings.Contains(line, `"remote_ip":"198.51.100.1"`) {
			limitedLine = line
		}
	}
	if limitedLine == "" || !strings.Contains(limitedLine, `"reason":"authorize"`) || !strings.Contains(limitedLine, `"outcome":"failure"`) {
		t.Errorf("no rate_limited audit record for authorize from the forwarded client 198.51.100.1:\n%s", logs.String())
	}
	if strings.Contains(logs.String(), `"remote_ip":"3.3.3.3"`) {
		t.Error("a forwarded address from an untrusted peer reached the log")
	}
	_, metrics := getBody(t, s.Internal.Handler, "127.0.0.1:9090", "/metrics")
	if !strings.Contains(metrics, `byward_rate_limited_total{endpoint="authorize"} 3`) {
		t.Errorf("metrics must count all three refusals:\n%s", metrics)
	}
}
