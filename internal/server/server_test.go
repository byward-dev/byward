package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/corker/mcp-authproxy/internal/audit"
	"github.com/corker/mcp-authproxy/internal/config"
	"github.com/corker/mcp-authproxy/internal/logging"
	"github.com/corker/mcp-authproxy/internal/resource"
	"github.com/corker/mcp-authproxy/internal/testutil/fakeupstream"
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
		"MCP_AUTHPROXY_PUBLIC_URL=https://mcp.example.com/mcp",
		"MCP_AUTHPROXY_UPSTREAM_URL=" + up.URL + "/mcp",
		"MCP_AUTHPROXY_ALLOWED_ORIGINS=https://app.example",
	}, extraEnv...)...), os.ReadFile)
	if err != nil {
		t.Fatal(err)
	}
	logs := &syncBuffer{}
	log := slog.New(slog.NewJSONHandler(logs, nil))
	srv := httptest.NewServer(Handler(cfg, log, acceptGood{}, nil, Observability{Audit: audit.New(log, nil, time.Now)}))
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
	e := start(t, "MCP_AUTHPROXY_ALLOWED_HOSTS=proxy.internal:8080")
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
	cfg, _, err := config.Load(nil, append(authEnv(t), "MCP_AUTHPROXY_PUBLIC_URL=https://m.example/mcp", "MCP_AUTHPROXY_UPSTREAM_URL=http://u/mcp"), os.ReadFile)
	if err != nil {
		t.Fatal(err)
	}
	s, err := New(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	for _, srv := range []*http.Server{s.Public, s.Internal} {
		if srv.ReadHeaderTimeout == 0 || srv.ReadTimeout == 0 || srv.IdleTimeout == 0 || srv.MaxHeaderBytes == 0 {
			t.Fatalf("a limit is unset: %+v", srv)
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
	cfg, _, err := config.Load(nil, append(authEnv(t), "MCP_AUTHPROXY_PUBLIC_URL=https://m.example/mcp", "MCP_AUTHPROXY_UPSTREAM_URL=http://u/mcp", "MCP_AUTHPROXY_LISTEN=127.0.0.1:0", "MCP_AUTHPROXY_INTERNAL_LISTEN=127.0.0.1:0"), os.ReadFile)
	if err != nil {
		t.Fatal(err)
	}
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
		"MCP_AUTHPROXY_INSECURE_NO_AUTH=true",
		"MCP_AUTHPROXY_PUBLIC_URL=http://localhost:8080/mcp",
		"MCP_AUTHPROXY_UPSTREAM_URL=" + up.URL + "/mcp",
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(Handler(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)), resource.NoTokens{}, nil, Observability{}))
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
		name, setting string
		value         func(t *testing.T) string
	}{
		{"empty keys dir", "MCP_AUTHPROXY_KEYS_DIR", func(t *testing.T) string { return t.TempDir() }},
		{"malformed clients file", "MCP_AUTHPROXY_STATIC_CLIENTS_FILE", func(t *testing.T) string {
			p := filepath.Join(t.TempDir(), "clients.json")
			if err := os.WriteFile(p, []byte(`{"clients":`), 0o600); err != nil {
				t.Fatal(err)
			}
			return p
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			environ := append(authEnv(t), "MCP_AUTHPROXY_PUBLIC_URL=https://m.example/mcp", "MCP_AUTHPROXY_UPSTREAM_URL=http://u/mcp")
			for i, kv := range environ {
				if strings.HasPrefix(kv, c.setting+"=") {
					environ[i] = c.setting + "=" + c.value(t)
				}
			}
			cfg, _, err := config.Load(nil, environ, os.ReadFile)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := New(cfg, slog.New(slog.NewTextHandler(io.Discard, nil))); err == nil || !strings.HasPrefix(err.Error(), c.setting+":") {
				t.Fatalf("err = %v, want it to start with %q", err, c.setting+":")
			}
		})
	}
}

func TestNewServesTheBrokerRoutes(t *testing.T) {
	cfg, _, err := config.Load(nil, append(authEnv(t), "MCP_AUTHPROXY_PUBLIC_URL=https://mcp.example.com/mcp", "MCP_AUTHPROXY_UPSTREAM_URL=http://u/mcp"), os.ReadFile)
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

// ADR-0018 §10, ADR-0021 §8 and §10: metrics and probes only on the internal listener.
func TestInternalListenerServesProbesAndMetricsAndThePublicOneDoesNot(t *testing.T) {
	cfg, _, err := config.Load(nil, append(authEnv(t), "MCP_AUTHPROXY_PUBLIC_URL=https://mcp.example.com/mcp", "MCP_AUTHPROXY_UPSTREAM_URL=http://u/mcp"), os.ReadFile)
	if err != nil {
		t.Fatal(err)
	}
	s, err := New(cfg, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	if code, _ := getBody(t, s.Internal.Handler, "x", "/livez"); code != 200 {
		t.Fatalf("livez = %d", code)
	}
	if code, body := getBody(t, s.Internal.Handler, "x", "/readyz"); code != 200 || !strings.Contains(body, `"keys":"ok"`) || !strings.Contains(body, `"store":"ok"`) {
		t.Fatalf("readyz = %d %s", code, body)
	}
	// A public request is timed under its fixed route name.
	getBody(t, s.Public.Handler, "mcp.example.com", "/mcp")
	code, body := getBody(t, s.Internal.Handler, "x", "/metrics")
	if code != 200 || !strings.Contains(body, "mcp_authproxy_build_info") || !strings.Contains(body, `route="/mcp",status_class="4xx"`) {
		t.Fatalf("metrics = %d, missing build info or the public request:\n%s", code, body)
	}
	for _, p := range []string{"/metrics", "/livez", "/readyz"} {
		if code, _ := getBody(t, s.Public.Handler, "mcp.example.com", p); code != http.StatusNotFound {
			t.Errorf("public %s = %d, want 404", p, code)
		}
	}
}

func TestEmptyInternalListenTurnsTheInternalListenerOff(t *testing.T) {
	cfg, _, err := config.Load(nil, append(authEnv(t), "MCP_AUTHPROXY_PUBLIC_URL=https://m.example/mcp", "MCP_AUTHPROXY_UPSTREAM_URL=http://u/mcp", "MCP_AUTHPROXY_INTERNAL_LISTEN="), os.ReadFile)
	if err != nil {
		t.Fatal(err)
	}
	s, err := New(cfg, slog.New(slog.DiscardHandler))
	if err != nil || s.Internal != nil {
		t.Fatalf("internal server = %v, err %v; want none", s.Internal, err)
	}
}

func TestStartupAuditsKeysAndStaticClients(t *testing.T) {
	cfg, _, err := config.Load(nil, append(authEnv(t), "MCP_AUTHPROXY_PUBLIC_URL=https://m.example/mcp", "MCP_AUTHPROXY_UPSTREAM_URL=http://u/mcp"), os.ReadFile)
	if err != nil {
		t.Fatal(err)
	}
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

// ADR-0021 §10: on shutdown /readyz fails before the public listener closes, and the internal
// listener (probes, metrics) closes only after the public one, so the drain is visible.
// Shutdown runs RegisterOnShutdown callbacks in goroutines, so each asserts the state it sees.
func TestRunDrainsReadinessBeforeShutdownAndClosesTheInternalListenerLast(t *testing.T) {
	cfg, _, err := config.Load(nil, append(authEnv(t), "MCP_AUTHPROXY_PUBLIC_URL=https://m.example/mcp", "MCP_AUTHPROXY_UPSTREAM_URL=http://u/mcp",
		"MCP_AUTHPROXY_LISTEN=127.0.0.1:0", "MCP_AUTHPROXY_INTERNAL_LISTEN=127.0.0.1:0"), os.ReadFile)
	if err != nil {
		t.Fatal(err)
	}
	logs := &syncBuffer{}
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
	for !listenLine.MatchString(logs.String()) {
		runtime.Gosched()
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
	wg.Wait()
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
	cfg, _, err := config.Load(nil, append(authEnv(t), "MCP_AUTHPROXY_PUBLIC_URL=https://mcp.example.com/mcp", "MCP_AUTHPROXY_UPSTREAM_URL=http://u/mcp"), os.ReadFile)
	if err != nil {
		t.Fatal(err)
	}
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
	_, metrics := getBody(t, s.Internal.Handler, "x", "/metrics")
	if !strings.Contains(metrics, `mcp_authproxy_audit_events_total{event="host_rejected",outcome="failure"} 15`) {
		t.Errorf("metrics must count all 15 rejections:\n%s", metrics)
	}
}

// ADR-0021 §8: label values come from the route table, never from the request.
func TestRouteLabelsNeverCarryRequestDetails(t *testing.T) {
	cfg, _, err := config.Load(nil, append(authEnv(t), "MCP_AUTHPROXY_PUBLIC_URL=https://mcp.example.com/mcp", "MCP_AUTHPROXY_UPSTREAM_URL=http://u/mcp"), os.ReadFile)
	if err != nil {
		t.Fatal(err)
	}
	s, err := New(cfg, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{"/mcp?user=alice", "/no-such-route-alice", "/callback/entra?state=alice"} {
		getBody(t, s.Public.Handler, "mcp.example.com", p)
	}
	_, metrics := getBody(t, s.Internal.Handler, "x", "/metrics")
	if strings.Contains(metrics, "alice") {
		t.Fatalf("a request detail reached a label:\n%s", metrics)
	}
	for _, want := range []string{`route="/mcp"`, `route="other"`, `route="/callback/entra"`} {
		if !strings.Contains(metrics, want) {
			t.Errorf("metrics lack %s", want)
		}
	}
}
