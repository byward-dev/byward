package server

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/corker/mcp-authproxy/internal/config"
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
	cfg, _, err := config.Load(nil, append([]string{
		"MCP_AUTHPROXY_PUBLIC_URL=https://mcp.example.com/mcp",
		"MCP_AUTHPROXY_UPSTREAM_URL=" + up.URL + "/mcp",
		"MCP_AUTHPROXY_ALLOWED_ORIGINS=https://app.example",
	}, extraEnv...), nil)
	if err != nil {
		t.Fatal(err)
	}
	logs := &syncBuffer{}
	srv := httptest.NewServer(Handler(cfg, slog.New(slog.NewJSONHandler(logs, nil)), acceptGood{}))
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

func TestBodyLimit(t *testing.T) {
	e := start(t)
	res := e.do(t, "POST", "/mcp", bytes.NewReader(make([]byte, MaxMCPBody+1)), map[string]string{"Authorization": "Bearer " + goodToken})
	if res.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("got %d", res.StatusCode)
	}
}

func TestChunkedBodyOverLimitIs413(t *testing.T) {
	e := start(t)
	big := io.MultiReader(strings.NewReader(strings.Repeat("x", MaxMCPBody)), strings.NewReader("y"))
	r, _ := http.NewRequest("POST", e.srv.URL+"/mcp", io.NopCloser(big)) // no ContentLength: chunked
	r.Host = "mcp.example.com"
	r.Header.Set("Authorization", "Bearer "+goodToken)
	res, err := http.DefaultClient.Do(r)
	if err != nil {
		t.Fatal(err)
	}
	_ = res.Body.Close()
	if res.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("got %d", res.StatusCode)
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
	cfg, _, err := config.Load(nil, []string{"MCP_AUTHPROXY_PUBLIC_URL=https://m.example/mcp", "MCP_AUTHPROXY_UPSTREAM_URL=http://u/mcp"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	s := New(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if s.ReadHeaderTimeout == 0 || s.ReadTimeout == 0 || s.IdleTimeout == 0 || s.MaxHeaderBytes == 0 {
		t.Fatalf("a limit is unset: %+v", s)
	}
	if s.Addr != "127.0.0.1:8080" {
		t.Fatalf("default bind = %q", s.Addr)
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
	cfg, _, err := config.Load(nil, []string{"MCP_AUTHPROXY_PUBLIC_URL=https://m.example/mcp", "MCP_AUTHPROXY_UPSTREAM_URL=http://u/mcp", "MCP_AUTHPROXY_LISTEN=127.0.0.1:0"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- Run(ctx, New(cfg, log), log) }()
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
	h := admit(1, 1, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
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
	buf := make([]byte, 64)
	buf = buf[:len("data: one\n\n")]
	if _, err := io.ReadFull(res.Body, buf); err != nil || string(buf) != "data: one\n\n" {
		t.Fatalf("first event not flushed through the middleware chain: %q %v", buf, err)
	}
}
