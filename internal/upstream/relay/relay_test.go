package relay

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"testing"

	"github.com/byward-dev/byward/internal/testutil/fakeupstream"
)

func quiet() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func relayTo(t *testing.T, up *fakeupstream.Server, path string) http.Handler {
	t.Helper()
	u, err := url.Parse(up.URL + path)
	if err != nil {
		t.Fatal(err)
	}
	return New(quiet(), u)
}

func TestRelayForwardsBodyVerbatimAndStripsProxyHeaders(t *testing.T) {
	up := fakeupstream.New()
	t.Cleanup(up.Close)
	body := []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"_meta":{"traceparent":"00-abc-def-01"}}}`)
	r := httptest.NewRequest("POST", "https://mcp.example.com/mcp?x=1&access_token=leak", bytes.NewReader(body))
	r.Header.Set("Authorization", "Bearer secret")
	r.Header.Set("Forwarded", "for=1.2.3.4")
	r.Header.Set("X-Forwarded-For", "1.2.3.4")
	r.Header.Set("X-Forwarded-User", "admin")
	r.Header.Set("x-forwarded-prefix", "/evil")
	r.Header["X_Forwarded_For"] = []string{"6.6.6.6"} // underscore spelling
	r.Header.Set("Origin", "https://app.example")
	r.Header.Set("Sec-Fetch-Site", "cross-site")
	r.Header.Set("Sec-Fetch-Mode", "cors")
	r.Header.Set("Mcp-Session-Id", "s1")
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	relayTo(t, up, "/upstream-mcp").ServeHTTP(w, r)

	got, ok := up.Last()
	if !ok {
		t.Fatal("nothing reached the upstream")
	}
	if !bytes.Equal(got.Body, body) || !bytes.Equal(w.Body.Bytes(), body) {
		t.Fatalf("body changed: up=%s resp=%s", got.Body, w.Body)
	}
	if got.Path != "/upstream-mcp" || got.RawQuery != "x=1" || !strings.HasPrefix(got.Host, "127.0.0.1:") {
		t.Fatalf("path=%q query=%q host=%q", got.Path, got.RawQuery, got.Host)
	}
	for k := range got.Header {
		n := strings.ReplaceAll(k, "_", "-")
		if n == "Authorization" || k == "Forwarded" || k == "Origin" || strings.HasPrefix(n, "X-Forwarded-") || strings.HasPrefix(k, "Sec-Fetch-") {
			t.Fatalf("header %s reached the upstream", k)
		}
	}
	if got.Header.Get("Mcp-Session-Id") != "s1" {
		t.Fatal("MCP headers must pass through")
	}
}

func TestRelayHidesUpstreamErrors(t *testing.T) {
	gone := httptest.NewServer(http.NotFoundHandler())
	gone.Close() // a URL nothing listens on any more
	u, _ := url.Parse(gone.URL + "/mcp")
	w := httptest.NewRecorder()
	New(quiet(), u).ServeHTTP(w, httptest.NewRequest("POST", "/mcp", nil))
	if w.Code != http.StatusBadGateway || strings.Contains(w.Body.String(), "127.0.0.1") {
		t.Fatalf("code=%d body=%q", w.Code, w.Body)
	}
}

func TestRelayStreamsServerSentEvents(t *testing.T) {
	up := fakeupstream.New()
	t.Cleanup(up.Close)
	next := make(chan struct{})
	t.Cleanup(func() { close(next) }) // runs before up.Close, so a failing test cannot hang
	up.Handler = func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, "data: one\n\n")
		w.(http.Flusher).Flush()
		<-next
	}
	srv := httptest.NewServer(relayTo(t, up, "/mcp"))
	t.Cleanup(srv.Close)
	res, err := http.Post(srv.URL, "application/json", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = res.Body.Close() }()
	buf := make([]byte, len("data: one\n\n"))
	if _, err := io.ReadFull(res.Body, buf); err != nil || string(buf) != "data: one\n\n" {
		t.Fatalf("first event not flushed: %q %v", buf, err)
	}
}

func TestRelayDropsUpstreamCORS(t *testing.T) {
	up := fakeupstream.New()
	t.Cleanup(up.Close)
	up.Handler = func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Credentials", "true")
		w.Header().Set("Mcp-Session-Id", "s1")
	}
	w := httptest.NewRecorder()
	relayTo(t, up, "/mcp").ServeHTTP(w, httptest.NewRequest("POST", "/mcp", nil))
	if w.Header().Get("Access-Control-Allow-Origin") != "" || w.Header().Get("Access-Control-Allow-Credentials") != "" || w.Header().Get("Mcp-Session-Id") != "s1" {
		t.Fatalf("headers = %v", w.Header())
	}
}
func TestAccessTokenIsRemovedWithoutTouchingTheRestOfTheQuery(t *testing.T) {
	for raw, want := range map[string]string{
		"b=1&a=%7E&access_token=x":                  "b=1&a=%7E",
		"access_token=x":                            "",
		"x=1&access%5Ftoken=y&access_token=z&z=%20": "x=1&z=%20",
		"q=access_token":                            "q=access_token",
		"plain=1&b=2":                               "plain=1&b=2",
	} {
		if got := withoutAccessToken(raw); got != want {
			t.Errorf("%q: got %q want %q", raw, got, want)
		}
	}
}

// ADR-0021 §9: the relay writes our trace context as a header and never touches params._meta.
func TestTraceContextIsInjectedAsAHeaderAndTheBodyIsUntouched(t *testing.T) {
	const ours = "00-11111111111111111111111111111111-2222222222222222-01"
	cases := []struct {
		name   string
		opts   []Option
		wantTP string
	}{
		{"with tracing", []Option{WithInject(func(_ context.Context, h http.Header) { h.Set("Traceparent", ours) })}, ours},
		{"without tracing the inbound header passes unchanged", nil, "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"},
	}
	body := []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"_meta":{"traceparent":"00-aaaa-bbbb-01"}}}`)
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			up := fakeupstream.New()
			t.Cleanup(up.Close)
			u, _ := url.Parse(up.URL + "/mcp")
			r := httptest.NewRequest("POST", "/mcp", bytes.NewReader(body))
			r.Header.Set("Traceparent", "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01")
			New(quiet(), u, c.opts...).ServeHTTP(httptest.NewRecorder(), r)
			got, ok := up.Last()
			if !ok {
				t.Fatal("nothing reached the upstream")
			}
			if tp := got.Header.Get("Traceparent"); tp != c.wantTP {
				t.Errorf("upstream traceparent = %q, want %q", tp, c.wantTP)
			}
			if !bytes.Equal(got.Body, body) {
				t.Errorf("the body (params._meta) changed: %s", got.Body)
			}
		})
	}
}

// A stripped header is gone in every spelling before the injectors run, so what an injector sets is
// the only value the upstream sees; injectors run in order (ADR-0016 §4).
func TestAForgedIdentityHeaderInAnySpellingIsReplacedBeforeInjectorsRun(t *testing.T) {
	up := fakeupstream.New()
	t.Cleanup(up.Close)
	u, _ := url.Parse(up.URL + "/mcp")
	var order []string
	h := New(quiet(), u, WithStripped("X-Byward-Identity"),
		WithInject(func(_ context.Context, h http.Header) {
			order = append(order, "first")
			h.Set("X-Byward-Identity", "Bearer ours")
		}),
		WithInject(func(_ context.Context, h http.Header) { order = append(order, "second:"+h.Get("X-Byward-Identity")) }))
	r := httptest.NewRequest("POST", "https://mcp.example.com/mcp", strings.NewReader("{}"))
	r.Header["X-Byward-Identity"] = []string{"Bearer forged"}
	r.Header["X_BYWARD_IDENTITY"] = []string{"Bearer forged"}
	r.Header["x-byward-identity"] = []string{"Bearer forged"}
	h.ServeHTTP(httptest.NewRecorder(), r)
	got, ok := up.Last()
	if !ok {
		t.Fatal("nothing reached the upstream")
	}
	if v := got.Header.Values("X-Byward-Identity"); len(v) != 1 || v[0] != "Bearer ours" {
		t.Fatalf("the upstream got X-Byward-Identity %q, want only ours", v)
	}
	for k, v := range got.Header {
		if strings.EqualFold(strings.ReplaceAll(k, "_", "-"), "X-Byward-Identity") && (k != "X-Byward-Identity" || len(v) != 1 || v[0] != "Bearer ours") {
			t.Fatalf("header %s = %q reached the upstream", k, v)
		}
	}
	if strings.Join(order, ",") != "first,second:Bearer ours" {
		t.Fatalf("injectors ran as %v", order)
	}
}

// An MCP client's request trailers never reach the upstream, whatever they are named, and never
// beside the headers the proxy strips or sets: they arrive after the body, out of the strip's sight.
// Each name is sent straight to the relay, which forwards before the body is read (so only the
// trailer's name has arrived), and behind a handler that reads the body first (so its value has too).
func TestAClientsRequestTrailersNeverReachTheUpstream(t *testing.T) {
	up := fakeupstream.New()
	t.Cleanup(up.Close)
	u, _ := url.Parse(up.URL + "/mcp")
	ours := func(_ context.Context, h http.Header) { h.Set("X-Byward-Identity", "ours") }
	relay := New(quiet(), u, WithStripped("X-Byward-Identity"), WithInject(ours))
	readFirst := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		r.Body = io.NopCloser(bytes.NewReader(b))
		relay.ServeHTTP(w, r)
	})
	body := `{"jsonrpc":"2.0","id":1,"method":"ping"}`
	// The control: sent straight to the upstream, a trailer is recorded, so an empty record below
	// means the relay dropped it.
	sendWithTrailer(t, up.Server, "X-Harmless", body)
	if got, _ := up.Last(); got.Trailer.Get("X-Harmless") != "forged" {
		t.Fatal("the fake upstream does not record a trailer sent to it directly")
	}
	for _, front := range []struct {
		name string
		h    http.Handler
	}{{"forwarded as it arrives", relay}, {"forwarded after the body is read", readFirst}} {
		srv := httptest.NewServer(front.h)
		t.Cleanup(srv.Close)
		for _, name := range []string{"X-Byward-Identity", "Authorization", "Forwarded", "X-Forwarded-For", "Origin", "Mcp-Session-Id", "X-Harmless"} {
			t.Run(front.name+"/"+name, func(t *testing.T) {
				before := len(up.Requests())
				if status := sendWithTrailer(t, srv, name, body); status != http.StatusOK {
					t.Fatalf("status %d", status)
				}
				got, _ := up.Last()
				if len(up.Requests()) != before+1 {
					t.Fatal("nothing reached the upstream")
				}
				if len(got.Trailer) != 0 || string(got.Body) != body {
					t.Fatalf("trailers %v, body %q reached the upstream", got.Trailer, got.Body)
				}
				// A regression guard: a Go upstream keeps trailers apart from headers, so this holds
				// unless the relay itself copies a trailer into the headers.
				if v := got.Header.Values(name); slices.Contains(v, "forged") {
					t.Fatalf("the trailer reached the upstream as the header %s: %q", name, v)
				}
				if v := got.Header.Values("X-Byward-Identity"); len(v) != 1 || v[0] != "ours" {
					t.Fatalf("X-Byward-Identity %q, want only ours", v)
				}
			})
		}
	}
}

// sendWithTrailer posts body to srv with the request trailer name: forged, and returns the
// response status. The body has no length, so it is sent chunked, which is what carries trailers.
func sendWithTrailer(t *testing.T, srv *httptest.Server, name, body string) int {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, srv.URL+"/mcp", io.NopCloser(strings.NewReader(body)))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Trailer = http.Header{name: {"forged"}}
	res, err := srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = res.Body.Close()
	return res.StatusCode
}
