package relay

import (
	"bufio"
	"bytes"
	"context"
	"io"
	"log"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httptrace"
	"net/textproto"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

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

// The upstream's response trailers never reach the MCP client, announced or not, the headers the relay
// cleans included: they arrive after the body, out of reach of that cleaning and of the session
// binding.
func TestRelayDropsUpstreamTrailers(t *testing.T) {
	for _, tc := range []struct {
		name     string
		trailer  func(w http.ResponseWriter) // sets the trailers after the body is written and flushed
		announce string
	}{
		{"announced", func(w http.ResponseWriter) { w.Header().Set("Mcp-Session-Id", "raw") }, "Mcp-Session-Id"},
		{"unannounced only", func(w http.ResponseWriter) { w.Header().Set(http.TrailerPrefix+"Mcp-Session-Id", "raw") }, ""},
		{"the headers the relay cleans", func(w http.ResponseWriter) {
			w.Header().Set("Access-Control-Allow-Origin", "*")
			w.Header().Set(http.TrailerPrefix+"Www-Authenticate", `Bearer resource_metadata="https://evil.example"`)
		}, "Access-Control-Allow-Origin"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			up := fakeupstream.New()
			t.Cleanup(up.Close)
			up.Handler = func(w http.ResponseWriter, _ *http.Request) {
				if tc.announce != "" {
					w.Header().Set("Trailer", tc.announce)
				}
				_, _ = io.WriteString(w, "ok")
				w.(http.Flusher).Flush() // chunked, so even an unannounced trailer goes on the wire
				tc.trailer(w)
			}
			srv := httptest.NewServer(relayTo(t, up, "/mcp"))
			t.Cleanup(srv.Close)
			res, err := srv.Client().Post(srv.URL+"/mcp", "application/json", strings.NewReader(`{}`))
			if err != nil {
				t.Fatal(err)
			}
			body, _ := io.ReadAll(res.Body) // trailers arrive at the end of the body
			_ = res.Body.Close()
			if string(body) != "ok" || len(res.Trailer) != 0 {
				t.Fatalf("body %q, trailers %v reached the client", body, res.Trailer)
			}
		})
	}
}

// A client's request to switch protocols never reaches the upstream, whatever the method: MCP never
// upgrades, and the raw connection would bypass the session binding.
func TestAClientsUpgradeRequestNeverReachesTheUpstream(t *testing.T) {
	up := fakeupstream.New()
	t.Cleanup(up.Close)
	srv := httptest.NewServer(relayTo(t, up, "/mcp"))
	t.Cleanup(srv.Close)
	for _, method := range []string{http.MethodGet, http.MethodPost} {
		t.Run(method, func(t *testing.T) {
			req, _ := http.NewRequest(method, srv.URL+"/mcp", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"ping"}`))
			req.Header.Set("Connection", "Upgrade")
			req.Header.Set("Upgrade", "websocket")
			res, err := srv.Client().Do(req)
			if err != nil {
				t.Fatal(err)
			}
			_ = res.Body.Close()
			got, ok := up.Last()
			if !ok || got.Method != method {
				t.Fatalf("the upstream got %+v, want the %s", got, method)
			}
			if got.Header.Get("Upgrade") != "" || strings.Contains(strings.ToLower(strings.Join(got.Header.Values("Connection"), ",")), "upgrade") {
				t.Fatalf("Upgrade %q, Connection %q reached the upstream", got.Header.Get("Upgrade"), got.Header.Values("Connection"))
			}
		})
	}
}

// An upstream that switches protocols anyway gets the client a 502 with none of its headers (never its
// raw Mcp-Session-Id, never a raw connection past the session binding), and the operator a log line
// saying why. With the client's Upgrade already stripped, ReverseProxy itself would refuse the 101
// too; the log line is what pins the relay's own refusal.
func TestAnUpstreamThatSwitchesProtocolsGetsTheClientA502(t *testing.T) {
	for _, tc := range []struct {
		name    string
		upgrade bool // the upstream names the protocol it switches to
	}{{"naming the protocol", true}, {"bare", false}} {
		t.Run(tc.name, func(t *testing.T) {
			up := fakeupstream.New()
			t.Cleanup(up.Close)
			up.Handler = func(w http.ResponseWriter, _ *http.Request) {
				if tc.upgrade {
					w.Header().Set("Connection", "Upgrade")
					w.Header().Set("Upgrade", "websocket")
				}
				w.Header().Set("Mcp-Session-Id", "raw")
				w.WriteHeader(http.StatusSwitchingProtocols)
			}
			u, _ := url.Parse(up.URL + "/mcp")
			var logs bytes.Buffer
			srv := httptest.NewServer(New(slog.New(slog.NewTextHandler(&logs, nil)), u))
			t.Cleanup(srv.Close)
			conn, err := net.Dial("tcp", strings.TrimPrefix(srv.URL, "http://"))
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = conn.Close() }()
			_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
			if _, err := io.WriteString(conn, "POST /mcp HTTP/1.1\r\nHost: mcp.example.com\r\nContent-Length: 2\r\n\r\n{}"); err != nil {
				t.Fatal(err)
			}
			res, err := http.ReadResponse(bufio.NewReader(conn), nil)
			if err != nil {
				t.Fatal(err)
			}
			_ = res.Body.Close()
			if res.StatusCode != http.StatusBadGateway || res.Header.Get("Mcp-Session-Id") != "" || res.Header.Get("Upgrade") != "" {
				t.Fatalf("status %d, headers %v; want 502 with none of the upstream's headers", res.StatusCode, res.Header)
			}
			if !strings.Contains(logs.String(), errUpstreamUpgrade.Error()) {
				t.Fatalf("log %q does not say the upstream switched protocols", logs.String())
			}
		})
	}
}

// An upstream's informational responses (100, 102, 103) reach the MCP client with Link and
// Mcp-Session-Id only (which the binding seals): the headers the relay cleans from the final response,
// and any others, never ride along on a 1xx, past ModifyResponse. The final response is untouched.
func TestAnUpstreamsInformationalResponsesCarryOnlyLinkAndTheSession(t *testing.T) {
	hinted := map[string]string{"Link": "</style.css>; rel=preload", "Mcp-Session-Id": "raw", "Access-Control-Allow-Origin": "*",
		"Www-Authenticate": `Bearer resource_metadata="https://evil.example"`, "Set-Cookie": "up=1", "X-Other": "x"}
	for _, code := range []int{http.StatusContinue, http.StatusProcessing, http.StatusEarlyHints} {
		t.Run(http.StatusText(code), func(t *testing.T) {
			up := fakeupstream.New()
			t.Cleanup(up.Close)
			up.Handler = func(w http.ResponseWriter, _ *http.Request) {
				for k, v := range hinted {
					w.Header().Set(k, v)
				}
				w.WriteHeader(code)
				for k := range hinted {
					w.Header().Del(k) // a 1xx's headers would otherwise ride on the final response too
				}
				w.Header().Set("Content-Type", "application/json")
				_, _ = io.WriteString(w, "{}")
			}
			fetch := func(t *testing.T, url string) (http.Header, *http.Response) {
				t.Helper()
				var got http.Header
				trace := &httptrace.ClientTrace{Got1xxResponse: func(c int, h textproto.MIMEHeader) error {
					if c == code {
						got = http.Header(h).Clone()
					}
					return nil
				}}
				req, _ := http.NewRequestWithContext(httptrace.WithClientTrace(context.Background(), trace), http.MethodPost, url, strings.NewReader(`{}`))
				res, err := http.DefaultClient.Do(req)
				if err != nil {
					t.Fatal(err)
				}
				_, _ = io.ReadAll(res.Body)
				_ = res.Body.Close()
				return got, res
			}
			// The control: straight from the upstream, the 1xx carries every header.
			if direct, _ := fetch(t, up.URL); len(direct) != len(hinted) {
				t.Fatalf("the upstream's %d carried %v, want all of %v", code, direct, hinted)
			}
			srv := httptest.NewServer(relayTo(t, up, "/mcp"))
			t.Cleanup(srv.Close)
			got, res := fetch(t, srv.URL+"/mcp")
			if len(got) != 2 || got.Get("Link") != hinted["Link"] || got.Get("Mcp-Session-Id") != "raw" {
				t.Fatalf("the %d reached the client with %v, want Link and Mcp-Session-Id only", code, got)
			}
			if res.StatusCode != http.StatusOK || res.Header.Get("Content-Type") != "application/json" {
				t.Fatalf("final response %d %v", res.StatusCode, res.Header)
			}
		})
	}
}

// The headers the proxy set before the relay ran (CORS, the request ID, and every value of each) survive
// an upstream's 1xx, which ReverseProxy clears the header map after, whatever final response follows:
// the upstream's own, a failure it sends, or the relay's 502 when it hangs up. They never override a
// header the upstream's final response sets, and the upstream's own CORS headers stay dropped.
func TestTheProxysOwnHeadersSurviveAnUpstreamsInformationalResponse(t *testing.T) {
	for _, tc := range []struct {
		name  string
		final func(w http.ResponseWriter) // after the 103
		want  int
	}{
		{"a success", func(w http.ResponseWriter) {
			w.Header().Set("Vary", "Accept")
			w.Header().Set("Access-Control-Allow-Origin", "*")
			_, _ = io.WriteString(w, "{}")
		}, http.StatusOK},
		{"a failure", func(w http.ResponseWriter) {
			w.Header().Set("Vary", "Accept")
			w.Header().Set("Access-Control-Allow-Origin", "*")
			w.WriteHeader(http.StatusInternalServerError)
		}, http.StatusInternalServerError},
		{"a hang-up", func(http.ResponseWriter) { panic(http.ErrAbortHandler) }, http.StatusBadGateway},
	} {
		t.Run(tc.name, func(t *testing.T) {
			up := fakeupstream.New()
			t.Cleanup(up.Close)
			up.Handler = func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Link", "</style.css>; rel=preload")
				w.WriteHeader(http.StatusEarlyHints)
				w.Header().Del("Link")
				tc.final(w)
			}
			relay := relayTo(t, up, "/mcp")
			srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("X-Request-Id", "req-1")
				w.Header().Set("Access-Control-Allow-Origin", "https://app.example")
				w.Header()["Access-Control-Expose-Headers"] = []string{"Mcp-Session-Id", "X-Request-Id"}
				w.Header().Set("Vary", "Origin")
				relay.ServeHTTP(w, r)
			}))
			var serverLog bytes.Buffer // net/http's own complaints, such as a status written twice
			srv.Config.ErrorLog = log.New(&serverLog, "", 0)
			srv.Start()
			t.Cleanup(srv.Close)
			hinted := false
			trace := &httptrace.ClientTrace{Got1xxResponse: func(code int, _ textproto.MIMEHeader) error {
				hinted = hinted || code == http.StatusEarlyHints
				return nil
			}}
			req, _ := http.NewRequestWithContext(httptrace.WithClientTrace(context.Background(), trace), http.MethodPost, srv.URL+"/mcp", strings.NewReader(`{}`))
			res, err := srv.Client().Do(req)
			if err != nil {
				t.Fatal(err)
			}
			_, _ = io.ReadAll(res.Body)
			_ = res.Body.Close()
			if !hinted || res.StatusCode != tc.want {
				t.Fatalf("103 seen %v, final status %d; want a 103 then %d", hinted, res.StatusCode, tc.want)
			}
			if res.Header.Get("X-Request-Id") != "req-1" || !slices.Equal(res.Header.Values("Access-Control-Allow-Origin"), []string{"https://app.example"}) ||
				!slices.Equal(res.Header.Values("Access-Control-Expose-Headers"), []string{"Mcp-Session-Id", "X-Request-Id"}) {
				t.Fatalf("final headers %v; want the proxy's request ID and CORS back, every value, and not the upstream's", res.Header)
			}
			if tc.want != http.StatusBadGateway && !slices.Equal(res.Header.Values("Vary"), []string{"Accept"}) {
				t.Fatalf("Vary %q; want the upstream's final header as it set it", res.Header.Values("Vary"))
			}
			srv.Close() // flushes the server's log
			if strings.Contains(serverLog.String(), "superfluous") {
				t.Fatalf("the relay wrote a status twice: %s", serverLog.String())
			}
		})
	}
}

// The proxy's own headers also survive when the answer after a 1xx is the relay's own body with no
// status written first: the header-timeout answer to an upstream that sent a 103 and then nothing.
func TestTheProxysOwnHeadersSurviveATimeoutAfterAnInformationalResponse(t *testing.T) {
	up := fakeupstream.New()
	t.Cleanup(up.Close)
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	up.Handler = func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Link", "</style.css>; rel=preload")
		w.WriteHeader(http.StatusEarlyHints)
		select { // no final response until the relay has given up
		case <-release:
		case <-r.Context().Done():
		}
	}
	u, _ := url.Parse(up.URL + "/mcp")
	relay := New(quiet(), u, WithResponseHeaderTimeout(200*time.Millisecond))
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Request-Id", "req-1")
		w.Header().Set("Access-Control-Allow-Origin", "https://app.example")
		relay.ServeHTTP(w, r)
	}))
	t.Cleanup(srv.Close)
	hinted := false
	trace := &httptrace.ClientTrace{Got1xxResponse: func(code int, _ textproto.MIMEHeader) error {
		hinted = hinted || code == http.StatusEarlyHints
		return nil
	}}
	req, _ := http.NewRequestWithContext(httptrace.WithClientTrace(context.Background(), trace), http.MethodPost, srv.URL+"/mcp",
		strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{}}`))
	res, err := srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(res.Body)
	_ = res.Body.Close()
	if !hinted {
		t.Fatal("no 103 reached the client, so this test proves nothing")
	}
	if res.StatusCode != http.StatusOK || !strings.Contains(string(body), `"id":1`) {
		t.Fatalf("status %d, body %s; want the timeout answer", res.StatusCode, body)
	}
	if res.Header.Get("X-Request-Id") != "req-1" || res.Header.Get("Access-Control-Allow-Origin") != "https://app.example" {
		t.Fatalf("final headers %v; want the proxy's request ID and CORS back", res.Header)
	}
}

// An interim 101 (an HTTP/2 upstream can send one; it reaches the writer through ReverseProxy's 1xx
// hook, never ModifyResponse) is dropped: the final response that follows is the one the MCP client
// gets, with none of the 101's headers.
func TestAnInterimSwitchingProtocolsIsNeverForwarded(t *testing.T) {
	rec := httptest.NewRecorder()
	w := &informational{ResponseWriter: rec, ours: http.Header{}}
	w.Header().Set("Mcp-Session-Id", "raw-101")
	w.WriteHeader(http.StatusSwitchingProtocols)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if rec.Code != http.StatusOK || rec.Header().Get("Mcp-Session-Id") != "" {
		t.Fatalf("status %d, headers %v; want the final 200 without the 101's headers", rec.Code, rec.Header())
	}
}

// An upstream redirect never reaches the MCP client, which would follow it away from the proxy: the
// client gets 502 and the log names where the upstream pointed, without the parts that could carry
// a secret. A 304 answers a conditional request and is passed on.
func TestAnUpstreamRedirectGetsTheClientA502AndTheLogWhereItPointed(t *testing.T) {
	up := fakeupstream.New()
	t.Cleanup(up.Close)
	for _, tc := range []struct {
		name     string
		status   int
		location string
		logged   string // in the log's reason; "" for a 304
	}{
		{"moved permanently, with the fix", http.StatusMovedPermanently, "https://mcp.internal.example/mcp", "points to https://mcp.internal.example/mcp; if that is its MCP endpoint, set BYWARD_UPSTREAM_URL to it"},
		{"found", http.StatusFound, "https://mcp.internal.example/mcp", "points to https://mcp.internal.example/mcp;"},
		{"see other", http.StatusSeeOther, "https://mcp.internal.example/mcp", "points to https://mcp.internal.example/mcp;"},
		{"temporary", http.StatusTemporaryRedirect, "https://mcp.internal.example/mcp", "points to https://mcp.internal.example/mcp;"},
		{"permanent", http.StatusPermanentRedirect, "https://mcp.internal.example/mcp", "points to https://mcp.internal.example/mcp;"},
		{"multiple choices", http.StatusMultipleChoices, "https://mcp.internal.example/mcp", "points to https://mcp.internal.example/mcp;"},
		{"relative", http.StatusPermanentRedirect, "/mcp/", "points to " + up.URL + "/mcp/;"},
		{"userinfo, query and fragment are dropped", http.StatusFound, "https://user:pw-secret@sso.example/login?code=code-secret#frag-secret", "points to https://sso.example/login;"},
		{"path parameters are dropped", http.StatusFound, "/cb;jsessionid=sess-secret", "points to " + up.URL + "/cb;"},
		{"an opaque Location is not logged", http.StatusFound, "https:tok-secret", "the upstream sent no usable Location"},
		{"without a Location", http.StatusFound, "", "the upstream sent no usable Location"},
		{"not modified is passed on", http.StatusNotModified, "", ""},
		{"a bad request is passed on", http.StatusBadRequest, "", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			up.Handler = func(w http.ResponseWriter, _ *http.Request) {
				if tc.location != "" {
					w.Header().Set("Location", tc.location)
				}
				w.WriteHeader(tc.status)
			}
			u, _ := url.Parse(up.URL + "/mcp")
			var logs bytes.Buffer
			w := httptest.NewRecorder()
			New(slog.New(slog.NewTextHandler(&logs, nil)), u).ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader("{}")))
			if tc.logged == "" {
				if w.Code != tc.status || logs.Len() != 0 {
					t.Fatalf("status %d, log %q; want the %d passed on, nothing logged", w.Code, logs.String(), tc.status)
				}
				return
			}
			if w.Code != http.StatusBadGateway || w.Header().Get("Location") != "" || strings.Contains(w.Body.String(), "example") {
				t.Fatalf("status %d, Location %q, body %q; want 502 that names nothing of the upstream's", w.Code, w.Header().Get("Location"), w.Body)
			}
			if !strings.Contains(logs.String(), `level=ERROR msg="upstream redirected the request"`) || !strings.Contains(logs.String(), tc.logged) ||
				!strings.Contains(logs.String(), "status="+strconv.Itoa(tc.status)) {
				t.Fatalf("log %q; want the redirect, its status and %q", logs.String(), tc.logged)
			}
			if strings.Contains(logs.String(), "secret") || strings.Contains(logs.String(), "upstream error") {
				t.Fatalf("log %q names a secret or logs the redirect twice", logs.String())
			}
		})
	}
}
