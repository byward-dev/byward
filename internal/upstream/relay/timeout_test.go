package relay

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/http/httptrace"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/byward-dev/byward/internal/testutil/fakeupstream"
)

const headerTimeout = 50 * time.Millisecond

// stalled returns a relay whose upstream never sends response headers, its log, and a channel that
// receives once per upstream request when the proxy drops it. The upstream is released when the
// test ends, so a relay without the timeout fails the test instead of hanging it.
func stalled(t *testing.T) (http.Handler, *bytes.Buffer, <-chan struct{}) {
	t.Helper()
	dropped, release := make(chan struct{}, 4), make(chan struct{})
	up := fakeupstream.New()
	t.Cleanup(up.Close)
	t.Cleanup(func() { close(release) }) // runs before up.Close
	up.Handler = func(_ http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
			dropped <- struct{}{}
		case <-release:
		}
	}
	u, err := url.Parse(up.URL + "/mcp")
	if err != nil {
		t.Fatal(err)
	}
	logs := new(bytes.Buffer) // written before ServeHTTP returns, read after
	return New(slog.New(slog.NewTextHandler(logs, nil)), u, WithResponseHeaderTimeout(headerTimeout)), logs, dropped
}

// serveStalled serves r and fails the test if the relay is still waiting after 5 s: the request's
// in-flight slot would then still be held.
func serveStalled(t *testing.T, h http.Handler, r *http.Request) *httptest.ResponseRecorder {
	t.Helper()
	w := httptest.NewRecorder()
	done := make(chan struct{})
	go func() {
		defer close(done)
		h.ServeHTTP(w, r)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the relay is still waiting for the stalled upstream; its slot is not freed")
	}
	return w
}

func TestStalledUpstreamIsAnsweredAndDropped(t *testing.T) {
	overCapture := `{"jsonrpc":"2.0","method":"tools/call","params":{"pad":"` + strings.Repeat("x", captureLimit) + `"},"id":1}`
	cases := []struct {
		name, method, reqBody string
		wantStatus            int
		wantBody              string // substring; "" means empty body
	}{
		{"tools/call: tool error the model can read", "POST", toolsCall, 200,
			`{"id":7,"jsonrpc":"2.0","result":{"content":[{"text":"` + msgTimeout + `","type":"text"}],"isError":true}}`},
		{"another method: JSON-RPC error", "POST", `{"jsonrpc":"2.0","id":"a-1","method":"tools/list"}`, 200,
			`{"error":{"code":-32603,"data":{"upstreamTimeout":true},"message":"` + msgTimeout + `"},"id":"a-1","jsonrpc":"2.0"}`},
		{"notification: accepted", "POST", `{"jsonrpc":"2.0","method":"notifications/initialized"}`, 202, ""},
		{"GET stream: no stream offered", "GET", ``, 405, ""},
		{"batch: id unknown, 504", "POST", `[` + toolsCall + `]`, 504, "upstream did not answer in time"},
		{"not JSON-RPC: 504", "POST", `hello`, 504, "upstream did not answer in time"},
		{"body over the capture limit: id unknown, 504", "POST", overCapture, 504, "upstream did not answer in time"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			h, logs, dropped := stalled(t)
			w := serveStalled(t, h, httptest.NewRequest(c.method, "/mcp", strings.NewReader(c.reqBody)))
			if w.Code != c.wantStatus {
				t.Fatalf("status %d, want %d (body %q)", w.Code, c.wantStatus, w.Body)
			}
			if c.wantBody == "" && w.Body.Len() != 0 {
				t.Fatalf("body %q, want empty", w.Body)
			}
			if !strings.Contains(w.Body.String(), c.wantBody) {
				t.Fatalf("body %q, want %q", w.Body, c.wantBody)
			}
			if c.wantStatus == 200 && !json.Valid(w.Body.Bytes()) {
				t.Fatalf("not JSON: %s", w.Body)
			}
			if l := logs.String(); !strings.Contains(l, "upstream did not answer in time") || !strings.Contains(l, "no response headers within 50ms") {
				t.Errorf("the operator log lacks the timeout and its duration: %q", l)
			}
			select {
			case <-dropped:
			case <-time.After(5 * time.Second):
				t.Fatal("the upstream request was not dropped")
			}
		})
	}
}

func TestHeaderTimeoutDoesNotLimitAStreamedBody(t *testing.T) {
	// The headers must beat the timeout even on a loaded runner, and the body must come after it.
	const timeout = time.Second
	up := fakeupstream.New()
	t.Cleanup(up.Close)
	up.Handler = func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		w.(http.Flusher).Flush()
		time.Sleep(timeout + 200*time.Millisecond)
		_, _ = io.WriteString(w, "data: late\n\n")
	}
	u, err := url.Parse(up.URL + "/mcp")
	if err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	New(quiet(), u, WithResponseHeaderTimeout(timeout)).ServeHTTP(w, httptest.NewRequest("POST", "/mcp", strings.NewReader(toolsCall)))
	if w.Code != http.StatusOK || w.Body.String() != "data: late\n\n" {
		t.Fatalf("got %d %q, want the whole stream", w.Code, w.Body)
	}
}

type netTimeout struct{}

func (netTimeout) Error() string   { return "timeout awaiting response headers" }
func (netTimeout) Timeout() bool   { return true }
func (netTimeout) Temporary() bool { return true }

func TestOnlyATimeoutAfterTheRequestWasWrittenIsAHeaderTimeout(t *testing.T) {
	written := func(ctx context.Context) context.Context {
		ctx = traceWrite(ctx)
		httptrace.ContextClientTrace(ctx).WroteRequest(httptrace.WroteRequestInfo{})
		return ctx
	}
	gone, cancel := context.WithCancel(context.Background())
	cancel()
	cases := []struct {
		name string
		ctx  context.Context
		err  error
		want bool
	}{
		{"timeout after the request was written", written(context.Background()), netTimeout{}, true},
		{"wrapped timeout after the request was written", written(context.Background()), &url.Error{Op: "Post", URL: "u", Err: netTimeout{}}, true},
		{"dial or TLS timeout: the request was never written", traceWrite(context.Background()), netTimeout{}, false},
		{"untraced request", context.Background(), netTimeout{}, false},
		{"client went away", written(gone), netTimeout{}, false},
		{"connection refused", written(context.Background()), errors.New("dial tcp: connection refused"), false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := isHeaderTimeout(c.ctx, c.err); got != c.want {
				t.Errorf("isHeaderTimeout = %v, want %v for %v", got, c.want, c.err)
			}
		})
	}
}
