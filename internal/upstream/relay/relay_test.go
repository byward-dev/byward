package relay

import (
	"bytes"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/corker/mcp-authproxy/internal/testutil/fakeupstream"
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

func TestRelayIsByteTransparentAndStrips(t *testing.T) {
	up := fakeupstream.New()
	t.Cleanup(up.Close)
	body := []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"_meta":{"traceparent":"00-abc-def-01"}}}`)
	r := httptest.NewRequest("POST", "https://mcp.example.com/mcp?x=1", bytes.NewReader(body))
	r.Header.Set("Authorization", "Bearer secret")
	r.Header.Set("Forwarded", "for=1.2.3.4")
	r.Header.Set("X-Forwarded-For", "1.2.3.4")
	r.Header.Set("X-Forwarded-User", "admin")
	r.Header.Set("x-forwarded-prefix", "/evil")
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
		if k == "Authorization" || k == "Forwarded" || strings.HasPrefix(k, "X-Forwarded-") {
			t.Fatalf("header %s reached the upstream", k)
		}
	}
	if got.Header.Get("Mcp-Session-Id") != "s1" {
		t.Fatal("MCP headers must pass through")
	}
}

func TestRelayHidesUpstreamErrors(t *testing.T) {
	u, _ := url.Parse("http://127.0.0.1:1/mcp")
	w := httptest.NewRecorder()
	New(quiet(), u).ServeHTTP(w, httptest.NewRequest("POST", "/mcp", nil))
	if w.Code != http.StatusBadGateway || strings.Contains(w.Body.String(), "127.0.0.1") {
		t.Fatalf("code=%d body=%q", w.Code, w.Body)
	}
}

func TestRelayInFlightCap(t *testing.T) {
	up := fakeupstream.New()
	t.Cleanup(up.Close)
	release := make(chan struct{})
	var started sync.WaitGroup
	started.Add(MaxInFlight)
	up.Handler = func(w http.ResponseWriter, _ *http.Request) { started.Done(); <-release }
	h := relayTo(t, up, "/mcp")
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)

	var done sync.WaitGroup
	for range MaxInFlight {
		done.Add(1)
		go func() {
			defer done.Done()
			if res, err := http.Post(srv.URL, "application/json", nil); err == nil {
				_ = res.Body.Close()
			}
		}()
	}
	started.Wait()
	res, err := http.Post(srv.URL, "application/json", nil)
	if err != nil {
		t.Fatal(err)
	}
	_ = res.Body.Close()
	close(release)
	done.Wait()
	if res.StatusCode != http.StatusServiceUnavailable || res.Header.Get("Retry-After") == "" {
		t.Fatalf("over the cap: got %d", res.StatusCode)
	}
}

func TestRelayStreamsServerSentEvents(t *testing.T) {
	up := fakeupstream.New()
	t.Cleanup(up.Close)
	next := make(chan struct{})
	up.Handler = func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, "data: one\n\n")
		w.(http.Flusher).Flush()
		<-next
		_, _ = io.WriteString(w, "data: two\n\n")
	}
	srv := httptest.NewServer(relayTo(t, up, "/mcp"))
	t.Cleanup(srv.Close)
	res, err := http.Post(srv.URL, "application/json", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = res.Body.Close() }()
	buf := make([]byte, 64)
	n, err := res.Body.Read(buf)
	if err != nil || string(buf[:n]) != "data: one\n\n" {
		t.Fatalf("first event not flushed: %q %v", buf[:n], err)
	}
	close(next)
}
