//go:build linux || darwin

package stdio

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/byward-dev/byward/internal/logging"
)

// observed serves req with the bridge through logging.Observe, as the server's wrappers do, on w in
// the background. Its result waits until the bridge has returned and is what Observe recorded.
func (b *bridgeHarness) observed(t *testing.T, w http.ResponseWriter, req *http.Request) func() logging.CutOff {
	t.Helper()
	var cut logging.CutOff
	done := make(chan struct{})
	go func() {
		defer close(done)
		logging.Observe(w, req, b.bridge, func(_ int, c logging.CutOff) { cut = c })
	}()
	return func() logging.CutOff {
		t.Helper()
		select {
		case <-done:
		case <-time.After(guard):
			t.Fatal("the bridge did not return")
		}
		return cut
	}
}

// A stream from the upstream process that its request's end cuts off, its headers already sent, is
// recorded with why (#533): client_closed when its MCP client went away, shutdown when the proxy
// shut down. A listen the shutdown ends with its completion result has completed, so it is not cut
// off.
func TestAStdioStreamEndedByItsRequestIsRecordedAsCutOffUnlessItCompleted(t *testing.T) {
	for _, stream := range []struct {
		name string
		// open starts the bridge and returns the request of a stream that stays open until its
		// request ends.
		open func(t *testing.T, b *bridgeHarness, ctx context.Context) *http.Request
		// modern bridges serve the 2026-07-28 era; the others the legacy one.
		modern bool
		// completes: the proxy's shutdown ends it with its completion result.
		completes bool
	}{
		{"a legacy GET stream", func(t *testing.T, b *bridgeHarness, ctx context.Context) *http.Request {
			return b.request(ctx, http.MethodGet, "alice", b.initialize(t, "alice"), "")
		}, false, false},
		{"a legacy POST stream", func(t *testing.T, b *bridgeHarness, ctx context.Context) *http.Request {
			return b.request(ctx, http.MethodPost, "alice", b.initialize(t, "alice"), `{"jsonrpc":"2.0","id":2,"method":"hold"}`)
		}, false, false},
		{"a modern request's stream", func(_ *testing.T, b *bridgeHarness, ctx context.Context) *http.Request {
			body := modernBody(`"h"`, "hold", "", "")
			return b.request(ctx, http.MethodPost, "alice", "", body, modernHeaders(body)...)
		}, true, false},
		{"a modern listen", func(_ *testing.T, b *bridgeHarness, ctx context.Context) *http.Request {
			body := modernBody(`"L"`, "subscriptions/listen", "", `"notifications":{"toolsListChanged":true}`)
			return b.request(ctx, http.MethodPost, "alice", "", body, modernHeaders(body)...)
		}, true, true},
	} {
		for _, e := range endings {
			t.Run(stream.name+", "+e.name, func(t *testing.T) {
				b := newBridge(t, nil)
				if stream.modern {
					b = newModernBridge(t, nil)
				}
				ctx, end := e.start()
				defer end()
				w := &brokenWriter{header: http.Header{}}
				cut := b.observed(t, w, stream.open(t, b, ctx))
				eventually(t, "the stream to start", w.hasStarted) // after its request reached the upstream
				if stream.completes {
					eventually(t, "the acknowledgement", func() bool { return strings.Contains(w.written(), "acknowledged") })
				}
				end()
				want := e.cut
				if e.shutdown && stream.completes { // ended with its completion result
					want = ""
				}
				if got := cut(); got != want {
					t.Errorf("recorded as cut off %q; want %q (body %q)", got, want, w.written())
				}
			})
		}
	}
}

// A stream whose write to its MCP client fails, its request still live, has lost its client: it is
// recorded as cut off with client_closed, whatever the write was and wherever it failed (#533). A
// listen the proxy ends with its completion result has completed, so it is not cut off, unless that
// result cannot be written.
func TestAStdioStreamWhoseWriteFailsIsRecordedAsClientClosedAndACompletedListenIsNot(t *testing.T) {
	const announce = `{"jsonrpc":"2.0","id":9,"method":"announce"}`
	const hold, release = `{"jsonrpc":"2.0","id":2,"method":"hold"}`, `{"jsonrpc":"2.0","id":3,"method":"release"}`
	modern := func(b *bridgeHarness, body string) *http.Request {
		return b.request(context.Background(), http.MethodPost, "alice", "", body, modernHeaders(body)...)
	}
	listen := modernBody(`"L"`, "subscriptions/listen", "", `"notifications":{"toolsListChanged":true}`)
	// An ender ends an open stream; breakIn makes its writer fail, at a write or at a flush.
	type ender = func(t *testing.T, b *bridgeHarness, breakIn func())
	for _, tc := range []struct {
		name   string
		modern bool
		// open returns the stream's request, and what ends it once it is open.
		open func(t *testing.T, b *bridgeHarness) (*http.Request, ender)
		// acked: the stream is open once its acknowledgement is written.
		acked bool
		want  logging.CutOff
		// breaks: the ender makes the writer fail, so the row runs once for each failure. One that
		// does not runs once, and its body must hold written.
		breaks  bool
		written string
	}{
		{"a legacy GET stream, a message", false, func(t *testing.T, b *bridgeHarness) (*http.Request, ender) {
			sid := b.initialize(t, "alice")
			return b.request(context.Background(), http.MethodGet, "alice", sid, ""), func(t *testing.T, b *bridgeHarness, breakIn func()) {
				breakIn()
				readEvents(t, b.post(t, "alice", sid, announce))
			}
		}, false, logging.ClientClosed, true, ""},
		{"a legacy GET stream, a keep-alive", false, func(t *testing.T, b *bridgeHarness) (*http.Request, ender) {
			return b.request(context.Background(), http.MethodGet, "alice", b.initialize(t, "alice"), ""), func(_ *testing.T, b *bridgeHarness, breakIn func()) {
				breakIn()
				b.clk.Advance(keepAliveInterval)
			}
		}, false, logging.ClientClosed, true, ""},
		{"a legacy POST stream, its answer", false, func(t *testing.T, b *bridgeHarness) (*http.Request, ender) {
			sid := b.initialize(t, "alice")
			return b.request(context.Background(), http.MethodPost, "alice", sid, hold), func(t *testing.T, b *bridgeHarness, breakIn func()) {
				b.stderrSaid(t, "holding")
				breakIn()
				readEvents(t, b.post(t, "alice", sid, release))
			}
		}, false, logging.ClientClosed, true, ""},
		{"a legacy POST stream, the error its ended session gets", false, func(t *testing.T, b *bridgeHarness) (*http.Request, ender) {
			sid := b.initialize(t, "alice")
			return b.request(context.Background(), http.MethodPost, "alice", sid, hold), func(t *testing.T, b *bridgeHarness, breakIn func()) {
				b.stderrSaid(t, "holding")
				breakIn()
				if w := b.serve(context.Background(), http.MethodDelete, "alice", sid, ""); w.Code != http.StatusNoContent {
					t.Fatalf("DELETE: status %d", w.Code)
				}
			}
		}, false, logging.ClientClosed, true, ""},
		{"a modern request's stream, its answer", true, func(_ *testing.T, b *bridgeHarness) (*http.Request, ender) {
			return modern(b, modernBody(`"h"`, "hold", "", "")), func(t *testing.T, b *bridgeHarness, breakIn func()) {
				breakIn()
				readEvents(t, b.modern(t, "alice", modernBody(`2`, "release", "", "")))
			}
		}, false, logging.ClientClosed, true, ""},
		{"a modern listen, a notification", true, func(_ *testing.T, b *bridgeHarness) (*http.Request, ender) {
			return modern(b, listen), func(t *testing.T, b *bridgeHarness, breakIn func()) {
				breakIn()
				readEvents(t, b.modern(t, "alice", modernBody(`1`, "notify", "", "")))
			}
		}, true, logging.ClientClosed, true, ""},
		{"a modern listen, a keep-alive", true, func(_ *testing.T, b *bridgeHarness) (*http.Request, ender) {
			return modern(b, listen), func(_ *testing.T, b *bridgeHarness, breakIn func()) {
				breakIn()
				b.clk.Advance(keepAliveInterval)
			}
		}, true, logging.ClientClosed, true, ""},
		{"a modern listen ended with its completion result", true, func(_ *testing.T, b *bridgeHarness) (*http.Request, ender) {
			return modern(b, listen), func(_ *testing.T, b *bridgeHarness, _ func()) { b.bridge.Drain() }
		}, true, "", false, `"resultType":"complete"`},
		{"a modern listen whose completion result cannot be written", true, func(_ *testing.T, b *bridgeHarness) (*http.Request, ender) {
			return modern(b, listen), func(_ *testing.T, b *bridgeHarness, breakIn func()) {
				breakIn()
				b.bridge.Drain()
			}
		}, true, logging.ClientClosed, true, ""},
	} {
		runs := map[string]string{tc.name: ""} // each subtest's name, and what fails in it
		if tc.breaks {
			runs = map[string]string{}
			for _, what := range failures {
				runs[tc.name+", "+what+" fails"] = what
			}
		}
		for name, what := range runs {
			t.Run(name, func(t *testing.T) {
				b := newBridge(t, nil)
				if tc.modern {
					b = newModernBridge(t, nil)
				}
				req, endIt := tc.open(t, b)
				w := &brokenWriter{header: http.Header{}}
				cut := b.observed(t, w, req)
				eventually(t, "the stream to start", w.hasStarted)
				if tc.acked {
					eventually(t, "the acknowledgement", func() bool { return strings.Contains(w.written(), "acknowledged") })
				}
				endIt(t, b, func() { w.breakIn(what) })
				if got := cut(); got != tc.want {
					t.Errorf("recorded as cut off %q; want %q (body %q)", got, tc.want, w.written())
				}
				if !strings.Contains(w.written(), tc.written) {
					t.Errorf("body %q; want it to hold %s", w.written(), tc.written)
				}
			})
		}
	}
}

// An initialize whose stream has started, with a notification the upstream sent before it holds its
// answer, and whose request then ends, is cut off and logs no initialize failure: it ended because
// its request did (#533, #549).
func TestAnInitializeEndedByItsRequestAfterItsStreamStartedIsCutOffAndLogsNoInitializeFailure(t *testing.T) {
	for _, e := range endings {
		t.Run(e.name, func(t *testing.T) {
			b := newBridge(t, func(c *Config) { c.Command = append(c.Command, "-init=lognhold") })
			ctx, end := e.start()
			defer end()
			w := &brokenWriter{header: http.Header{}}
			cut := b.observed(t, w, b.request(ctx, http.MethodPost, "alice", "", initialize))
			eventually(t, "the notification", func() bool { return strings.Contains(w.written(), `"method":"notifications/message"`) })
			end()
			if got := cut(); got != e.cut {
				t.Errorf("recorded as cut off %q; want %q", got, e.cut)
			}
			b.noFailureLogged(t)
		})
	}
}

// A stream that ends without its request ending or a write failing is not cut off, however it ends:
// with its answer, with the error its process's exit or its session's end gets, by the upstream
// ending a subscription, or as a GET stream another replaces (#533).
func TestAStdioStreamThatEndsOtherwiseIsNotCutOff(t *testing.T) {
	const hold = `{"jsonrpc":"2.0","id":2,"method":"hold"}`
	modern := func(b *bridgeHarness, body string) *http.Request {
		return b.request(context.Background(), http.MethodPost, "alice", "", body, modernHeaders(body)...)
	}
	deleteSession := func(t *testing.T, b *bridgeHarness, sid string) {
		t.Helper()
		if w := b.serve(context.Background(), http.MethodDelete, "alice", sid, ""); w.Code != http.StatusNoContent {
			t.Fatalf("DELETE: status %d", w.Code)
		}
	}
	listen := modernBody(`"L"`, "subscriptions/listen", "", `"notifications":{"toolsListChanged":true}`)
	for _, tc := range []struct {
		name   string
		modern bool
		// open returns the stream's request, and what ends it once it is open (nil: it ends itself).
		open func(t *testing.T, b *bridgeHarness) (*http.Request, func(t *testing.T, b *bridgeHarness))
		// acked: the stream is open once its acknowledgement is written.
		acked bool
	}{
		{"a legacy POST stream, answered", false, func(t *testing.T, b *bridgeHarness) (*http.Request, func(*testing.T, *bridgeHarness)) {
			return b.request(context.Background(), http.MethodPost, "alice", b.initialize(t, "alice"), `{"jsonrpc":"2.0","id":2,"method":"tools/list"}`), nil
		}, false},
		{"a legacy POST stream, its session ended", false, func(t *testing.T, b *bridgeHarness) (*http.Request, func(*testing.T, *bridgeHarness)) {
			sid := b.initialize(t, "alice")
			return b.request(context.Background(), http.MethodPost, "alice", sid, hold), func(t *testing.T, b *bridgeHarness) {
				b.stderrSaid(t, "holding")
				deleteSession(t, b, sid)
			}
		}, false},
		{"a legacy GET stream, its session ended", false, func(t *testing.T, b *bridgeHarness) (*http.Request, func(*testing.T, *bridgeHarness)) {
			sid := b.initialize(t, "alice")
			return b.request(context.Background(), http.MethodGet, "alice", sid, ""), func(t *testing.T, b *bridgeHarness) { deleteSession(t, b, sid) }
		}, false},
		{"a legacy GET stream, replaced by a newer one", false, func(t *testing.T, b *bridgeHarness) (*http.Request, func(*testing.T, *bridgeHarness)) {
			sid := b.initialize(t, "alice")
			return b.request(context.Background(), http.MethodGet, "alice", sid, ""), func(t *testing.T, b *bridgeHarness) { b.listen(t, context.Background(), sid) }
		}, false},
		{"a modern request's stream, answered", true, func(_ *testing.T, b *bridgeHarness) (*http.Request, func(*testing.T, *bridgeHarness)) {
			return modern(b, modernBody(`1`, "env", "", "")), nil
		}, false},
		{"a modern request's stream, its process exited", true, func(_ *testing.T, b *bridgeHarness) (*http.Request, func(*testing.T, *bridgeHarness)) {
			return modern(b, modernBody(`1`, "crash", "", "")), nil
		}, false},
		{"a modern listen the upstream ended", true, func(_ *testing.T, b *bridgeHarness) (*http.Request, func(*testing.T, *bridgeHarness)) {
			return modern(b, listen), func(t *testing.T, b *bridgeHarness) {
				readEvents(t, b.modern(t, "alice", modernBody(`1`, "teardown", "", "")))
			}
		}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b := newBridge(t, nil)
			if tc.modern {
				b = newModernBridge(t, nil)
			}
			req, endIt := tc.open(t, b)
			w := &brokenWriter{header: http.Header{}}
			cut := b.observed(t, w, req)
			eventually(t, "the stream to start", w.hasStarted)
			if tc.acked {
				eventually(t, "the acknowledgement", func() bool { return strings.Contains(w.written(), "acknowledged") })
			}
			if endIt != nil {
				endIt(t, b)
			}
			if got := cut(); got != "" {
				t.Errorf("recorded as cut off %q; want none (body %q)", got, w.written())
			}
		})
	}
}
