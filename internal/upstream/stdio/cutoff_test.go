//go:build linux || darwin

package stdio

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/byward-dev/byward/internal/logging"
)

// listenBody is a modern subscriptions/listen under the client id "L".
var listenBody = modernBody(`"L"`, "subscriptions/listen", "", `"notifications":{"toolsListChanged":true}`)

// modernRequest is a 2026-07-28 POST of body as alice, with ctx.
func (b *bridgeHarness) modernRequest(ctx context.Context, body string) *http.Request {
	return b.request(ctx, http.MethodPost, "alice", "", body, modernHeaders(body)...)
}

// endSession ends alice's legacy MCP session sid with a DELETE.
func (b *bridgeHarness) endSession(t *testing.T, sid string) {
	t.Helper()
	if w := b.serve(context.Background(), http.MethodDelete, "alice", sid, ""); w.Code != http.StatusNoContent {
		t.Fatalf("DELETE: status %d", w.Code)
	}
}

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

// observeStream starts a bridge of the modern era or the legacy one, serves the request open builds
// through observed on a writer that can be broken, and waits until its stream is open: started, and
// for a listen (acked), acknowledged.
func observeStream(t *testing.T, modern, acked bool, open func(*bridgeHarness) *http.Request) (*bridgeHarness, *brokenWriter, func() logging.CutOff) {
	t.Helper()
	b := newBridge
	if modern {
		b = newModernBridge
	}
	h := b(t, nil)
	w := &brokenWriter{header: http.Header{}}
	cut := h.observed(t, w, open(h))
	eventually(t, "the stream to start", w.hasStarted) // after its request reached the upstream
	if acked {
		eventually(t, "the acknowledgement", func() bool { return strings.Contains(w.written(), "acknowledged") })
	}
	return h, w, cut
}

// A stream from the upstream process that its request's end cuts off, its headers already sent, is
// recorded with why (#533): client_closed when its MCP client went away, shutdown when the proxy
// shut down. A listen the shutdown ends with its completion result has completed, so it is not cut
// off.
func TestAStdioStreamEndedByItsRequestIsRecordedAsCutOffUnlessItCompleted(t *testing.T) {
	for _, stream := range []struct {
		name string
		// open returns the request, with ctx, of a stream that stays open until its request ends.
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
			return b.modernRequest(ctx, modernBody(`"h"`, "hold", "", ""))
		}, true, false},
		{"a modern listen", func(_ *testing.T, b *bridgeHarness, ctx context.Context) *http.Request {
			return b.modernRequest(ctx, listenBody)
		}, true, true},
	} {
		for _, e := range endings {
			t.Run(stream.name+", "+e.name, func(t *testing.T) {
				ctx, end := e.start()
				defer end()
				_, w, cut := observeStream(t, stream.modern, stream.completes, func(b *bridgeHarness) *http.Request { return stream.open(t, b, ctx) })
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
				b.endSession(t, sid)
			}
		}, false, logging.ClientClosed, true, ""},
		{"a modern request's stream, its answer", true, func(_ *testing.T, b *bridgeHarness) (*http.Request, ender) {
			return b.modernRequest(context.Background(), modernBody(`"h"`, "hold", "", "")), func(t *testing.T, b *bridgeHarness, breakIn func()) {
				breakIn()
				readEvents(t, b.modern(t, "alice", modernBody(`2`, "release", "", "")))
			}
		}, false, logging.ClientClosed, true, ""},
		{"a modern listen, a notification", true, func(_ *testing.T, b *bridgeHarness) (*http.Request, ender) {
			return b.modernRequest(context.Background(), listenBody), func(t *testing.T, b *bridgeHarness, breakIn func()) {
				breakIn()
				readEvents(t, b.modern(t, "alice", modernBody(`1`, "notify", "", "")))
			}
		}, true, logging.ClientClosed, true, ""},
		{"a modern listen, a keep-alive", true, func(_ *testing.T, b *bridgeHarness) (*http.Request, ender) {
			return b.modernRequest(context.Background(), listenBody), func(_ *testing.T, b *bridgeHarness, breakIn func()) {
				breakIn()
				b.clk.Advance(keepAliveInterval)
			}
		}, true, logging.ClientClosed, true, ""},
		{"a modern listen ended with its completion result", true, func(_ *testing.T, b *bridgeHarness) (*http.Request, ender) {
			return b.modernRequest(context.Background(), listenBody), func(_ *testing.T, b *bridgeHarness, _ func()) { b.bridge.Drain() }
		}, true, "", false, `"resultType":"complete"`},
		{"a modern listen whose completion result cannot be written", true, func(_ *testing.T, b *bridgeHarness) (*http.Request, ender) {
			return b.modernRequest(context.Background(), listenBody), func(_ *testing.T, b *bridgeHarness, breakIn func()) {
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
				var endIt ender
				b, w, cut := observeStream(t, tc.modern, tc.acked, func(b *bridgeHarness) *http.Request {
					req, e := tc.open(t, b)
					endIt = e
					return req
				})
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

// An initialize whose request ends before its stream starts is answered by how it ended (#529) and
// is not cut off: nothing of a stream was sent (#533).
func TestAnInitializeEndedByItsRequestBeforeItsStreamStartedIsAnsweredAndNotCutOff(t *testing.T) {
	for _, e := range endings {
		t.Run(e.name, func(t *testing.T) {
			b := newBridge(t, func(c *Config) { c.Command = []string{fakeBin, "-mcp", "-init=hold"} })
			ctx, end := e.start()
			defer end()
			w := httptest.NewRecorder()
			cut := b.observed(t, w, b.request(ctx, http.MethodPost, "alice", "", initialize))
			b.stderrSaid(t, "holding initialize")
			end()
			if got := cut(); got != "" {
				t.Errorf("recorded as cut off %q; want none", got)
			}
			e.answered(t, w)
		})
	}
}

// A stream that ends without its request ending or a write failing is not cut off, however it ends:
// with its answer, with the error its process's exit or its session's end gets, by the upstream
// ending a subscription, or as a GET stream another replaces (#533).
func TestAStdioStreamThatEndsWithoutItsRequestEndingOrAWriteFailingIsNotCutOff(t *testing.T) {
	const hold, exited = `{"jsonrpc":"2.0","id":2,"method":"hold"}`, "upstream process exited"
	// A finisher ends an open stream; nil for one that ends by itself.
	type finisher = func(t *testing.T, b *bridgeHarness)
	for _, tc := range []struct {
		name   string
		modern bool
		// open returns the stream's request, and what ends it once it is open.
		open func(t *testing.T, b *bridgeHarness) (*http.Request, finisher)
		// acked: the stream is open once its acknowledgement is written.
		acked bool
		// written is what the body must hold, so the row ends the way its name says ("" for a GET
		// stream, which writes nothing of its own as it ends).
		written string
	}{
		{"a legacy POST stream, answered", false, func(t *testing.T, b *bridgeHarness) (*http.Request, finisher) {
			return b.request(context.Background(), http.MethodPost, "alice", b.initialize(t, "alice"), `{"jsonrpc":"2.0","id":2,"method":"env"}`), nil
		}, false, `"result":`},
		{"a legacy POST stream, its session ended", false, func(t *testing.T, b *bridgeHarness) (*http.Request, finisher) {
			sid := b.initialize(t, "alice")
			return b.request(context.Background(), http.MethodPost, "alice", sid, hold), func(t *testing.T, b *bridgeHarness) {
				b.stderrSaid(t, "holding")
				b.endSession(t, sid)
			}
		}, false, exited},
		{"a legacy GET stream, its session ended", false, func(t *testing.T, b *bridgeHarness) (*http.Request, finisher) {
			sid := b.initialize(t, "alice")
			return b.request(context.Background(), http.MethodGet, "alice", sid, ""), func(t *testing.T, b *bridgeHarness) { b.endSession(t, sid) }
		}, false, ""},
		{"a legacy GET stream, replaced by a newer one", false, func(t *testing.T, b *bridgeHarness) (*http.Request, finisher) {
			sid := b.initialize(t, "alice")
			return b.request(context.Background(), http.MethodGet, "alice", sid, ""), func(t *testing.T, b *bridgeHarness) { b.listen(t, context.Background(), sid) }
		}, false, ""},
		{"a modern request's stream, answered", true, func(_ *testing.T, b *bridgeHarness) (*http.Request, finisher) {
			return b.modernRequest(context.Background(), modernBody(`1`, "env", "", "")), nil
		}, false, `"result":`},
		{"a modern request's stream, its process exited", true, func(_ *testing.T, b *bridgeHarness) (*http.Request, finisher) {
			return b.modernRequest(context.Background(), modernBody(`1`, "crash", "", "")), nil
		}, false, exited},
		{"a modern listen the upstream ended", true, func(_ *testing.T, b *bridgeHarness) (*http.Request, finisher) {
			return b.modernRequest(context.Background(), listenBody), func(t *testing.T, b *bridgeHarness) {
				readEvents(t, b.modern(t, "alice", modernBody(`1`, "teardown", "", "")))
			}
		}, true, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var finish finisher
			b, w, cut := observeStream(t, tc.modern, tc.acked, func(b *bridgeHarness) *http.Request {
				req, f := tc.open(t, b)
				finish = f
				return req
			})
			if finish != nil {
				finish(t, b)
			}
			if got := cut(); got != "" {
				t.Errorf("recorded as cut off %q; want none (body %q)", got, w.written())
			}
			if !strings.Contains(w.written(), tc.written) {
				t.Errorf("body %q; want it to hold %s", w.written(), tc.written)
			}
		})
	}
}
