//go:build linux || darwin

package stdio

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/byward-dev/byward/internal/logging"
	"github.com/byward-dev/byward/internal/shutdown"
)

// ending is one way a request can end before it is answered: its MCP client went away, or the proxy
// is shutting down (the server ends each request in flight through shutdown.WithCancel). The first
// records 499, never sent; the second answers 503 on a connection that closes, so the MCP client,
// still there, can retry (#527, #529).
type ending struct {
	name     string
	start    func() (ctx context.Context, end func())
	status   int
	body     string
	shutdown bool // the proxy ended the request: its connection closes, a listen gets its completion
	// cut is what a stream already started records when the request ends this way (#533).
	cut logging.CutOff
}

var endings = []ending{
	{"the MCP client went away", func() (context.Context, func()) {
		ctx, cancel := context.WithCancel(context.Background())
		return ctx, cancel
	}, 499, "", false, logging.ClientClosed},
	{"the proxy shuts down", func() (context.Context, func()) {
		return shutdown.WithCancel(context.Background())
	}, http.StatusServiceUnavailable, "the proxy is shutting down\n", true, logging.ShutDown},
}

// answered fails t unless w is the answer to a request that ended this way.
func (e ending) answered(t *testing.T, w *httptest.ResponseRecorder) {
	t.Helper()
	if w.Code != e.status || w.Body.String() != e.body || (w.Header().Get("Connection") == "close") != e.shutdown {
		t.Fatalf("answer %d %q, Connection %q; want %d %q, closing %v", w.Code, w.Body, w.Header().Get("Connection"), e.status, e.body, e.shutdown)
	}
}

// noFailureLogged fails t if the bridge or its processes logged anything at WARN or above.
func (b *bridgeHarness) noFailureLogged(t *testing.T) {
	t.Helper()
	if got := b.log.warnings(); len(got) != 0 {
		t.Fatalf("logged %v; want nothing at WARN or above for a request that ended", got)
	}
}

// stderrSaid waits until the upstream process has written line to its stderr.
func (b *bridgeHarness) stderrSaid(t *testing.T, line string) {
	t.Helper()
	eventually(t, "the upstream process to write "+line, func() bool {
		for _, rec := range b.log.with("upstream stderr") {
			if rec.attrs["line"] == line {
				return true
			}
		}
		return false
	})
}

const modernNotification = `{"jsonrpc":"2.0","method":"notifications/progress","params":{"_meta":{` +
	`"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}}}}`

// A request that ends before the upstream process answers it, on every path that sends to the
// process or starts it, is not a failure of the process: nothing is logged as one, and the request
// records 499 when its MCP client went away, or answers 503 when the proxy is shutting down (#529).
// On main the bridge logged "relaying to the upstream process failed" or "cannot start the upstream
// process" with context canceled, and answered 502. A running process is leased even to a request
// that has ended, so each row reaches the path its name says, every run.
func TestARequestThatEndsBeforeTheUpstreamProcessAnswersIsAnsweredByHowItEndedAndNeverLoggedAsAFailure(t *testing.T) {
	for _, path := range []struct {
		name string
		// send starts the bridge and sends the request that ends, with ctx already ended.
		send func(t *testing.T, ctx context.Context) (*bridgeHarness, *httptest.ResponseRecorder)
	}{
		{"legacy initialize, its process not yet started", func(t *testing.T, ctx context.Context) (*bridgeHarness, *httptest.ResponseRecorder) {
			b := newBridge(t, nil)
			return b, b.serve(ctx, http.MethodPost, "alice", "", initialize)
		}},
		{"legacy notification to a running session", func(t *testing.T, ctx context.Context) (*bridgeHarness, *httptest.ResponseRecorder) {
			b := newBridge(t, nil)
			sid := b.initialize(t, "alice")
			return b, b.serve(ctx, http.MethodPost, "alice", sid, `{"jsonrpc":"2.0","method":"notifications/initialized"}`)
		}},
		{"legacy request to a running session", func(t *testing.T, ctx context.Context) (*bridgeHarness, *httptest.ResponseRecorder) {
			b := newBridge(t, nil)
			sid := b.initialize(t, "alice")
			return b, b.serve(ctx, http.MethodPost, "alice", sid, `{"jsonrpc":"2.0","id":2,"method":"tools/list"}`)
		}},
		{"legacy GET stream of a running session", func(t *testing.T, ctx context.Context) (*bridgeHarness, *httptest.ResponseRecorder) {
			b := newBridge(t, nil)
			sid := b.initialize(t, "alice")
			return b, b.serve(ctx, http.MethodGet, "alice", sid, "")
		}},
		{"modern request, its process not yet started", func(t *testing.T, ctx context.Context) (*bridgeHarness, *httptest.ResponseRecorder) {
			b := newModernBridge(t, nil)
			body := modernBody(`1`, "tools/list", "", "")
			return b, b.serve(ctx, http.MethodPost, "alice", "", body, modernHeaders(body)...)
		}},
		{"modern request to a running process", func(t *testing.T, ctx context.Context) (*bridgeHarness, *httptest.ResponseRecorder) {
			b := newModernBridge(t, nil)
			if res := b.modern(t, "alice", modernBody(`1`, "tools/list", "", "")); res.StatusCode != http.StatusOK {
				t.Fatalf("first request: status %d", res.StatusCode)
			}
			body := modernBody(`2`, "tools/list", "", "")
			return b, b.serve(ctx, http.MethodPost, "alice", "", body, modernHeaders(body)...)
		}},
		{"modern notification to a running process", func(t *testing.T, ctx context.Context) (*bridgeHarness, *httptest.ResponseRecorder) {
			b := newModernBridge(t, nil)
			if res := b.modern(t, "alice", modernBody(`1`, "tools/list", "", "")); res.StatusCode != http.StatusOK {
				t.Fatalf("first request: status %d", res.StatusCode)
			}
			return b, b.serve(ctx, http.MethodPost, "alice", "", modernNotification, modernHeaders(modernNotification)...)
		}},
	} {
		for _, e := range endings {
			t.Run(path.name+", "+e.name, func(t *testing.T) {
				ctx, end := e.start()
				end()
				b, w := path.send(t, ctx)
				e.answered(t, w)
				b.noFailureLogged(t)
			})
		}
	}
}

// An initialize whose request ends while its process holds it, unanswered, or while the process is
// not reading it, records how it ended instead of the 200 or 502 it got on main, and logs no failure
// (#529; main logged "initialize failed: no MCP session"). Its process is stopped, as for any
// initialize that does not succeed.
func TestAnInitializeThatEndsBeforeItIsAnsweredIsAnsweredByHowItEndedAndItsProcessStopped(t *testing.T) {
	for _, s := range []struct {
		name, init, body, said string
	}{
		{"while its answer is awaited", "-init=hold", initialize, "holding initialize"},
		// Larger than any pipe buffer, so the Send waits on a process that never reads.
		{"while it is being sent", "-init=block", strings.Replace(initialize, `"params":{`, `"params":{"pad":"`+strings.Repeat("a", 4<<20)+`",`, 1), "blocking"},
	} {
		for _, e := range endings {
			t.Run(s.name+", "+e.name, func(t *testing.T) {
				b := newBridge(t, func(c *Config) { c.Command = []string{fakeBin, "-mcp", s.init} })
				ctx, end := e.start()
				answered := make(chan *httptest.ResponseRecorder, 1)
				go func() { answered <- b.serve(ctx, http.MethodPost, "alice", "", s.body) }()
				b.stderrSaid(t, s.said)
				end()
				e.answered(t, <-answered)
				eventually(t, "the unusable process to be stopped", func() bool { return len(b.log.with("stopping upstream process")) == 1 })
				b.noFailureLogged(t)
			})
		}
	}
}

// An initialize whose answer cannot be written while its request is still live is a failure, and is
// logged as one, at WARN: only a request that ended is spared the warning.
func TestAnInitializeWhoseAnswerCannotBeWrittenWhileItsRequestIsLiveIsLoggedAsAFailure(t *testing.T) {
	b := newBridge(t, nil)
	w := &brokenWriter{header: http.Header{}, broken: "write"}
	b.bridge.ServeHTTP(w, b.request(context.Background(), http.MethodPost, "alice", "", initialize))
	var failures []record // at WARN or above; the answer it could not write is logged as dropped too
	for _, rec := range b.log.warnings() {
		if rec.msg == "initialize failed: no MCP session" {
			failures = append(failures, rec)
		}
	}
	if len(failures) != 1 || failures[0].attrs["reason"] != "client_disconnected" {
		t.Fatalf("logged at WARN or above %v; want one initialize failure with reason client_disconnected", b.log.warnings())
	}
}

// A stream that has started keeps the status it sent when its request ends: nothing more is written
// to it, not even when the proxy shuts down.
func TestAStartedStreamKeepsItsStatusAndGetsNothingMoreWhenItsRequestEnds(t *testing.T) {
	for _, e := range endings {
		t.Run(e.name, func(t *testing.T) {
			b := newBridge(t, nil)
			sid := b.initialize(t, "alice")
			ctx, end := e.start()
			answered := make(chan *httptest.ResponseRecorder, 1)
			go func() {
				answered <- b.serve(ctx, http.MethodPost, "alice", sid, `{"jsonrpc":"2.0","id":2,"method":"hold"}`)
			}()
			b.stderrSaid(t, "holding")
			end()
			w := <-answered
			if w.Code != http.StatusOK || w.Header().Get("Content-Type") != "text/event-stream" || w.Body.Len() != 0 {
				t.Fatalf("answer %d %q, Content-Type %q; want the stream's 200 and nothing written after it", w.Code, w.Body, w.Header().Get("Content-Type"))
			}
			b.noFailureLogged(t)
		})
	}
}

// A GET whose request ended never takes over its MCP session's live GET stream: the next message
// outside a request still reaches the live one.
func TestAnEndedGETNeverReplacesItsMCPSessionsLiveGETStream(t *testing.T) {
	for _, e := range endings {
		t.Run(e.name, func(t *testing.T) {
			b := newBridge(t, nil)
			sid := b.initialize(t, "alice")
			live := b.listen(t, context.Background(), sid)
			ctx, end := e.start()
			end()
			e.answered(t, b.serve(ctx, http.MethodGet, "alice", sid, ""))
			readEvents(t, b.post(t, "alice", sid, `{"jsonrpc":"2.0","id":1,"method":"announce"}`))
			if got, ok := live.next(); !ok || got != `{"jsonrpc":"2.0","method":"notifications/message","params":{"level":"info"}}` {
				t.Fatalf("the live GET stream got %q (open %v); want the announcement", got, ok)
			}
		})
	}
}

// A listen whose request the proxy's shutdown ends, before Drain reaches it, is still ended by the
// server's choice: it gets its completion result (2026-07-28 subscriptions) and is cancelled
// upstream. A listen whose MCP client went away gets no completion, only the upstream cancellation
// (#529).
func TestAListenEndedByTheProxyShuttingDownGetsItsCompletionAndOneWhoseMCPClientWentAwayDoesNot(t *testing.T) {
	for _, e := range endings {
		t.Run(e.name, func(t *testing.T) {
			b := newModernBridge(t, nil)
			ctx, end := e.start()
			body := modernBody(`"L"`, "subscriptions/listen", "", `"notifications":{"toolsListChanged":true}`)
			w := &brokenWriter{header: http.Header{}} // read while it is written
			done := make(chan struct{})
			go func() {
				defer close(done)
				b.bridge.ServeHTTP(w, b.request(ctx, http.MethodPost, "alice", "", body, modernHeaders(body)...))
			}()
			eventually(t, "the acknowledgement", func() bool { return strings.Contains(w.written(), "acknowledged") })
			end()
			<-done
			got := eventsOf(t, &http.Response{Header: w.header, Body: io.NopCloser(strings.NewReader(w.written()))}).all()
			want := 1
			if e.shutdown {
				want = 2
			}
			if len(got) != want || !strings.Contains(got[0], "notifications/subscriptions/acknowledged") ||
				(e.shutdown && !sameJSON(t, []byte(got[1]), `{"jsonrpc":"2.0","id":"L","result":{"resultType":"complete","_meta":{"io.modelcontextprotocol/subscriptionId":"L"}}}`)) {
				t.Fatalf("listen events %q; want its acknowledgement, then its completion only if the proxy ended it (%v)", got, e.shutdown)
			}
			eventually(t, "the upstream to see the listen cancelled", func() bool { return len(b.upstreamCancellations(t)) == 1 })
			b.noFailureLogged(t)
		})
	}
}

// An initialize whose request ends as a write to its stream fails logs no initialize failure: the
// write failed because its request ended (its MCP client went away, or the proxy is shutting down),
// not because of the upstream process (#549). Its
// process is stopped, as for any initialize that does not succeed. The write that fails is the
// stream's first event: a notification the upstream sends before it holds its answer, or the answer
// itself, written after the drain finds nothing before it. Either way the one warning is that event,
// dropped.
func TestAnInitializeWhoseWriteFailsAsItsRequestEndsLogsNoInitializeFailureAndItsProcessStopped(t *testing.T) {
	for _, s := range []struct{ name, init, first, want string }{
		{"a notification first", "-init=lognhold", "the notification", `"method":"notifications/message"`},
		{"its result", "", "the result", `"result":`},
	} {
		for _, e := range endings {
			t.Run(s.name+", "+e.name, func(t *testing.T) {
				b := newBridge(t, func(c *Config) {
					if s.init != "" {
						c.Command = append(c.Command, s.init)
					}
				})
				w := newGatedWriter(2) // the stream's start, then its first event, whose write fails
				w.fail = errBrokenPipe
				ctx, end := e.start()
				done := make(chan struct{})
				go func() {
					defer close(done)
					b.bridge.ServeHTTP(w, b.request(ctx, http.MethodPost, "alice", "", initialize))
				}()
				select {
				case <-w.blocked:
				case <-time.After(guard):
					t.Fatalf("%s was never written", s.first)
				}
				end()
				w.open()
				<-done
				if got := w.written(); !strings.Contains(got, s.want) {
					t.Fatalf("the failed write was %q; want %s", got, s.first)
				}
				var warns []string
				for _, rec := range b.log.warnings() {
					warns = append(warns, rec.msg)
				}
				if want := []string{"upstream notification dropped"}; !slices.Equal(warns, want) {
					t.Fatalf("logged %q at WARN or above; want only %q: no initialize failure for a request that ended", warns, want)
				}
				if got := b.stops("initialize_failed"); got != 1 {
					t.Fatalf("%d initialize_failed stops; want its process stopped once", got)
				}
			})
		}
	}
}

// A request that ends while its MCP session's process is stopping is answered by how it ended, not
// 404, which tells its MCP client to start a new session (#552). A stubborn upstream keeps running
// after DELETE until the kill timers, which the fake clock never fires: the process is stopping for
// the whole test.
func TestARequestThatEndsWhileItsMCPSessionsProcessIsStoppingIsAnsweredByHowItEndedAndNeverLoggedAsAFailure(t *testing.T) {
	for _, m := range []struct{ name, method, body string }{
		{"notification", http.MethodPost, `{"jsonrpc":"2.0","method":"notifications/initialized"}`},
		{"request", http.MethodPost, `{"jsonrpc":"2.0","id":2,"method":"echo","params":{}}`},
		{"GET stream", http.MethodGet, ""},
	} {
		for _, e := range endings {
			t.Run(m.name+", "+e.name, func(t *testing.T) {
				b := newBridge(t, func(c *Config) { c.Command = []string{fakeBin, "-mcp", "-stubborn"} })
				sid := b.initialize(t, "alice")
				if res := b.do(t, context.Background(), http.MethodDelete, "alice", sid, ""); res.StatusCode != http.StatusNoContent {
					t.Fatalf("DELETE: status %d", res.StatusCode)
				}
				ctx, end := e.start()
				end()
				e.answered(t, b.serve(ctx, m.method, "alice", sid, m.body))
				b.noFailureLogged(t)
				if b.m.Len() != 1 {
					t.Fatalf("Len = %d: the test needs the process still stopping", b.m.Len())
				}
			})
		}
	}
}

// A send that failed is answered by how its request ended, if it ended, with nothing logged, even
// when its process has exited or is stopping: the process stopping as the request ended is not why
// it ended (#552). Only a request still live is answered by why the send failed: 404 if its process
// exited, so its MCP client starts a new session, and 502 with a warning for any other failure.
func TestAFailedSendIsAnsweredByHowItsRequestEndedBeforeWhyItFailed(t *testing.T) {
	for _, e := range endings {
		t.Run(e.name, func(t *testing.T) {
			log := &recorder{mu: &sync.Mutex{}, recs: &[]record{}}
			s := &session{log: slog.New(log)}
			ctx, end := e.start()
			end()
			w := httptest.NewRecorder()
			s.sendFailed(w, httptest.NewRequestWithContext(ctx, http.MethodPost, "/", nil), ErrExited)
			e.answered(t, w)
			if got := log.warnings(); len(got) != 0 {
				t.Fatalf("logged %v; want nothing at WARN or above for a request that ended", got)
			}
		})
	}
	for _, live := range []struct {
		name   string
		err    error
		status int
		body   string
		warns  []string
	}{
		// Its MCP client starts a new session.
		{"a live request whose process exited", ErrExited, http.StatusNotFound, "session not found\n", nil},
		// The process is still there: a failure of it, logged, and never a 404.
		{"a live request whose send failed otherwise", errors.New("write |1: broken pipe"), http.StatusBadGateway,
			"upstream unavailable\n", []string{"relaying to the upstream process failed"}},
	} {
		t.Run(live.name, func(t *testing.T) {
			log := &recorder{mu: &sync.Mutex{}, recs: &[]record{}}
			s := &session{log: slog.New(log)}
			w := httptest.NewRecorder()
			s.sendFailed(w, httptest.NewRequest(http.MethodPost, "/", nil), live.err)
			var warns []string
			for _, rec := range log.warnings() {
				warns = append(warns, rec.msg)
			}
			if w.Code != live.status || w.Body.String() != live.body || !slices.Equal(warns, live.warns) {
				t.Fatalf("answer %d %q, logged %q; want %d %q and %q", w.Code, w.Body, warns, live.status, live.body, live.warns)
			}
			for _, rec := range log.warnings() { // the failure is logged with its cause
				if got := fmt.Sprint(rec.attrs["error"]); got != live.err.Error() {
					t.Fatalf("logged error %q, want the send's, %q", got, live.err)
				}
			}
		})
	}
}

// An ended request to another user's MCP session is still that: 404 and the "session of another
// user" warning, never answered as if it were its own session's request that ended (#552 keeps the
// user check first).
func TestAnEndedRequestToAnotherUsersMCPSessionIs404AndWarned(t *testing.T) {
	for _, e := range endings {
		t.Run(e.name, func(t *testing.T) {
			b := newBridge(t, nil)
			sid := b.initialize(t, "alice")
			ctx, end := e.start()
			end()
			w := b.serve(ctx, http.MethodPost, "bob", sid, `{"jsonrpc":"2.0","method":"notifications/initialized"}`)
			if w.Code != http.StatusNotFound || w.Body.String() != "session not found\n" {
				t.Fatalf("answer %d %q; want 404 %q", w.Code, w.Body, "session not found\n")
			}
			var warned []record
			for _, rec := range b.log.warnings() {
				if rec.msg == "session of another user" {
					warned = append(warned, rec)
				}
			}
			if len(warned) != 1 || warned[0].attrs["reason"] != "session_user_mismatch" {
				t.Fatalf("logged at WARN or above %v; want the mismatch warned once, reason session_user_mismatch", b.log.warnings())
			}
		})
	}
}
