package shutdown

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// A request whose context ended is answered by how it ended, and the caller then logs nothing as a
// failure: the proxy shutting down (cause http.ErrServerClosed, however wrapped) leaves the MCP
// client there, which gets 503 on a connection that closes; the client going away (the plain
// context.Canceled) records 499, never sent. A request still live, or one ended for another cause
// such as a deadline, is left to the caller (#527, #529).
func TestAnEndedRequestIsAnsweredOnlyWhenTheProxyShutsDownOrItsMCPClientWentAway(t *testing.T) {
	live := context.Background()
	gone, cancel := context.WithCancel(context.Background())
	cancel()
	stopped, shutDown := WithCancel(context.Background())
	shutDown()
	wrapped, stopWrapped := context.WithCancelCause(context.Background())
	stopWrapped(fmt.Errorf("serve: %w", http.ErrServerClosed))
	late, stopLate := context.WithTimeout(context.Background(), 0)
	defer stopLate()
	other, stopOther := context.WithCancelCause(context.Background())
	stopOther(errors.New("some other cause"))
	for _, c := range []struct {
		name         string
		ctx          context.Context
		answered     bool
		shuttingDown bool
		status       int
		body         string
		connection   string
	}{
		{"still live", live, false, false, http.StatusOK, "", ""},
		{"the MCP client went away", gone, true, false, 499, "", ""},
		{"the proxy shuts down", stopped, true, true, http.StatusServiceUnavailable, "the proxy is shutting down\n", "close"},
		{"the proxy shuts down, its cause wrapped", wrapped, true, true, http.StatusServiceUnavailable, "the proxy is shutting down\n", "close"},
		{"its deadline passed", late, false, false, http.StatusOK, "", ""},
		{"ended for another cause", other, false, false, http.StatusOK, "", ""},
	} {
		t.Run(c.name, func(t *testing.T) {
			if got := ShuttingDown(c.ctx); got != c.shuttingDown {
				t.Fatalf("ShuttingDown = %v; want %v", got, c.shuttingDown)
			}
			w := httptest.NewRecorder()
			got := AnswerIfEnded(w, httptest.NewRequestWithContext(c.ctx, http.MethodPost, "/mcp", nil))
			if got != c.answered || w.Code != c.status || w.Body.String() != c.body || w.Header().Get("Connection") != c.connection {
				t.Fatalf("AnswerIfEnded = %v, answer %d %q, Connection %q; want %v, %d %q, %q",
					got, w.Code, w.Body, w.Header().Get("Connection"), c.answered, c.status, c.body, c.connection)
			}
		})
	}
}

// deadlineWriter records the read deadlines set on it.
type deadlineWriter struct {
	http.ResponseWriter
	set chan time.Time
}

func (w deadlineWriter) SetReadDeadline(d time.Time) error { w.set <- d; return nil }

// #697: CutsBodyReads sets a read deadline already past when, and only when, the proxy shuts down
// while the handler runs: not for an MCP client that went away (its read fails with its
// connection), not while the request is live, and never once the handler has returned.
func TestCutsBodyReadsSetsAPastReadDeadlineOnlyAtAShutdownWhileTheHandlerRuns(t *testing.T) {
	for _, c := range []struct {
		name  string
		start func(context.Context) (context.Context, func())
		cut   bool
	}{
		{"the proxy shuts down", WithCancel, true},
		{"the MCP client went away", func(p context.Context) (context.Context, func()) { return context.WithCancel(p) }, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			ctx, end := c.start(context.Background())
			defer end()
			w := deadlineWriter{httptest.NewRecorder(), make(chan time.Time, 1)}
			ended, returned := make(chan struct{}), make(chan struct{})
			go func() {
				defer close(returned)
				CutsBodyReads(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { <-ended })).
					ServeHTTP(w, httptest.NewRequestWithContext(ctx, http.MethodPost, "/mcp", nil))
			}()
			end()
			select {
			case d := <-w.set:
				if !c.cut || d.IsZero() || d.After(time.Now()) {
					t.Fatalf("read deadline %v set; want %s", d, map[bool]string{true: "one already past", false: "none"}[c.cut])
				}
			case <-time.After(map[bool]time.Duration{true: 5 * time.Second, false: 100 * time.Millisecond}[c.cut]):
				if c.cut { // the AfterFunc runs at once; a deadline not set by then never will be
					t.Fatal("no read deadline set within 5s of the shutdown")
				}
			}
			close(ended)
			<-returned
		})
	}
	t.Run("the proxy shuts down after the handler returned", func(t *testing.T) {
		ctx, shutDown := WithCancel(context.Background())
		w := deadlineWriter{httptest.NewRecorder(), make(chan time.Time, 1)}
		CutsBodyReads(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})).
			ServeHTTP(w, httptest.NewRequestWithContext(ctx, http.MethodPost, "/mcp", nil))
		shutDown()
		select {
		case d := <-w.set:
			t.Fatalf("read deadline %v set after the handler returned; want none", d)
		case <-time.After(100 * time.Millisecond):
		}
	})
}

// slowCut is a writer whose read deadline takes until release to set, as a cut still running.
type slowCut struct {
	http.ResponseWriter
	entered, release chan struct{}
}

func (w slowCut) SetReadDeadline(time.Time) error { close(w.entered); <-w.release; return nil }

// #697: a handler that returns while the cut is still setting the read deadline does not return
// before it: the server then reuses its writer, and over HTTP/2 a late deadline would panic.
func TestCutsBodyReadsDoesNotReturnWhileACutIsRunning(t *testing.T) {
	ctx, shutDown := WithCancel(context.Background())
	w := slowCut{httptest.NewRecorder(), make(chan struct{}), make(chan struct{})}
	returned := make(chan struct{})
	go func() {
		defer close(returned)
		CutsBodyReads(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
			<-r.Context().Done()
			<-w.entered // the cut has started; the handler returns now
		})).ServeHTTP(w, httptest.NewRequestWithContext(ctx, http.MethodPost, "/mcp", nil))
	}()
	shutDown()
	select {
	case <-returned:
		t.Fatal("it returned while the cut was still running")
	case <-time.After(100 * time.Millisecond):
	}
	close(w.release)
	select {
	case <-returned:
	case <-time.After(5 * time.Second):
		t.Fatal("it did not return within 5s of the cut ending")
	}
}
