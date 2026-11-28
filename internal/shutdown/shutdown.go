// Package shutdown is how the proxy stopping reaches the requests still in flight (CONTEXT.md:
// Shutdown). internal/server ends each request through WithCancel; a handler whose request ended
// answers it with AnswerIfEnded, which tells the proxy shutting down from the MCP client going away.
package shutdown

import (
	"context"
	"errors"
	"net/http"
	"time"
)

// statusClientClosedRequest is the status a request records when its MCP client went away before it
// was answered: nginx's "client closed request" convention (499). It is never sent, since the client
// is gone, so a client that gave up is not counted as a failure of the proxy or its upstream (#527).
const statusClientClosedRequest = 499

// WithCancel returns a copy of parent for the server's requests, and the func that ends them as the
// proxy shutting down: with http.ErrServerClosed as the cause, where a client going away leaves the
// plain context.Canceled.
func WithCancel(parent context.Context) (ctx context.Context, shutDown func()) {
	ctx, cancel := context.WithCancelCause(parent)
	return ctx, func() { cancel(http.ErrServerClosed) }
}

// ShuttingDown reports whether ctx, a request's context, was ended by the proxy shutting down
// (WithCancel).
func ShuttingDown(ctx context.Context) bool {
	return errors.Is(context.Cause(ctx), http.ErrServerClosed)
}

// ClientWentAway reports whether ctx, a request's context, was ended by its MCP client going away:
// cancelled with no cause of the proxy's. Any other end, a deadline say, is not its client's.
func ClientWentAway(ctx context.Context) bool {
	return errors.Is(context.Cause(ctx), context.Canceled)
}

// AnswerIfEnded answers r if its context was ended by the proxy shutting down or by its MCP client
// going away, and reports whether it did; the caller then logs nothing as a failure, whatever error
// the ending gave it (#527). A request ended by shutdown still has its client: it gets 503 "the
// proxy is shutting down" on a connection that closes, so it can retry. A client that went away
// leaves the plain context.Canceled, and the request records 499. Any other end, a deadline say, is
// left to the caller, as is a request still live. Call it only before anything of the response is
// written.
func AnswerIfEnded(w http.ResponseWriter, r *http.Request) bool {
	ctx := r.Context()
	switch { // a live request has no cause, so neither case holds for it
	case ShuttingDown(ctx):
		w.Header().Set("Connection", "close")
		http.Error(w, "the proxy is shutting down", http.StatusServiceUnavailable)
		return true
	case ClientWentAway(ctx):
		w.WriteHeader(statusClientClosedRequest)
		return true
	}
	return false
}

// CutsBodyReads wraps a server's handler so that the proxy shutting down also ends a request body
// still being read. Ending the context does not, as a server's body read waits on its connection
// alone. Then the read fails, and the handler answers 503 with AnswerIfEnded while its MCP client is
// still there, instead of after the whole shutdown grace (#697). A client going away needs no
// cut, as the read fails with its connection.
//
// It sets the request's read deadline to now from the context's AfterFunc goroutine, while the
// handler may be blocked reading. That is safe in Go 1.27.4:
//   - HTTP/1.1: the deadline is the connection's (net/http/server.go:501-503, crypto/tls/conn.go:149-151),
//     and "Multiple goroutines may invoke methods on a Conn simultaneously", a deadline reaching "any
//     currently-blocked Read call" (net/net.go:123, 170-171).
//   - HTTP/2: a deadline already past closes the stream's body pipe at once (internal/http2/server.go:2716-2722,
//     1847-1853), a pipe guarded by its mutex (internal/http2/pipe.go:122-134).
//
// A body already read is not changed. Over HTTP/2 its pipe has already closed with io.EOF, and a
// second close does nothing (pipe.go:132-134). Over HTTP/1.1 the server reads the connection in the
// background once the body ends (server.go:2146-2150). The deadline fails that read, which only
// cancels the request's context again (server.go:809-817); a context keeps its first cause, so
// the request still ends as the proxy shutting down.
//
// The handler does not return while a cut is still running: once it has, the server reuses w, and
// over HTTP/2 a late SetReadDeadline would dereference the writer's state, which handlerDone sets to
// nil (internal/http2/server.go:2946-2951, 2717), and panic in a goroutine nothing recovers.
//
// It must wrap the server's own handler, outermost, so w is the server's writer. It acts only on a
// request that serve() ends through WithCancel: the public listener's. The internal listener's
// requests are never ended that way, and read no body.
func CutsBodyReads(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		cut := make(chan struct{})
		stop := context.AfterFunc(ctx, func() {
			defer close(cut)
			if ShuttingDown(ctx) {
				_ = http.NewResponseController(w).SetReadDeadline(time.Now())
			}
		})
		defer func() {
			if !stop() { // the cut has started: w is its until it is done
				<-cut
			}
		}()
		next.ServeHTTP(w, r)
	})
}
