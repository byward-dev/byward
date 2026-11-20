// Package shutdown is how the proxy stopping reaches the requests still in flight (CONTEXT.md:
// Shutdown). internal/server ends each request through WithCancel; a handler whose request ended
// answers it with AnswerIfEnded, which tells the proxy shutting down from the MCP client going away.
package shutdown

import (
	"context"
	"errors"
	"net/http"
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
