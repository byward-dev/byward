package logging

import (
	"context"
	"net/http"

	"github.com/byward-dev/byward/internal/shutdown"
)

// CutOff is why a response was cut off after its headers were sent (#533). Its request records the
// status it sent, with the cause as error_type: on the request line, on
// byward_http_request_duration_seconds and on the server span. It is empty for a response that was
// not cut off.
type CutOff string

const (
	// ClientClosed is a response whose MCP client went away.
	ClientClosed CutOff = "client_closed"
	// ShutDown is a response the proxy's shutdown ended.
	ShutDown CutOff = "shutdown"
	// UpstreamAborted is a response whose upstream broke off its body (#387).
	UpstreamAborted CutOff = "upstream_aborted"
)

// ending holds a request's CutOff, set once, so every wrapper that records the request records the
// same cause, even when the request ends between their records.
type ending struct{ cut CutOff }

type endingKey struct{}

// endedBy names what ended ctx, a request's context: the proxy's shutdown, else the MCP client going
// away; "" while it is live. A request's context has no deadline, so any other end is its client's.
func endedBy(ctx context.Context) CutOff {
	switch {
	case shutdown.ShuttingDown(ctx):
		return ShutDown
	case ctx.Err() != nil:
		return ClientClosed
	}
	return ""
}

// StreamEnded records that the response to the request of ctx, its headers already sent, is cut off
// because the request ended: by the proxy's shutdown or its MCP client going away. A handler that
// ends such a stream by returning calls it, so the stream is recorded as one that was cut off. A
// request still live, or one that no wrapper records, is left as it is.
func StreamEnded(ctx context.Context) {
	e, _ := ctx.Value(endingKey{}).(*ending)
	if e != nil && e.cut == "" {
		e.cut = endedBy(ctx)
	}
}

// Observe serves r with next through a StatusRecorder over w, then calls record with the status
// sent and the CutOff (empty unless the response was cut off). A handler that aborts the response
// with http.ErrAbortHandler, as ReverseProxy does when the upstream's body fails mid-copy, is
// recorded too: as cut off by the proxy's shutdown, by its MCP client going away, or else by its
// upstream. The panic then goes on, so the server still tears the connection down. The request
// line, the request metric and the server span all record through it.
func Observe(w http.ResponseWriter, r *http.Request, next http.Handler, record func(status int, cut CutOff)) {
	e, _ := r.Context().Value(endingKey{}).(*ending)
	if e == nil {
		e = &ending{}
		r = r.WithContext(context.WithValue(r.Context(), endingKey{}, e))
	}
	rec := NewStatusRecorder(w)
	returned := false
	defer func() {
		if returned {
			return
		}
		p := recover()
		switch {
		case p == nil: // runtime.Goexit: not a panic, and nothing was answered
			return
		case p != http.ErrAbortHandler: //nolint:errorlint // sentinel compared as net/http does
			panic(p)
		}
		if e.cut == "" {
			e.cut = endedBy(r.Context())
		}
		if e.cut == "" { // the request is live, so its upstream broke off
			e.cut = UpstreamAborted
		}
		record(rec.Status(), e.cut)
		panic(p)
	}()
	next.ServeHTTP(rec, r)
	returned = true
	record(rec.Status(), e.cut)
}
