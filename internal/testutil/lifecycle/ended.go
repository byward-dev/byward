package lifecycle

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/byward-dev/byward/internal/logging"
	"github.com/byward-dev/byward/internal/shutdown"
)

// An Ended is an ending a handler sees through its request context: its MCP client went away, or
// the proxy is shutting down (the server ends each request in flight through shutdown.WithCancel).
// The first records 499, never sent; the second answers 503 on a connection that closes, so the
// MCP client, still there, can retry (#527, #529).
type Ended struct {
	Ending Ending // ClientGone or Shutdown
	Status int    // what shutdown.AnswerIfEnded answers
	Body   string
	Closes bool // the answer closes its connection
	// Cut is what a stream already started records when its request ends this way (#533).
	Cut logging.CutOff
}

// ContextEndings are the two endings a handler sees through its request context.
var ContextEndings = []Ended{
	{Ending: ClientGone, Status: 499, Cut: logging.ClientClosed},
	{Ending: Shutdown, Status: http.StatusServiceUnavailable, Body: "the proxy is shutting down\n", Closes: true, Cut: logging.ShutDown},
}

// Start is a request context under parent, and the call that ends it this way.
func (e Ended) Start(parent context.Context) (context.Context, func()) {
	if e.Ending == Shutdown {
		return shutdown.WithCancel(parent)
	}
	return context.WithCancel(parent)
}

// Answered fails t unless w is the answer to a request that ended this way.
func (e Ended) Answered(t testing.TB, w *httptest.ResponseRecorder) {
	t.Helper()
	if w.Code != e.Status || w.Body.String() != e.Body || (w.Header().Get("Connection") == "close") != e.Closes {
		t.Fatalf("answer %d %q, Connection %q; want %d %q, closing %v", w.Code, w.Body, w.Header().Get("Connection"), e.Status, e.Body, e.Closes)
	}
}
