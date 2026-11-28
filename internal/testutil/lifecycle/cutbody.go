package lifecycle

import (
	"errors"
	"io"
	"os"
)

// A CutBody is a request body in flight: its sender has written the first byte and holds the
// rest, so a handler reading it is in the body-in-flight state. Pass it as the request's body,
// wait for Started, then end the request, and Finish, Cut or Stop the body.
type CutBody struct {
	*io.PipeReader
	w       *io.PipeWriter
	rest    string
	started chan struct{}
}

// NewCutBody starts sending body, up to its first byte.
func NewCutBody(body string) *CutBody {
	pr, pw := io.Pipe()
	b := &CutBody{PipeReader: pr, w: pw, rest: body[1:], started: make(chan struct{})}
	go func() {
		defer close(b.started)
		_, _ = io.WriteString(pw, body[:1]) // returns once the handler has read it, or the body is closed
	}()
	return b
}

// Started is closed once the handler has read the first byte, or the body was closed first.
func (b *CutBody) Started() <-chan struct{} { return b.started }

// Finish sends the rest of the body, then its end.
func (b *CutBody) Finish() {
	go func() { _, _ = io.WriteString(b.w, b.rest); _ = b.w.Close() }()
}

// Cut fails the rest of the read, as a connection that resets does.
func (b *CutBody) Cut() { _ = b.w.CloseWithError(errors.New("connection reset by peer")) }

// Expire fails the rest of the read as a read deadline that has passed does: the server's, set by
// shutdown.CutsBodyReads at a shutdown.
func (b *CutBody) Expire() { _ = b.w.CloseWithError(os.ErrDeadlineExceeded) }

// Stop ends the body where it is: its sender gave up.
func (b *CutBody) Stop() { _ = b.w.Close() }
