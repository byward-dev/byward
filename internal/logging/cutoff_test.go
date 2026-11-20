package logging

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"runtime"
	"testing"
	"time"

	"github.com/byward-dev/byward/internal/shutdown"
)

// recorded is what one Observe call recorded, and whether it recorded at all.
type recorded struct {
	status int
	cut    CutOff
	called int
}

func (r *recorded) record(status int, cut CutOff) {
	r.status, r.cut, r.called = status, cut, r.called+1
}

// observe serves req with h through Observe and returns what it recorded and what panicked out of it.
func observe(req *http.Request, h http.HandlerFunc) (rec recorded, panicked any) {
	defer func() { panicked = recover() }()
	Observe(httptest.NewRecorder(), req, h, rec.record)
	return rec, nil
}

// The handlers a request can meet: one that answers, one whose stream its upstream breaks off (as
// ReverseProxy aborts it), and one that ends its stream by returning.
func accepted(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusAccepted) }

func streamThenAbort(w http.ResponseWriter, _ *http.Request) {
	_, _ = w.Write([]byte("data: one\n\n"))
	panic(http.ErrAbortHandler)
}

func streamThenEnd(w http.ResponseWriter, r *http.Request) {
	_, _ = w.Write([]byte("data: one\n\n"))
	StreamEnded(r.Context())
}

// A response cut off after its headers is recorded with the status it sent and why, then the abort
// goes on to the server; a response that ends is recorded with no cause (#533).
func TestObserveRecordsTheStatusSentAndWhyAResponseWasCutOff(t *testing.T) {
	live := func() *http.Request { return httptest.NewRequest(http.MethodGet, "/mcp", nil) }
	clientGone := func() *http.Request {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		return live().WithContext(ctx)
	}
	shuttingDown := func() *http.Request {
		ctx, shutDown := shutdown.WithCancel(context.Background())
		shutDown()
		return live().WithContext(ctx)
	}
	pastDeadline := func() *http.Request {
		ctx, cancel := context.WithDeadline(context.Background(), time.Unix(0, 0))
		t.Cleanup(cancel)
		return live().WithContext(ctx)
	}
	var markedTwice struct {
		req      *http.Request
		shutDown func()
	}
	{
		ctx, shutDown := shutdown.WithCancel(context.Background())
		t.Cleanup(shutDown)
		markedTwice.req, markedTwice.shutDown = live().WithContext(ctx), shutDown
	}
	for _, tc := range []struct {
		name    string
		req     *http.Request
		handler http.HandlerFunc
		status  int
		cut     CutOff
		aborted bool
	}{
		{"a response that ends", live(), accepted, http.StatusAccepted, "", false},
		{"a response that ends after its client left", clientGone(), accepted, http.StatusAccepted, "", false},
		{"its upstream broke off", live(), streamThenAbort, http.StatusOK, UpstreamAborted, true},
		{"its MCP client went away", clientGone(), streamThenAbort, http.StatusOK, ClientClosed, true},
		{"the proxy shut down", shuttingDown(), streamThenAbort, http.StatusOK, ShutDown, true},
		// Neither the proxy nor its client ended a request past a deadline, as shutdown tells them apart.
		{"its upstream broke off, the request past a deadline", pastDeadline(), streamThenAbort, http.StatusOK, UpstreamAborted, true},
		{"its upstream broke off after a 500", live(), func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
			panic(http.ErrAbortHandler)
		}, http.StatusInternalServerError, UpstreamAborted, true},
		{"a stream its handler ends after its client left", clientGone(), streamThenEnd, http.StatusOK, ClientClosed, false},
		{"a stream its handler ends at shutdown", shuttingDown(), streamThenEnd, http.StatusOK, ShutDown, false},
		{"a stream its handler ends, its request still live (as after a failed write)", live(), streamThenEnd, http.StatusOK, ClientClosed, false},
		{"a stream marked cut off twice keeps its first cause", markedTwice.req, func(w http.ResponseWriter, r *http.Request) {
			streamThenEnd(w, r) // a failed write, its request still live
			markedTwice.shutDown()
			StreamEnded(r.Context())
		}, http.StatusOK, ClientClosed, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec, p := observe(tc.req, tc.handler)
			if rec.called != 1 || rec.status != tc.status || rec.cut != tc.cut {
				t.Errorf("recorded %d times, status %d, cut %q; want once, %d, %q", rec.called, rec.status, rec.cut, tc.status, tc.cut)
			}
			if aborted := p == http.ErrAbortHandler; aborted != tc.aborted || (p != nil && !aborted) { //nolint:errorlint // sentinel compared as net/http does
				t.Errorf("panic %v; want http.ErrAbortHandler: %v", p, tc.aborted)
			}
		})
	}
}

// Any other panic is not Observe's: it goes on as it was, unrecorded, to the recoverer below the
// wrappers or the server. A handler that ends with runtime.Goexit (a test's t.FailNow) neither
// records nor panics.
func TestObserveLeavesOtherPanicsAndGoexitAlone(t *testing.T) {
	rec, p := observe(httptest.NewRequest(http.MethodGet, "/", nil), func(http.ResponseWriter, *http.Request) { panic("boom") })
	if p != "boom" || rec.called != 0 {
		t.Errorf("panic %v, recorded %d times; want the panic %q, unrecorded", p, rec.called, "boom")
	}
	done := make(chan recorded)
	go func() {
		var rec recorded
		defer func() { done <- rec }()
		defer func() {
			if p := recover(); p != nil {
				t.Errorf("Goexit turned into the panic %v", p)
			}
		}()
		Observe(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil),
			http.HandlerFunc(func(http.ResponseWriter, *http.Request) { runtime.Goexit() }), rec.record)
	}()
	if rec := <-done; rec.called != 0 {
		t.Errorf("recorded %d times for a handler that called runtime.Goexit; want none", rec.called)
	}
}

// Wrappers nested around one request record the same cause, even when the request ends between
// their records: the innermost decides it.
func TestNestedObserversRecordOneCause(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var outer, inner recorded
	func() {
		defer func() { _ = recover() }()
		Observe(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil).WithContext(ctx), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			defer cancel() // the client leaves after the inner record, before the outer one
			Observe(w, r, http.HandlerFunc(streamThenAbort), inner.record)
		}), outer.record)
	}()
	if inner.cut != UpstreamAborted || outer.cut != UpstreamAborted {
		t.Errorf("inner %q, outer %q; want both %q", inner.cut, outer.cut, UpstreamAborted)
	}
}

// The request line of a response cut off after its headers has the status it sent and why, as
// error_type; every other request line has no error_type at all (#533).
func TestARequestLineHasAnErrorTypeOnlyForAResponseCutOff(t *testing.T) {
	for _, tc := range []struct {
		name      string
		handler   http.HandlerFunc
		status    float64
		errorType any // the request line's error_type, as JSON decodes it; nil for none
	}{
		{"a response that ends", accepted, http.StatusAccepted, nil},
		{"a stream its upstream broke off", streamThenAbort, http.StatusOK, string(UpstreamAborted)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			func() {
				defer func() { _ = recover() }() // a cut-off response's abort goes on to the server
				Middleware(New(&buf, "json"), tc.handler).ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/mcp", nil))
			}()
			var line map[string]any
			if err := json.Unmarshal(buf.Bytes(), &line); err != nil {
				t.Fatalf("request line %q: %v", buf.String(), err)
			}
			if got, has := line["error_type"]; line["status"] != tc.status || got != tc.errorType || has != (tc.errorType != nil) {
				t.Errorf("request line %s; want status %v and error_type %v", buf.String(), tc.status, tc.errorType)
			}
		})
	}
}
