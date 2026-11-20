package tracing

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/codes"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"

	"github.com/byward-dev/byward/internal/shutdown"
)

// streamThenAbort starts a stream, then aborts it as ReverseProxy does when its upstream's body fails.
func streamThenAbort(w http.ResponseWriter, _ *http.Request) {
	_, _ = io.WriteString(w, "data: one\n\n")
	panic(http.ErrAbortHandler)
}

// clientGone and shuttingDown are a request's context ended by its client going away, and by the
// proxy's shutdown.
func clientGone() context.Context {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	return ctx
}

func shuttingDown() context.Context {
	ctx, shutDown := shutdown.WithCancel(context.Background())
	shutDown()
	return ctx
}

// writes is a handler that answers with status, and nothing else.
func writes(status int) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(status) }
}

// A server span is an error only for a 5xx, or a response its upstream broke off after its headers: a
// 4xx is the client's mistake, and 499 (the client went away, #527) is no failure of byward's, so both
// leave the status unset. The final status counts: a handler that writes no header answers 200, and
// an informational 103 is not the answer. The status code is recorded either way. A response cut off
// after its headers also records why as error.type, which is absent from every other span (#533):
// one whose client went away, or that the proxy's shutdown ended, is still no failure.
func TestAServerSpanIsAnErrorOnlyForA5xxOrAnUpstreamBreakOff(t *testing.T) {
	restoreGlobals(t)
	clearOTELEnv(t)
	exp := tracetest.NewInMemoryExporter()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSyncer(exp))
	t.Cleanup(func() { _ = tp.Shutdown(context.Background()) })
	otel.SetTracerProvider(tp)
	for _, tc := range []struct {
		name    string
		handler http.HandlerFunc
		status  int // the status the span records
		want    codes.Code
		ctx     func() context.Context // the request's context; nil for one that stays live
		errType string                 // the span's error.type; "" for none at all
	}{
		{"a body with no header", func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "{}") }, 200, codes.Unset, nil, ""},
		{"200", writes(200), 200, codes.Unset, nil, ""},
		{"400", writes(400), 400, codes.Unset, nil, ""},
		{"401", writes(401), 401, codes.Unset, nil, ""},
		{"403", writes(403), 403, codes.Unset, nil, ""},
		{"404", writes(404), 404, codes.Unset, nil, ""},
		{"421", writes(421), 421, codes.Unset, nil, ""},
		{"499", writes(499), 499, codes.Unset, nil, ""},
		{"500", writes(500), 500, codes.Error, nil, ""},
		{"502", writes(502), 502, codes.Error, nil, ""},
		{"503", writes(503), 503, codes.Error, nil, ""},
		{"504", writes(504), 504, codes.Error, nil, ""},
		{"599", writes(599), 599, codes.Error, nil, ""},
		{"103 then 500", func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusEarlyHints)
			w.WriteHeader(500)
		}, 500, codes.Error, nil, ""},
		// Once the final status is sent, a later WriteHeader is superfluous and does not count.
		{"500 then a superfluous 200", func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(500)
			w.WriteHeader(200)
		}, 500, codes.Error, nil, ""},
		{"200 then a superfluous 500", func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(200)
			w.WriteHeader(500)
		}, 200, codes.Unset, nil, ""},
		{"500 then a body, as http.Error writes", func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, "boom", 500)
		}, 500, codes.Error, nil, ""},
		{"a body then a superfluous 500", func(w http.ResponseWriter, _ *http.Request) {
			_, _ = io.WriteString(w, "{}")
			w.WriteHeader(500)
		}, 200, codes.Unset, nil, ""},
		{"a stream its upstream broke off", streamThenAbort, 200, codes.Error, nil, "upstream_aborted"},
		{"a stream whose client went away", streamThenAbort, 200, codes.Unset, clientGone, "client_closed"},
		{"a stream the proxy's shutdown ended", streamThenAbort, 200, codes.Unset, shuttingDown, "shutdown"},
		{"a 500 whose client went away", func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(500)
			panic(http.ErrAbortHandler)
		}, 500, codes.Error, clientGone, "client_closed"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			exp.Reset()
			req := httptest.NewRequest("POST", "/mcp", nil)
			if tc.ctx != nil {
				req = req.WithContext(tc.ctx())
			}
			func() {
				defer func() { // a cut-off response's abort goes on to the server
					if p := recover(); (p != nil) != (tc.errType != "") {
						t.Errorf("panic %v; want http.ErrAbortHandler only for a response cut off", p)
					}
				}()
				Middleware(route, tc.handler).ServeHTTP(httptest.NewRecorder(), req)
			}()
			spans := exp.GetSpans()
			if len(spans) != 1 {
				t.Fatalf("got %d spans, want 1", len(spans))
			}
			if got := spans[0].Status.Code; got != tc.want {
				t.Errorf("span status %v, want %v", got, tc.want)
			}
			var recorded int64
			found := false
			errType, hasErrType := "", false
			for _, kv := range spans[0].Attributes {
				switch kv.Key {
				case "http.response.status_code":
					recorded, found = kv.Value.AsInt64(), true
				case "error.type":
					errType, hasErrType = kv.Value.AsString(), true
				}
			}
			if hasErrType != (tc.errType != "") || errType != tc.errType {
				t.Errorf("error.type %q (set: %v); want %q, and none unless the response was cut off", errType, hasErrType, tc.errType)
			}
			switch {
			case !found:
				t.Error("the span has no http.response.status_code attribute")
			case recorded != int64(tc.status):
				t.Errorf("http.response.status_code is %d, want %d", recorded, tc.status)
			}
		})
	}
}
