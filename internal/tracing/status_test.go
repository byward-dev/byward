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
)

// writes is a handler that answers with status, and nothing else.
func writes(status int) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(status) }
}

// A server span is an error only for a 5xx: a 4xx is the client's mistake, and 499 (the client went
// away, #527) is no failure of byward's, so both leave the status unset. The final status counts: a
// handler that writes no header answers 200, and an informational 103 is not the answer. The status
// code is recorded either way.
func TestAServerSpanIsAnErrorOnlyForA5xx(t *testing.T) {
	restoreGlobals(t)
	exp := tracetest.NewInMemoryExporter()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSyncer(exp))
	t.Cleanup(func() { _ = tp.Shutdown(context.Background()) })
	otel.SetTracerProvider(tp)
	for _, tc := range []struct {
		name    string
		handler http.HandlerFunc
		status  int // the status the span records
		want    codes.Code
	}{
		{"a body with no header", func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "{}") }, 200, codes.Unset},
		{"200", writes(200), 200, codes.Unset},
		{"400", writes(400), 400, codes.Unset},
		{"401", writes(401), 401, codes.Unset},
		{"403", writes(403), 403, codes.Unset},
		{"404", writes(404), 404, codes.Unset},
		{"421", writes(421), 421, codes.Unset},
		{"499", writes(499), 499, codes.Unset},
		{"500", writes(500), 500, codes.Error},
		{"502", writes(502), 502, codes.Error},
		{"503", writes(503), 503, codes.Error},
		{"504", writes(504), 504, codes.Error},
		{"599", writes(599), 599, codes.Error},
		{"103 then 500", func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusEarlyHints)
			w.WriteHeader(500)
		}, 500, codes.Error},
		// Once the final status is sent, a later WriteHeader is superfluous and does not count.
		{"500 then a superfluous 200", func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(500)
			w.WriteHeader(200)
		}, 500, codes.Error},
		{"200 then a superfluous 500", func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(200)
			w.WriteHeader(500)
		}, 200, codes.Unset},
		{"500 then a body, as http.Error writes", func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, "boom", 500)
		}, 500, codes.Error},
		{"a body then a superfluous 500", func(w http.ResponseWriter, _ *http.Request) {
			_, _ = io.WriteString(w, "{}")
			w.WriteHeader(500)
		}, 200, codes.Unset},
	} {
		t.Run(tc.name, func(t *testing.T) {
			exp.Reset()
			Middleware(route, tc.handler).ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("POST", "/mcp", nil))
			spans := exp.GetSpans()
			if len(spans) != 1 {
				t.Fatalf("got %d spans, want 1", len(spans))
			}
			if got := spans[0].Status.Code; got != tc.want {
				t.Errorf("span status %v, want %v", got, tc.want)
			}
			var recorded int64
			found := false
			for _, kv := range spans[0].Attributes {
				if kv.Key == "http.response.status_code" {
					recorded, found = kv.Value.AsInt64(), true
				}
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
