package tracing

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/codes"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
)

// A server span is an error only for a 5xx: a 4xx is the client's mistake, and 499 (the client went
// away, #527) is no failure of byward's, so both leave the status unset. The status code is recorded
// either way.
func TestAServerSpanIsAnErrorOnlyForA5xx(t *testing.T) {
	restoreGlobals(t)
	exp := tracetest.NewInMemoryExporter()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSyncer(exp))
	t.Cleanup(func() { _ = tp.Shutdown(context.Background()) })
	otel.SetTracerProvider(tp)
	for _, tc := range []struct {
		status int
		want   codes.Code
	}{
		{http.StatusOK, codes.Unset},
		{http.StatusBadRequest, codes.Unset},
		{http.StatusUnauthorized, codes.Unset},
		{http.StatusForbidden, codes.Unset},
		{http.StatusNotFound, codes.Unset},
		{http.StatusMisdirectedRequest, codes.Unset},
		{499, codes.Unset},
		{http.StatusInternalServerError, codes.Error},
		{http.StatusBadGateway, codes.Error},
		{http.StatusServiceUnavailable, codes.Error},
	} {
		t.Run(strconv.Itoa(tc.status), func(t *testing.T) {
			exp.Reset()
			h := Middleware(route, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(tc.status) }))
			h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("POST", "/mcp", nil))
			spans := exp.GetSpans()
			if len(spans) != 1 {
				t.Fatalf("got %d spans, want 1", len(spans))
			}
			if got := spans[0].Status.Code; got != tc.want {
				t.Errorf("status %d: span status %v, want %v", tc.status, got, tc.want)
			}
			var recorded int64
			for _, kv := range spans[0].Attributes {
				if kv.Key == "http.response.status_code" {
					recorded = kv.Value.AsInt64()
				}
			}
			if recorded != int64(tc.status) {
				t.Errorf("status %d: http.response.status_code is %d", tc.status, recorded)
			}
		})
	}
}
