// Package tracing turns on OpenTelemetry traces only when the operator sets OTEL_TRACES_EXPORTER
// (ADR-0021 §9). With it unset nothing is exported and no connection is made: autoexport alone
// would default to OTLP on localhost:4318. When on, there is one HTTP server span per request,
// continuing an inbound `traceparent` header; the relay injects ours toward the upstream, and the
// MCP body (`params._meta`) is never read or changed. No MCP attributes while those conventions
// are Development.
package tracing

import (
	"context"
	"net/http"

	"go.opentelemetry.io/contrib/exporters/autoexport"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.43.0"
	"go.opentelemetry.io/otel/trace"
)

const instrumentation = "github.com/corker/mcp-authproxy"

// Setup installs the tracer provider and the W3C trace-context propagator when getenv
// ("OTEL_TRACES_EXPORTER") is set, and returns a shutdown that flushes spans. Otherwise it changes
// nothing: the global provider and propagator stay no-ops, and an inbound `traceparent` reaches the
// upstream unchanged. Baggage is never propagated (it can carry user data).
func Setup(ctx context.Context, getenv func(string) string, version string) (enabled bool, shutdown func(context.Context) error, err error) {
	noop := func(context.Context) error { return nil }
	if getenv("OTEL_TRACES_EXPORTER") == "" {
		return false, noop, nil
	}
	exp, err := autoexport.NewSpanExporter(ctx)
	if err != nil {
		return false, noop, err
	}
	if autoexport.IsNoneSpanExporter(exp) {
		return false, noop, nil
	}
	res, err := resource.Merge(resource.Default(), resource.NewSchemaless(
		semconv.ServiceName("mcp-authproxy"), semconv.ServiceVersion(version)))
	if err != nil {
		return false, noop, err
	}
	tp := sdktrace.NewTracerProvider(sdktrace.WithBatcher(exp), sdktrace.WithResource(res))
	otel.SetTracerProvider(tp)
	otel.SetTextMapPropagator(propagation.TraceContext{})
	return true, tp.Shutdown, nil
}

// Middleware starts the server span for each request, named by route(r), a fixed set of names.
func Middleware(route func(*http.Request) string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := otel.GetTextMapPropagator().Extract(r.Context(), propagation.HeaderCarrier(r.Header))
		name := route(r)
		ctx, span := otel.Tracer(instrumentation).Start(ctx, r.Method+" "+name, trace.WithSpanKind(trace.SpanKindServer),
			trace.WithAttributes(semconv.HTTPRequestMethodKey.String(r.Method), attribute.String("http.route", name)))
		defer span.End()
		rec := &statusWriter{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(rec, r.WithContext(ctx))
		span.SetAttributes(semconv.HTTPResponseStatusCode(rec.status))
		if rec.status >= 500 {
			span.SetStatus(codes.Error, "")
		}
	})
}

// Inject writes the current trace context into h (toward the upstream). With tracing off the
// propagator is a no-op and h is left as it is.
func Inject(ctx context.Context, h http.Header) {
	otel.GetTextMapPropagator().Inject(ctx, propagation.HeaderCarrier(h))
}

type statusWriter struct {
	http.ResponseWriter
	status      int
	wroteHeader bool
}

func (s *statusWriter) WriteHeader(code int) {
	if !s.wroteHeader && (code < 100 || code > 199 || code == http.StatusSwitchingProtocols) {
		s.status, s.wroteHeader = code, true
	}
	s.ResponseWriter.WriteHeader(code)
}

func (s *statusWriter) Write(b []byte) (int, error) {
	s.wroteHeader = true
	return s.ResponseWriter.Write(b)
}

// Unwrap lets http.ResponseController reach the underlying writer (flush for streams).
func (s *statusWriter) Unwrap() http.ResponseWriter { return s.ResponseWriter }
