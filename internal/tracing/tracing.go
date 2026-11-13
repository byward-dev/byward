// Package tracing turns on OpenTelemetry traces only when the operator sets OTEL_TRACES_EXPORTER
// (ADR-0021 §9). With it unset nothing is exported and no connection is made: autoexport alone
// would default to OTLP on localhost:4318. When on, there is one HTTP server span per request,
// continuing an inbound `traceparent` header; the relay injects ours toward the upstream, and the
// MCP body (`params._meta`) is never read or changed. No MCP attributes while those conventions
// are Development.
package tracing

import (
	"github.com/byward-dev/byward/internal/envproxy"
	"github.com/byward-dev/byward/internal/logging"

	"context"
	"log/slog"
	"net/http"
	"net/url"
	"strings"

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

const instrumentation = "github.com/byward-dev/byward"

// propagator carries the trace context to the upstream: W3C trace context only.
var propagator propagation.TextMapPropagator = propagation.TraceContext{}

// Fields are the headers Inject sets on an upstream request, which the relay's strip cannot remove
// since Inject runs after it.
func Fields() []string { return propagator.Fields() }

// Setup installs the tracer provider, the W3C trace-context propagator and an error handler that
// sends OpenTelemetry's errors, such as a failed export, to log, when getenv("OTEL_TRACES_EXPORTER")
// is set, and returns a shutdown that flushes spans. Otherwise it changes nothing: the global
// provider and propagator stay no-ops, and an inbound `traceparent` reaches the upstream unchanged.
// Baggage is never propagated (it can carry user data).
func Setup(ctx context.Context, getenv func(string) string, version string, log *slog.Logger) (enabled bool, shutdown func(context.Context) error, err error) {
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
		semconv.ServiceName("byward"), semconv.ServiceVersion(version)))
	if err != nil {
		return false, noop, err
	}
	otel.SetErrorHandler(errorHandler(log, collectorProxyMisread(getenv, envproxy.Proxy)))
	tp := sdktrace.NewTracerProvider(sdktrace.WithBatcher(exp), sdktrace.WithResource(res))
	otel.SetTracerProvider(tp)
	otel.SetTextMapPropagator(propagator)
	return true, tp.Shutdown, nil
}

// errorHandler logs OpenTelemetry's errors in place of its default, which prints them to stderr as
// they are. Through an environment proxy Go misread, an export error quotes the address Go dialled
// from the setting's credentials, so every error then says only envproxy.Cause.
func errorHandler(log *slog.Logger, misread bool) otel.ErrorHandlerFunc {
	return func(err error) {
		if misread {
			log.Warn("tracing error", "error", envproxy.Cause)
			return
		}
		log.Warn("tracing error", "error", err)
	}
}

// collectorProxyMisread reports whether an environment proxy, as proxy reads it (envproxy.Proxy in
// production), that requests to an OTLP endpoint the settings name go through is one Go misread.
// Every endpoint setting is judged, not only the one the exporter picks, so a change in how it picks
// (it skips a traces endpoint it cannot parse) can only redact more. The http/protobuf exporter
// picks its proxy by the endpoint's scheme, the grpc one always as https, so both are judged. With
// no endpoint set the collector is on localhost, which Go never sends through a proxy.
func collectorProxyMisread(getenv func(string) string, proxy func(*http.Request) (*url.URL, error)) bool {
	for _, setting := range []string{"OTEL_EXPORTER_OTLP_TRACES_ENDPOINT", "OTEL_EXPORTER_OTLP_ENDPOINT"} {
		endpoint := strings.TrimSpace(getenv(setting)) // as OTel reads it
		if endpoint == "" {
			continue
		}
		host := endpoint // grpc takes a bare host:port
		if u, err := url.Parse(endpoint); err == nil && u.Host != "" {
			host = u.Host
		}
		for _, scheme := range []string{"http", "https"} {
			if via, err := proxy(&http.Request{URL: &url.URL{Scheme: scheme, Host: host}}); err == nil && envproxy.Malformed(via) {
				return true
			}
		}
	}
	return false
}

// Middleware starts the server span for each request, named by route(r), a fixed set of names.
func Middleware(route func(*http.Request) string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := otel.GetTextMapPropagator().Extract(r.Context(), propagation.HeaderCarrier(r.Header))
		name := route(r)
		ctx, span := otel.Tracer(instrumentation).Start(ctx, r.Method+" "+name, trace.WithSpanKind(trace.SpanKindServer),
			trace.WithAttributes(semconv.HTTPRequestMethodKey.String(r.Method), attribute.String("http.route", name)))
		defer span.End()
		rec := logging.NewStatusRecorder(w)
		next.ServeHTTP(rec, r.WithContext(ctx))
		span.SetAttributes(semconv.HTTPResponseStatusCode(rec.Status()))
		if rec.Status() >= 500 {
			span.SetStatus(codes.Error, "")
		}
	})
}

// Inject writes the current trace context into h (toward the upstream). With tracing off the
// propagator is a no-op and h is left as it is.
func Inject(ctx context.Context, h http.Header) {
	otel.GetTextMapPropagator().Inject(ctx, propagation.HeaderCarrier(h))
}
