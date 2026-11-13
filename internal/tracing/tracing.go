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
	"errors"
	"log/slog"
	"net/http"
	"net/url"

	"github.com/go-logr/logr"
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

// tracingError is the message every OpenTelemetry error is logged with.
const tracingError = "tracing error"

// propagator carries the trace context to the upstream: W3C trace context only.
var propagator propagation.TextMapPropagator = propagation.TraceContext{}

// Fields are the headers Inject sets on an upstream request, which the relay's strip cannot remove
// since Inject runs after it.
func Fields() []string { return propagator.Fields() }

// Setup installs the tracer provider, the W3C trace-context propagator, and an error handler and a
// logger that send OpenTelemetry's errors (a failed export, an exporter setting it rejects, an SDK
// setting it rejects) to log, when getenv("OTEL_TRACES_EXPORTER") is set, and returns a
// shutdown that flushes spans. Otherwise it changes nothing: the global provider and propagator stay
// no-ops, and an inbound `traceparent` reaches the upstream unchanged. Baggage is never propagated
// (it can carry user data).
func Setup(ctx context.Context, getenv func(string) string, version string, log *slog.Logger) (enabled bool, shutdown func(context.Context) error, err error) {
	noop := func(context.Context) error { return nil }
	if getenv("OTEL_TRACES_EXPORTER") == "" {
		return false, noop, nil
	}
	// Both go in first: the exporter reports a setting it rejects through the logger, and the first
	// handler set is the one OTel's default handler forwards to for good. settingErrors replaces it
	// only while the SDK reads its own settings.
	otel.SetLogger(logr.New(otelLog{log}))
	handler := errorHandler(log, envproxy.SettingMisread())
	otel.SetErrorHandler(handler)
	exp, err := autoexport.NewSpanExporter(ctx)
	if err != nil {
		return false, noop, err
	}
	if autoexport.IsNoneSpanExporter(exp) {
		return false, noop, nil
	}
	otel.SetErrorHandler(settingErrors(log))
	tp, err := provider(exp, version)
	otel.SetErrorHandler(handler)
	if err != nil {
		return false, noop, err
	}
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
			log.Warn(tracingError, "error", envproxy.Cause)
			return
		}
		log.Warn(tracingError, "error", err)
	}
}

// provider is the tracer provider exporting to exp. Building it reads the SDK's settings:
// OTEL_RESOURCE_ATTRIBUTES (twice) and the sampler's.
func provider(exp sdktrace.SpanExporter, version string) (*sdktrace.TracerProvider, error) {
	res, err := resource.Merge(resource.Default(), resource.NewSchemaless(
		semconv.ServiceName("byward"), semconv.ServiceVersion(version)))
	if err != nil {
		return nil, err
	}
	return sdktrace.NewTracerProvider(sdktrace.WithBatcher(exp), sdktrace.WithResource(res)), nil
}

// settingErrors is the error handler while the SDK reads its settings: it logs a fixed text naming
// the setting OpenTelemetry rejected (one it cannot parse, or a sampler ratio out of range), since
// OTel's error quotes the value (part of it for a bad escape), which can be a credential pasted by
// mistake. Resource detection's errors are told apart by type; any other is the sampler's, the only
// other setting read then.
func settingErrors(log *slog.Logger) otel.ErrorHandlerFunc {
	return func(err error) {
		setting := "OTEL_TRACES_SAMPLER or OTEL_TRACES_SAMPLER_ARG"
		var escape url.EscapeError
		if errors.Is(err, resource.ErrPartialResource) || errors.As(err, &escape) {
			setting = "OTEL_RESOURCE_ATTRIBUTES"
		}
		log.Warn(tracingError, "error", "invalid "+setting)
	}
}

// otelLog is OpenTelemetry's own logger, in place of its default, which prints to stderr. OTel logs
// the raw value of a setting it cannot parse (a header, often a credential, or an endpoint with its
// userinfo), and the error it logs with it can quote that value too, so only its message, which
// names what it was parsing, reaches the log. Like the default, it passes only OTel's errors, not its
// warnings or below.
type otelLog struct{ log *slog.Logger }

func (otelLog) Init(logr.RuntimeInfo)                 {}
func (otelLog) Enabled(level int) bool                { return level == 0 }
func (l otelLog) Info(_ int, msg string, _ ...any)    { l.log.Warn(tracingError, "error", msg) }
func (l otelLog) Error(_ error, msg string, _ ...any) { l.log.Warn(tracingError, "error", msg) }
func (l otelLog) WithValues(...any) logr.LogSink      { return l }
func (l otelLog) WithName(string) logr.LogSink        { return l }

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
