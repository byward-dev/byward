package tracing

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/trace/noop"
)

const inbound = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"

func route(*http.Request) string { return "mcp" }

// forwarded runs one request through Middleware and returns the traceparent Inject would send on.
func forwarded(t *testing.T) string {
	t.Helper()
	var out http.Header
	h := Middleware(route, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		out = r.Header.Clone() // the relay's Rewrite starts from a copy of the inbound headers
		Inject(r.Context(), out)
	}))
	r := httptest.NewRequest("POST", "/mcp", nil)
	r.Header.Set("traceparent", inbound)
	h.ServeHTTP(httptest.NewRecorder(), r)
	return out.Get("traceparent")
}

func restoreGlobals(t *testing.T) {
	t.Cleanup(func() {
		otel.SetTracerProvider(noop.NewTracerProvider())
		otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator())
	})
}

func clearOTELEnv(t *testing.T) {
	for _, kv := range os.Environ() {
		if k, _, _ := strings.Cut(kv, "="); strings.HasPrefix(k, "OTEL_") {
			t.Setenv(k, "")
			_ = os.Unsetenv(k)
		}
	}
}

// ADR-0024 §6: with OTEL_* unset, no telemetry connection happens (autoexport alone would send OTLP
// to localhost:4318). Setup must leave the global provider and propagator as they were; when the
// default port is free it is also watched for connections.
func TestNoTelemetryConnectionWhenOTELIsUnset(t *testing.T) {
	clearOTELEnv(t)
	restoreGlobals(t)
	var conns atomic.Int32
	if ln, err := net.Listen("tcp", "127.0.0.1:4318"); err == nil {
		defer func() { _ = ln.Close() }()
		go func() {
			for {
				c, err := ln.Accept()
				if err != nil {
					return
				}
				conns.Add(1)
				_ = c.Close()
			}
		}()
	} else {
		t.Logf("port 4318 is busy (%v); relying on the unchanged-globals check", err)
	}
	tp, prop := otel.GetTracerProvider(), otel.GetTextMapPropagator()
	enabled, shutdown, err := Setup(context.Background(), os.Getenv, "test")
	if err != nil || enabled {
		t.Fatalf("Setup with OTEL_* unset: enabled=%v err=%v, want off and no error", enabled, err)
	}
	if otel.GetTracerProvider() != tp || otel.GetTextMapPropagator() != prop {
		t.Fatal("Setup with OTEL_* unset replaced the global tracer provider or propagator")
	}
	if got := forwarded(t); got != inbound {
		t.Fatalf("with tracing off the inbound traceparent must pass unchanged, got %q", got)
	}
	// Shutdown flushes synchronously; with tracing off there is no exporter goroutine at all.
	_ = shutdown(context.Background())
	if n := conns.Load(); n != 0 {
		t.Fatalf("%d connection(s) to the OTLP default port with OTEL_* unset", n)
	}
}

func TestNoneExporterIsOff(t *testing.T) {
	clearOTELEnv(t)
	restoreGlobals(t)
	t.Setenv("OTEL_TRACES_EXPORTER", "none")
	if enabled, _, err := Setup(context.Background(), os.Getenv, "test"); err != nil || enabled {
		t.Fatalf("OTEL_TRACES_EXPORTER=none: enabled=%v err=%v", enabled, err)
	}
}

func TestTracesContinueTheInboundTraceAndReachTheExporter(t *testing.T) {
	clearOTELEnv(t)
	restoreGlobals(t)
	var exports atomic.Int32
	collector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" && r.URL.Path == "/v1/traces" {
			exports.Add(1)
		}
		w.WriteHeader(200)
	}))
	defer collector.Close()
	t.Setenv("OTEL_TRACES_EXPORTER", "otlp")
	t.Setenv("OTEL_EXPORTER_OTLP_PROTOCOL", "http/protobuf")
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", collector.URL)
	enabled, shutdown, err := Setup(context.Background(), os.Getenv, "test")
	if err != nil || !enabled {
		t.Fatalf("Setup: enabled=%v err=%v", enabled, err)
	}
	got := forwarded(t)
	parts := strings.Split(got, "-")
	if len(parts) != 4 || parts[1] != "4bf92f3577b34da6a3ce929d0e0e4736" || parts[2] == "00f067aa0ba902b7" {
		t.Fatalf("injected traceparent %q must continue trace 4bf9… with our own span ID", got)
	}
	if err := shutdown(context.Background()); err != nil {
		t.Fatal(err)
	}
	if exports.Load() == 0 {
		t.Fatal("no span reached the configured OTLP endpoint")
	}
}
