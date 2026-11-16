package tracing

import (
	"context"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"go.opentelemetry.io/contrib/exporters/autoexport"

	"github.com/byward-dev/byward/internal/testutil/testcert"
)

// L157, ADR-0021 §9: NewExporter refuses each class of OTEL_* value startup refuses (an unknown
// exporter, an OTLP protocol autoexport does not offer, an insecure endpoint with a TLS file),
// deliberately stricter than the OTel specification's warn-and-ignore, and builds the rest. With
// OTEL_TRACES_EXPORTER unset it builds nothing.
func TestNewExporterRefusesWhatStartupRefuses(t *testing.T) {
	ca := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(ca, testcert.Root(t), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name    string
		env     map[string]string
		refused string // "" when built; else autoexport's or otlptracehttp's error text, which a dependency update may reword
	}{
		{"an unknown exporter", map[string]string{"OTEL_TRACES_EXPORTER": "jaeger"}, "unknown exporter"},
		{"a list of exporters", map[string]string{"OTEL_TRACES_EXPORTER": "otlp,console"}, "unknown exporter"},
		{"an unknown OTLP protocol", map[string]string{"OTEL_TRACES_EXPORTER": "otlp", "OTEL_EXPORTER_OTLP_PROTOCOL": "http/json"}, "invalid OTLP protocol"},
		{"an unknown traces protocol", map[string]string{"OTEL_TRACES_EXPORTER": "otlp", "OTEL_EXPORTER_OTLP_TRACES_PROTOCOL": "udp"}, "invalid OTLP protocol"},
		{"an http:// endpoint with a TLS file", map[string]string{"OTEL_TRACES_EXPORTER": "otlp", "OTEL_EXPORTER_OTLP_PROTOCOL": "http/protobuf",
			"OTEL_EXPORTER_OTLP_ENDPOINT": "http://127.0.0.1:4318", "OTEL_EXPORTER_OTLP_CERTIFICATE": ca}, "insecure HTTP endpoint cannot use TLS client configuration"},
		{"an https:// endpoint made insecure, with a TLS file", map[string]string{"OTEL_TRACES_EXPORTER": "otlp",
			"OTEL_EXPORTER_OTLP_ENDPOINT": "https://127.0.0.1:4318", "OTEL_EXPORTER_OTLP_INSECURE": "true", "OTEL_EXPORTER_OTLP_CERTIFICATE": ca},
			"insecure HTTP endpoint cannot use TLS client configuration"},
		{"the traces protocol wins over the general one", map[string]string{"OTEL_TRACES_EXPORTER": "otlp", "OTEL_EXPORTER_OTLP_PROTOCOL": "udp",
			"OTEL_EXPORTER_OTLP_TRACES_PROTOCOL": "grpc"}, ""},
		{"none", map[string]string{"OTEL_TRACES_EXPORTER": "none"}, ""},
		{"console", map[string]string{"OTEL_TRACES_EXPORTER": "console"}, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			clearOTELEnv(t)
			restoreGlobals(t)
			for k, v := range tc.env {
				t.Setenv(k, v)
			}
			exp, err := NewExporter(context.Background(), os.Getenv, slog.New(slog.DiscardHandler))
			if tc.refused != "" {
				if err == nil || !strings.Contains(err.Error(), tc.refused) {
					t.Fatalf("NewExporter = %v; want it refused: %q", err, tc.refused)
				}
				return
			}
			if err != nil || exp == nil {
				t.Fatalf("NewExporter = %v, %v; want an exporter", exp, err)
			}
			if err := exp.Shutdown(context.Background()); err != nil {
				t.Fatalf("Shutdown: %v", err)
			}
		})
	}
	t.Run("unset", func(t *testing.T) {
		clearOTELEnv(t)
		restoreGlobals(t)
		if exp, err := NewExporter(context.Background(), os.Getenv, slog.New(slog.DiscardHandler)); exp != nil || err != nil {
			t.Fatalf("NewExporter with OTEL_TRACES_EXPORTER unset = %v, %v; want nothing built", exp, err)
		}
	})
}

// check --offline builds the exporter and shuts it down (L157): over either OTLP protocol, that
// opens no connection to the endpoint.
func TestNewExporterConnectsToNothing(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	for _, protocol := range []string{"http/protobuf", "grpc"} {
		t.Run(protocol, func(t *testing.T) {
			clearOTELEnv(t)
			restoreGlobals(t)
			t.Setenv("OTEL_TRACES_EXPORTER", "otlp")
			t.Setenv("OTEL_EXPORTER_OTLP_PROTOCOL", protocol)
			t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "http://"+ln.Addr().String())
			exp, err := NewExporter(context.Background(), os.Getenv, slog.New(slog.DiscardHandler))
			if err != nil || exp == nil || autoexport.IsNoneSpanExporter(exp) {
				t.Fatalf("NewExporter = %v, %v; want an OTLP exporter", exp, err)
			}
			time.Sleep(100 * time.Millisecond) // a connect the build started in the background lands while the listener is open
			if err := exp.Shutdown(context.Background()); err != nil {
				t.Fatalf("Shutdown: %v", err)
			}
		})
	}
	// Count every connection in the backlog, before closing the listener would discard one the
	// kernel completed but nothing accepted yet.
	if err := ln.(*net.TCPListener).SetDeadline(time.Now().Add(100 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	n := 0
	for {
		c, err := ln.Accept()
		if err != nil {
			break
		}
		n++
		_ = c.Close()
	}
	if n != 0 {
		t.Fatalf("building and shutting down the exporter opened %d connections, want none", n)
	}
}
