package tracing

import (
	"context"
	"log/slog"
	"os"
	"strings"
	"testing"

	"go.opentelemetry.io/otel"

	"github.com/byward-dev/byward/internal/testutil/rerun"
)

// Trace export reads the environment proxy (once per process, so the check runs in a child
// process), over either OTLP protocol: through a setting Go misread, the failed export is logged
// with the cause alone, and nothing on stderr or in the log quotes the address Go dialled.
func TestAFailedTraceExportNeverQuotesAMisreadEnvironmentProxy(t *testing.T) {
	if rerun.Child() {
		log := slog.New(slog.NewTextHandler(os.Stdout, nil))
		enabled, shutdown, err := Setup(context.Background(), os.Getenv, "test", log)
		if err != nil || !enabled {
			t.Fatalf("Setup: enabled=%v err=%v", enabled, err)
		}
		_, span := otel.Tracer(instrumentation).Start(context.Background(), "span")
		span.End()
		_ = shutdown(context.Background()) // the export fails, and its error goes to the handler
		return
	}
	for _, tc := range []struct{ name, protocol, endpoint string }{
		{"http-protobuf to a URL", "http/protobuf", "http://collector.example:4318"},
		{"grpc to a URL", "grpc", "http://collector.example:4317"},
		{"grpc to a target that names a DNS resolver first", "grpc", "dns://127.0.0.1:53/collector.example:4317"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			clearOTELEnv(t)
			t.Setenv("OTEL_TRACES_EXPORTER", "otlp")
			t.Setenv("OTEL_EXPORTER_OTLP_PROTOCOL", tc.protocol)
			t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", tc.endpoint)
			t.Setenv("OTEL_BSP_EXPORT_TIMEOUT", "1000") // ms: the export's retries end within it
			t.Setenv("GRPC_GO_LOG_SEVERITY_LEVEL", "")  // grpc's default: a developer's debug logs quote the address
			t.Setenv("GRPC_GO_LOG_VERBOSITY_LEVEL", "")
			rerun.EachProxySetting(t, "TestAFailedTraceExportNeverQuotesAMisreadEnvironmentProxy", func(t *testing.T, got, addr string, misread bool) {
				if !strings.Contains(got, `level=WARN msg="tracing error"`) {
					t.Fatalf("child output %q; want the failed export in the log at warn level", got)
				}
				rerun.CauseOnlyIfMisread(t, got, addr, misread)
			})
		})
	}
}
