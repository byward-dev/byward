package tracing

import (
	"context"
	"log/slog"
	"os"
	"strings"
	"testing"

	"github.com/byward-dev/byward/internal/testutil/rerun"
)

// An OTEL_* setting the exporter cannot parse is reported in the log by what was being parsed, never
// by its value: neither a header (a credential) nor an endpoint's userinfo reaches stderr or the log,
// over either OTLP protocol. OpenTelemetry's default logger prints to the stderr the process started
// with, so the check runs in a child process.
func TestAnOTELSettingTheExporterRejectsIsLoggedWithoutItsValue(t *testing.T) {
	if rerun.Child() {
		log := slog.New(slog.NewTextHandler(os.Stdout, nil))
		enabled, shutdown, err := Setup(context.Background(), os.Getenv, "test", log)
		if err != nil || !enabled {
			t.Fatalf("Setup: enabled=%v err=%v", enabled, err)
		}
		_ = shutdown(context.Background())
		return
	}
	const secret = "s3cret-token"
	for _, tc := range []struct {
		name, setting, value, message string
	}{
		{"a header without '='", "OTEL_EXPORTER_OTLP_HEADERS", "authorization:Bearer " + secret, "parse headers"},
		{"a header value that cannot be unescaped", "OTEL_EXPORTER_OTLP_HEADERS", "authorization=Bearer%zz" + secret, "escape header value"},
		{"an endpoint with userinfo that cannot be parsed", "OTEL_EXPORTER_OTLP_ENDPOINT", "http://user:" + secret + "@collector.example:4318/%zz", "parse url"},
	} {
		for _, protocol := range []string{"http/protobuf", "grpc"} {
			t.Run(tc.name+" over "+protocol, func(t *testing.T) {
				clearOTELEnv(t)
				got := rerun.Run(t, "TestAnOTELSettingTheExporterRejectsIsLoggedWithoutItsValue",
					"OTEL_TRACES_EXPORTER=otlp", "OTEL_EXPORTER_OTLP_PROTOCOL="+protocol, tc.setting+"="+tc.value)
				if strings.Contains(got, secret) {
					t.Fatalf("child output %q; want no part of the setting's value", got)
				}
				if !strings.Contains(got, `level=WARN msg="tracing error" error="`+tc.message+`"`) {
					t.Fatalf("child output %q; want the rejection logged at warn level as %q", got, tc.message)
				}
			})
		}
	}
}
