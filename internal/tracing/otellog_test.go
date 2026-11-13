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
		{"an endpoint with a bad escape and userinfo", "OTEL_EXPORTER_OTLP_ENDPOINT", "http://user:" + secret + "@collector.example:4318/%zz", "parse url"},
	} {
		for _, protocol := range []string{"http/protobuf", "grpc"} {
			t.Run(tc.name+" over "+protocol, func(t *testing.T) {
				clearOTELEnv(t)
				got := rerun.Run(t, "TestAnOTELSettingTheExporterRejectsIsLoggedWithoutItsValue",
					"OTEL_TRACES_EXPORTER=otlp", "OTEL_EXPORTER_OTLP_PROTOCOL="+protocol, tc.setting+"="+tc.value)
				if strings.Contains(got, secret) {
					t.Fatalf("child output %q; want no %q from the setting's value", got, secret)
				}
				if !strings.Contains(got, `level=WARN msg="tracing error" error="`+tc.message+`"`) {
					t.Fatalf("child output %q; want the rejection logged at warn level as %q", got, tc.message)
				}
				if n := strings.Count(got, `msg="tracing error"`); n != 1 { // OTel's info stays out (its "TracerProvider created")
					t.Fatalf("child output %q; want that one tracing error, got %d", got, n)
				}
			})
		}
	}
}

// An SDK setting OpenTelemetry cannot parse is logged by its name at warn level, never by its value,
// in the log or on stderr: OTel's own error quotes the value (part of it for a bad escape), which can
// be a credential pasted by mistake. The SDK reads each setting once per process, so each row runs
// in a child process.
func TestAnSDKSettingOTELCannotParseIsLoggedByNameWithoutItsValue(t *testing.T) {
	if rerun.Child() {
		log := slog.New(slog.NewTextHandler(os.Stdout, nil))
		if _, shutdown, err := Setup(context.Background(), os.Getenv, "test", log); err == nil {
			_ = shutdown(context.Background())
		}
		return
	}
	const sampler = "OTEL_TRACES_SAMPLER or OTEL_TRACES_SAMPLER_ARG"
	for _, tc := range []struct {
		name    string
		env     []string
		quoted  string // what OTel's own error quotes from the value
		setting string
	}{
		{"a resource attribute without '='", []string{"OTEL_RESOURCE_ATTRIBUTES=s3cret-token"}, "s3cret-token", "OTEL_RESOURCE_ATTRIBUTES"},
		{"a resource attribute value that cannot be unescaped", []string{"OTEL_RESOURCE_ATTRIBUTES=k=%zzs3cret"}, "%zz", "OTEL_RESOURCE_ATTRIBUTES"},
		{"a sampler argument that is not a number", []string{"OTEL_TRACES_SAMPLER=traceidratio", "OTEL_TRACES_SAMPLER_ARG=s3cret-token"}, "s3cret-token", sampler},
		{"a parent-based sampler argument that is not a number", []string{"OTEL_TRACES_SAMPLER=parentbased_traceidratio", "OTEL_TRACES_SAMPLER_ARG=s3cret-token"}, "s3cret-token", sampler},
		{"a sampler OTel does not know", []string{"OTEL_TRACES_SAMPLER=s3cret-token"}, "s3cret-token", sampler},
	} {
		t.Run(tc.name, func(t *testing.T) {
			clearOTELEnv(t)
			got := rerun.Run(t, "TestAnSDKSettingOTELCannotParseIsLoggedByNameWithoutItsValue", append(tc.env, "OTEL_TRACES_EXPORTER=console")...)
			if strings.Contains(got, tc.quoted) {
				t.Fatalf("child output %q; want no %q from the setting's value", got, tc.quoted)
			}
			want := `level=WARN msg="tracing error" error="cannot parse ` + tc.setting + `"`
			if !strings.Contains(got, want) {
				t.Fatalf("child output %q; want %q", got, want)
			}
			for _, line := range strings.Split(got, "\n") {
				if strings.Contains(line, `msg="tracing error"`) && !strings.Contains(line, want) {
					t.Fatalf("line %q; want every tracing error to be %q", line, want)
				}
			}
		})
	}
}
