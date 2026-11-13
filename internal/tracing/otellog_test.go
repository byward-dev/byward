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

// An SDK setting OpenTelemetry rejects is logged by its name at warn level, never by its value,
// in the log or on stderr: OTel's own error quotes the value (part of it for a bad escape), which can
// be a credential pasted by mistake. Each row runs in a child process: the SDK reads the resource
// settings once per process, and the check covers the child's stderr.
func TestAnSDKSettingOTELRejectsIsLoggedByNameWithoutItsValue(t *testing.T) {
	if rerun.Child() {
		log := slog.New(slog.NewTextHandler(os.Stdout, nil))
		if _, shutdown, err := Setup(context.Background(), os.Getenv, "test", log); err == nil {
			_ = shutdown(context.Background())
		}
		return
	}
	const secret = "s3cret-token"
	const samplerSettings = "OTEL_TRACES_SAMPLER or OTEL_TRACES_SAMPLER_ARG"
	for _, tc := range []struct {
		name      string
		env       []string
		notLogged string // the part of the value that must reach neither the log nor stderr
		loggedAs  string // the setting the log names
	}{
		{"a resource attribute without '='", []string{"OTEL_RESOURCE_ATTRIBUTES=" + secret}, secret, "OTEL_RESOURCE_ATTRIBUTES"},
		// OTel's error quotes only the bad escape, so that is what must stay out.
		{"a resource attribute value that cannot be unescaped", []string{"OTEL_RESOURCE_ATTRIBUTES=k=%zz"}, "%zz", "OTEL_RESOURCE_ATTRIBUTES"},
		{"a sampler argument that is not a number", []string{"OTEL_TRACES_SAMPLER=traceidratio", "OTEL_TRACES_SAMPLER_ARG=" + secret}, secret, samplerSettings},
		{"a parent-based sampler argument that is not a number", []string{"OTEL_TRACES_SAMPLER=parentbased_traceidratio", "OTEL_TRACES_SAMPLER_ARG=" + secret}, secret, samplerSettings},
		// A ratio that parses but is out of range: OTel's error does not quote it, so the row pins the
		// name; notLogged guards a later OTel that would (1e9 cannot occur in a timestamp).
		{"a sampler ratio above 1", []string{"OTEL_TRACES_SAMPLER=traceidratio", "OTEL_TRACES_SAMPLER_ARG=1e9"}, "1e9", samplerSettings},
		{"a sampler OTel does not know", []string{"OTEL_TRACES_SAMPLER=" + secret}, secret, samplerSettings},
	} {
		t.Run(tc.name, func(t *testing.T) {
			clearOTELEnv(t)
			got := rerun.Run(t, "TestAnSDKSettingOTELRejectsIsLoggedByNameWithoutItsValue", append(tc.env, "OTEL_TRACES_EXPORTER=console")...)
			if strings.Contains(got, tc.notLogged) {
				t.Fatalf("child output %q; want no %q from the setting's value", got, tc.notLogged)
			}
			want := `level=WARN msg="tracing error" error="invalid ` + tc.loggedAs + `"`
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
