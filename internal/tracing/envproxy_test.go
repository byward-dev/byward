package tracing

import (
	"context"
	"log/slog"
	"maps"
	"net/http"
	"net/url"
	"os"
	"slices"
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
	for _, tc := range []struct{ protocol, endpoint string }{
		{"http/protobuf", "http://collector.example:4318"},
		{"grpc", "http://collector.example:4317"},
	} {
		t.Run(tc.protocol, func(t *testing.T) {
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

// The environment proxy for the collector is judged for every endpoint the settings name (trimmed,
// a bare host:port as its host), since the exporter may fall back from one to the other, and under
// both schemes, since the grpc exporter always asks for an https one; with no endpoint the collector
// is on localhost and no proxy is asked for.
func TestTheCollectorsEnvironmentProxyIsJudgedForEveryConfiguredEndpointUnderEitherScheme(t *testing.T) {
	misread := &url.URL{Scheme: "http", Host: "127.0.0.1:1", Path: "/pw-secret@egress.example:3128"}
	wellFormed := &url.URL{Scheme: "http", Host: "egress.example:3128"}
	for _, tc := range []struct {
		name            string
		traces, general string
		proxies         map[string]*url.URL // by the request's scheme://host; none for a host not listed
		asked           []string            // the hosts the proxy is asked for
		want            bool
	}{
		{"no endpoint: the collector is on localhost", "", "", nil, nil, false},
		{"a misread setting for http", "", "http://collector.example:4318",
			map[string]*url.URL{"http://collector.example:4318": misread}, []string{"collector.example:4318"}, true},
		{"a misread setting for https alone, as grpc asks", "", "http://collector.example:4317",
			map[string]*url.URL{"https://collector.example:4317": misread}, []string{"collector.example:4317"}, true},
		{"well-formed settings", "", "http://collector.example:4318",
			map[string]*url.URL{"http://collector.example:4318": wellFormed, "https://collector.example:4318": wellFormed}, []string{"collector.example:4318"}, false},
		{"NO_PROXY exempts the collector", "", "http://collector.example:4318", nil, []string{"collector.example:4318"}, false},
		{"a misread setting for the traces endpoint alone", "http://traces.example:4318", "http://collector.example:4318",
			map[string]*url.URL{"http://traces.example:4318": misread}, []string{"traces.example:4318"}, true},
		{"a misread setting for the general endpoint, which the exporter falls back to", "127.0.0.1:4318", "http://collector.example:4318",
			map[string]*url.URL{"http://collector.example:4318": misread}, []string{"127.0.0.1:4318", "collector.example:4318"}, true},
		{"a bare host:port", "", "collector.example:4317",
			map[string]*url.URL{"https://collector.example:4317": misread}, []string{"collector.example:4317"}, true},
		{"an endpoint with spaces around it", "", " http://collector.example:4318 ",
			map[string]*url.URL{"http://collector.example:4318": misread}, []string{"collector.example:4318"}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			env := map[string]string{"OTEL_EXPORTER_OTLP_TRACES_ENDPOINT": tc.traces, "OTEL_EXPORTER_OTLP_ENDPOINT": tc.general}
			asked := map[string]bool{}
			proxy := func(r *http.Request) (*url.URL, error) {
				asked[r.URL.Host] = true
				return tc.proxies[r.URL.Scheme+"://"+r.URL.Host], nil
			}
			if got := collectorProxyMisread(func(k string) string { return env[k] }, proxy); got != tc.want {
				t.Fatalf("misread = %v; want %v", got, tc.want)
			}
			if got := slices.Sorted(maps.Keys(asked)); !slices.Equal(got, slices.Sorted(slices.Values(tc.asked))) {
				t.Fatalf("the proxy was asked for %q; want %q", got, tc.asked)
			}
		})
	}
}
