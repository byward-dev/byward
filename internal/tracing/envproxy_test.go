package tracing

import (
	"context"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"

	"go.opentelemetry.io/otel"

	"github.com/byward-dev/byward/internal/testutil/rerun"
)

// Trace export reads the environment's proxy (once per process, so the check runs in a child
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
			rerun.EachProxySetting(t, "TestAFailedTraceExportNeverQuotesAMisreadEnvironmentProxy", func(t *testing.T, got, addr string, misread bool) {
				if !strings.Contains(got, "tracing error") {
					t.Fatalf("child output %q; want the failed export in the log", got)
				}
				rerun.CauseOnlyIfMisread(t, got, addr, misread)
			})
		})
	}
}

// The collector's proxy is judged by the endpoint OTLP uses (the traces one before the general one,
// a bare host:port as its host) under both schemes, since the grpc exporter always asks for an https
// one; with no endpoint the collector is on localhost and no proxy is asked for.
func TestTheCollectorsProxyIsJudgedForTheConfiguredEndpointUnderEitherScheme(t *testing.T) {
	misread := &url.URL{Scheme: "http", Host: "127.0.0.1:1", Path: "/pw-secret@egress.example:3128"}
	wellFormed := &url.URL{Scheme: "http", Host: "egress.example:3128"}
	for _, tc := range []struct {
		name            string
		traces, general string
		proxies         map[string]*url.URL // by the request's scheme
		wantHost        string              // the host the proxy is asked for; "" when it is never asked
		want            bool
	}{
		{"no endpoint: the collector is on localhost", "", "", map[string]*url.URL{"http": misread, "https": misread}, "", false},
		{"a misread setting for http", "", "http://collector.example:4318", map[string]*url.URL{"http": misread}, "collector.example:4318", true},
		{"a misread setting for https alone, as grpc asks", "", "http://collector.example:4317", map[string]*url.URL{"https": misread}, "collector.example:4317", true},
		{"well-formed settings", "", "http://collector.example:4318", map[string]*url.URL{"http": wellFormed, "https": wellFormed}, "collector.example:4318", false},
		{"no proxy for the collector (NO_PROXY)", "", "http://collector.example:4318", nil, "collector.example:4318", false},
		{"the traces endpoint before the general one", "http://traces.example:4318", "http://collector.example:4318", map[string]*url.URL{"http": misread}, "traces.example:4318", true},
		{"a bare host:port", "", "collector.example:4317", map[string]*url.URL{"https": misread}, "collector.example:4317", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			env := map[string]string{"OTEL_EXPORTER_OTLP_TRACES_ENDPOINT": tc.traces, "OTEL_EXPORTER_OTLP_ENDPOINT": tc.general}
			var hosts []string
			proxy := func(r *http.Request) (*url.URL, error) {
				hosts = append(hosts, r.URL.Host)
				return tc.proxies[r.URL.Scheme], nil
			}
			if got := collectorProxyMisread(func(k string) string { return env[k] }, proxy); got != tc.want {
				t.Fatalf("misread = %v; want %v", got, tc.want)
			}
			for _, h := range hosts {
				if h != tc.wantHost {
					t.Fatalf("the proxy was asked for %q; want %q", h, tc.wantHost)
				}
			}
			if (len(hosts) == 0) != (tc.wantHost == "") {
				t.Fatalf("the proxy was asked for %q; want it asked for %q", hosts, tc.wantHost)
			}
		})
	}
}
