package server

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/codes"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"

	"github.com/byward-dev/byward/internal/audit"
	"github.com/byward-dev/byward/internal/logging"
	"github.com/byward-dev/byward/internal/metrics"
	"github.com/byward-dev/byward/internal/shutdown"
	"github.com/byward-dev/byward/internal/testutil/fakeupstream"
	"github.com/byward-dev/byward/internal/testutil/logsink"
)

// spans sets an in-memory exporter as the global tracer provider for the test, whatever the OTEL_*
// environment: every span is sampled and no attribute is dropped.
func spans(t *testing.T) *tracetest.InMemoryExporter {
	t.Helper()
	prev := otel.GetTracerProvider()
	exp := tracetest.NewInMemoryExporter()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSyncer(exp), sdktrace.WithSampler(sdktrace.AlwaysSample()),
		sdktrace.WithRawSpanLimits(sdktrace.SpanLimits{AttributeValueLengthLimit: -1, AttributeCountLimit: -1,
			EventCountLimit: -1, LinkCountLimit: -1, AttributePerEventCountLimit: -1, AttributePerLinkCountLimit: -1}))
	otel.SetTracerProvider(tp)
	t.Cleanup(func() { _ = tp.Shutdown(context.Background()); otel.SetTracerProvider(prev) })
	return exp
}

// requestCounts is each byward_http_request_duration_seconds series' count, by its labels.
func requestCounts(scrape string) map[string]int {
	out := map[string]int{}
	for _, m := range regexp.MustCompile(`(?m)^byward_http_request_duration_seconds_count\{(.*)\} (\d+)$`).FindAllStringSubmatch(scrape, -1) {
		n, _ := strconv.Atoi(m[2])
		out[m[1]] = n
	}
	return out
}

// A relayed stream cut off after its headers is recorded through the whole chain, with the status it
// sent and its cause (#533): one request line with error_type, one observation of
// byward_http_request_duration_seconds with that error_type, and a span with error.type, an error
// only when the upstream broke off. The abort still reaches the server, which closes the connection;
// a client still there sees the stream break off, not end. Before #533 such a stream had no request
// line, no metric and a span with no status code.
func TestAStreamCutOffAfterItsHeadersRecordsTheStatusItSentAndWhyThroughTheWholeChain(t *testing.T) {
	const event = "data: one\n\n"
	for _, tc := range []struct {
		name string
		cut  logging.CutOff
		// upstream writes after the first event: it holds the stream open until the relay's request
		// ends, or breaks off the connection.
		upstream func(w http.ResponseWriter, r *http.Request)
		// cutOff ends the stream once the client has the first event.
		cutOff    func(res *http.Response, shutDown func())
		wantError codes.Code
	}{
		{"its MCP client went away", logging.ClientClosed,
			func(_ http.ResponseWriter, r *http.Request) { <-r.Context().Done() },
			func(res *http.Response, _ func()) { _ = res.Body.Close() },
			codes.Unset},
		{"the proxy shut down", logging.ShutDown,
			func(_ http.ResponseWriter, r *http.Request) { <-r.Context().Done() },
			func(_ *http.Response, shutDown func()) { shutDown() },
			codes.Unset},
		{"its upstream broke off", logging.UpstreamAborted,
			func(w http.ResponseWriter, _ *http.Request) {
				c, _, err := http.NewResponseController(w).Hijack()
				if err == nil {
					_ = c.Close() // the chunked body ends with no last chunk
				}
			},
			func(*http.Response, func()) {},
			codes.Error},
	} {
		t.Run(tc.name, func(t *testing.T) {
			exp := spans(t)
			up := fakeupstream.New()
			t.Cleanup(up.Close)
			up.Handler = func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "text/event-stream")
				_, _ = io.WriteString(w, event)
				w.(http.Flusher).Flush()
				tc.upstream(w, r)
			}
			cfg := loadConfig(t, "https://mcp.example.com/mcp", "BYWARD_UPSTREAM_URL="+up.URL+"/mcp")
			logs := &logsink.Buffer{}
			log := logging.New(logs, "json")
			m := metrics.New()
			srv := httptest.NewUnstartedServer(Handler(cfg, log, httpUpstream(cfg, log), acceptGood{}, nil, nil,
				Observability{Audit: audit.New(log, nil, time.Now), Metrics: m}))
			// As serve does, so a request can tell the proxy shutting down from its client going away.
			base, shutDown := shutdown.WithCancel(context.Background())
			t.Cleanup(shutDown)
			srv.Config.BaseContext = func(net.Listener) context.Context { return base }
			var mu sync.Mutex
			var states []http.ConnState
			srv.Config.ConnState = func(_ net.Conn, s http.ConnState) { mu.Lock(); states = append(states, s); mu.Unlock() }
			srv.Start()
			t.Cleanup(srv.Close)

			r, _ := http.NewRequest(http.MethodGet, srv.URL+"/mcp", nil)
			r.Host = "mcp.example.com"
			r.Header.Set("Authorization", "Bearer "+goodToken)
			r.Header.Set("Accept", "text/event-stream")
			res, err := srv.Client().Do(r)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = res.Body.Close() })
			body := bufio.NewReader(res.Body)
			first := make([]byte, len(event))
			if _, err := io.ReadFull(body, first); err != nil || res.StatusCode != http.StatusOK || string(first) != event {
				t.Fatalf("status %d, first event %q, error %v; want the stream's first event", res.StatusCode, first, err)
			}
			tc.cutOff(res, shutDown)
			if tc.cut != logging.ClientClosed { // a client still there sees the stream break off, not end
				if _, err := io.Copy(io.Discard, body); !errors.Is(err, io.ErrUnexpectedEOF) {
					t.Fatalf("the rest of the stream read with error %v; want %v, a stream the server aborted", err, io.ErrUnexpectedEOF)
				}
			}

			// The request line: the one sure sign the handler has ended.
			var lines []map[string]any
			for deadline := time.Now().Add(10 * time.Second); ; time.Sleep(10 * time.Millisecond) {
				lines = lines[:0]
				for l := range strings.Lines(logs.String()) {
					var v map[string]any
					if json.Unmarshal([]byte(l), &v) == nil && v["msg"] == "request" {
						lines = append(lines, v)
					}
				}
				if len(lines) > 0 || time.Now().After(deadline) {
					break
				}
			}
			if len(lines) != 1 || lines[0]["status"] != float64(http.StatusOK) || lines[0]["error_type"] != string(tc.cut) {
				t.Fatalf("request lines %v; want one, status 200 with error_type %q; log %s", lines, tc.cut, logs)
			}

			counts := requestCounts(scrapeMetrics(t, m))
			want := `error_type="` + string(tc.cut) + `",route="/mcp",status_class="2xx"`
			if len(counts) != 1 || counts[want] != 1 {
				t.Errorf("request observations %v; want one, %s", counts, want)
			}

			got := exp.GetSpans()
			if len(got) != 1 {
				t.Fatalf("%d spans; want 1", len(got))
			}
			attrs := map[string]string{}
			for _, kv := range got[0].Attributes {
				attrs[string(kv.Key)] = kv.Value.String()
			}
			if attrs["http.response.status_code"] != "200" || attrs["error.type"] != string(tc.cut) || got[0].Status.Code != tc.wantError {
				t.Errorf("span status %v, attributes %v; want status %v, http.response.status_code 200 and error.type %q",
					got[0].Status.Code, attrs, tc.wantError, tc.cut)
			}

			// The abort reached the server: it closed the connection, which never went back to idle.
			for deadline := time.Now().Add(10 * time.Second); ; time.Sleep(10 * time.Millisecond) {
				mu.Lock()
				s := append([]http.ConnState(nil), states...)
				mu.Unlock()
				if strings.Contains(stateNames(s), "closed") || time.Now().After(deadline) {
					if want := "new active closed"; stateNames(s) != want {
						t.Errorf("connection states %q; want %q", stateNames(s), want)
					}
					break
				}
			}
		})
	}
}

func stateNames(s []http.ConnState) string {
	names := make([]string, len(s))
	for i, c := range s {
		names[i] = c.String()
	}
	return strings.Join(names, " ")
}
