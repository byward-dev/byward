package metrics

import (
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"
)

// Set BYWARD_UPDATE_GOLDEN=1 to rewrite testdata/names.golden after an intended change.
const golden = "testdata/names.golden"

func scrape(t *testing.T, m *Metrics) string {
	t.Helper()
	w := httptest.NewRecorder()
	m.Handler().ServeHTTP(w, httptest.NewRequest("GET", "/metrics", nil))
	if w.Code != 200 {
		t.Fatalf("scrape status %d", w.Code)
	}
	return w.Body.String()
}

// exercise touches every labelled metric so it appears in a scrape.
func exercise(m *Metrics) {
	h := m.Middleware(func(*http.Request) string { return "mcp" }, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(401) }))
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("POST", "/mcp?user=alice", nil))
	m.IdP("entra", "callback", "success", 120*time.Millisecond)
	m.IdPAlert("entra", "callback", "credential_rejected")
	m.InFlight("request", 1)
	m.Busy("stream")
	m.AuditEvent("login", "success")
	m.RateLimited("authorize")
	m.StdioProcesses(func() int { return 2 })
	m.CIMDFetch("ok")
	m.DCRRegistration("registered")
	m.Consent("verified", "remembered")
	m.Downstream("issued")
	m.AppToken("accepted")
	m.UpstreamRefused(403)
}

// Every family except the Go runtime's own collectors: a metric with the wrong prefix must reach the
// golden file, not be filtered out by the prefix it should carry.
var proxyMetric = regexp.MustCompile(`(?m)^# TYPE (\S+) (\S+)$`)

func isRuntimeMetric(name string) bool {
	return strings.HasPrefix(name, "go_") || strings.HasPrefix(name, "process_") || strings.HasPrefix(name, "promhttp_")
}

func TestMetricNamesMatchTheGoldenFile(t *testing.T) {
	m := New()
	exercise(m)
	var lines []string
	for _, g := range proxyMetric.FindAllStringSubmatch(scrape(t, m), -1) {
		if isRuntimeMetric(g[1]) {
			continue
		}
		if !strings.HasPrefix(g[1], "byward_") {
			t.Errorf("metric %s lacks the byward_ prefix (ADR-0028)", g[1])
		}
		lines = append(lines, g[1]+" "+g[2])
	}
	sort.Strings(lines)
	got := strings.Join(lines, "\n") + "\n"
	if os.Getenv("BYWARD_UPDATE_GOLDEN") == "1" {
		if err := os.WriteFile(golden, []byte(got), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(golden)
	if err != nil {
		t.Fatal(err)
	}
	if got != string(want) {
		t.Fatalf("metric names changed (public interface, ADR-0023); if intended, rerun with BYWARD_UPDATE_GOLDEN=1 and update docs/reference/observability.md\ngot:\n%s\nwant:\n%s", got, want)
	}
}

func TestEveryMetricHasADocsRow(t *testing.T) {
	docs, err := os.ReadFile("../../docs/reference/observability.md")
	if err != nil {
		t.Fatal(err)
	}
	want, err := os.ReadFile(golden)
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Fields(string(want)) {
		if strings.HasPrefix(line, "byward_") && !strings.Contains(string(docs), "`"+line+"`") {
			t.Errorf("metric %s is not documented in docs/reference/observability.md", line)
		}
	}
}

func TestLabelsCarryOnlyFixedValuesAndBucketsAreFixed(t *testing.T) {
	m := New()
	exercise(m)
	out := scrape(t, m)
	for _, leak := range []string{"alice", "/mcp", "user="} {
		if strings.Contains(out, leak) {
			t.Fatalf("a request detail %q reached a label: %s", leak, out)
		}
	}
	for _, le := range []string{`le="0.05"`, `le="0.1"`, `le="0.25"`, `le="0.5"`, `le="1"`, `le="2.5"`, `le="5"`, `le="10"`, `le="+Inf"`} {
		if !strings.Contains(out, `byward_http_request_duration_seconds_bucket{route="mcp",status_class="4xx",`+le+`}`) {
			t.Fatalf("bucket %s missing: %s", le, out)
		}
	}
}

func TestNilMetricsIsSafeToCall(t *testing.T) {
	var m *Metrics
	next := http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})
	if h := m.Middleware(nil, next); h == nil {
		t.Fatal("nil Metrics.Middleware must return the next handler, got nil")
	}
	m.IdP("entra", "callback", "success", time.Second)
	m.IdPAlert("entra", "callback", "credential_rejected")
	m.SeedIdPAlerts("entra", []string{"callback"}, []string{"protocol"})
	m.InFlight("request", 1)
	m.Busy("request")
	m.AuditEvent("login", "success")
	m.RateLimited("authorize")
	m.CIMDFetch("ok")
	m.DCRRegistration("registered")
	m.Consent("verified", "remembered")
	m.Downstream("issued")
	m.AppToken("accepted")
	m.UpstreamRefused(401)
}

// #204: seeding exports each given operation and reason of the IdP at 0, and nothing else, so an
// increase() rule sees the first alert after a start.
func TestAnIdPsAlertSeriesAreExportedAtZeroBeforeAnyAlert(t *testing.T) {
	m := New()
	m.SeedIdPAlerts("entra", []string{"callback", "refresh"}, []string{"credential_rejected", "protocol"})
	body := scrape(t, m)
	for _, op := range []string{"callback", "refresh"} {
		for _, reason := range []string{"credential_rejected", "protocol"} {
			if s := `byward_idp_alerts_total{idp="entra",operation="` + op + `",reason="` + reason + `"} 0`; !strings.Contains(body, s) {
				t.Errorf("%s is not exported:\n%s", s, body)
			}
		}
	}
	if n := strings.Count(body, "byward_idp_alerts_total{"); n != 4 {
		t.Errorf("%d alert series exported, want the 4 seeded:\n%s", n, body)
	}
}

// Upstream refusals are counted by status, and both statuses are exported at 0 before the first,
// so an increase() alert sees it.
func TestUpstreamRefusalsAreCountedByStatusFromZero(t *testing.T) {
	m := New()
	before := scrape(t, m)
	for _, want := range []string{`byward_upstream_refusals_total{status="401"} 0`, `byward_upstream_refusals_total{status="403"} 0`} {
		if !strings.Contains(before, want) {
			t.Fatalf("before any refusal, want %s in\n%s", want, before)
		}
	}
	m.UpstreamRefused(403)
	m.UpstreamRefused(403)
	after := scrape(t, m)
	for _, want := range []string{`byward_upstream_refusals_total{status="401"} 0`, `byward_upstream_refusals_total{status="403"} 2`} {
		if !strings.Contains(after, want) {
			t.Fatalf("after two 403s, want %s in\n%s", want, after)
		}
	}
}
