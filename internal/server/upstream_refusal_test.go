package server

import (
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/byward-dev/byward/internal/metrics"
)

// An upstream refusal is counted by status, through the relay that asserts the signed-in user's
// identity: the client gets the readable refusal, and the counter rises from its seeded 0.
func TestAnUpstreamRefusalIsCountedWithTheIdentityAssertion(t *testing.T) {
	e := newOBOEnv(t, "")
	if m := e.metrics(); !strings.Contains(m, `byward_upstream_refusals_total{status="403"} 0`) {
		t.Fatalf("before any refusal, the 403 series is not at 0:\n%s", m)
	}
	access := e.signIn(t)["access_token"].(string)
	e.mu.Lock()
	e.refuseWith = http.StatusForbidden
	e.mu.Unlock()
	if status, body := e.mcp(t, access, oboToolsCall, nil); status != http.StatusOK || !strings.Contains(body, "denied this request") {
		t.Fatalf("got %d %s, want the readable refusal", status, body)
	}
	m := e.metrics()
	for _, want := range []string{`byward_upstream_refusals_total{status="403"} 1`, `byward_upstream_refusals_total{status="401"} 0`} {
		if !strings.Contains(m, want) {
			t.Errorf("metrics lack %s", want)
		}
	}
}

// Without authentication the relay has no assertion to add, and still counts each refusal.
func TestAnUpstreamRefusalIsCountedWithoutAuthentication(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusUnauthorized) }))
	t.Cleanup(up.Close)
	cfg := loadConfig(t, "https://mcp.example.com/mcp", "BYWARD_UPSTREAM_URL="+up.URL+"/mcp")
	m := metrics.New()
	u, err := newUpstream(cfg, slog.New(slog.DiscardHandler), Observability{Metrics: m}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	answer := httptest.NewRecorder()
	u.handler.ServeHTTP(answer, httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`)))
	if answer.Code != http.StatusOK || !strings.Contains(answer.Body.String(), "rejected the proxy's credentials") {
		t.Fatalf("got %d %s, want the readable refusal", answer.Code, answer.Body)
	}
	rec := httptest.NewRecorder()
	m.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	for _, want := range []string{`byward_upstream_refusals_total{status="401"} 1`, `byward_upstream_refusals_total{status="403"} 0`} {
		if !strings.Contains(rec.Body.String(), want) {
			t.Errorf("metrics lack %s:\n%s", want, rec.Body)
		}
	}
}
