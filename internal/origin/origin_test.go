package origin

import (
	"time"

	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/byward-dev/byward/internal/audit"
)

var ok = http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })

func quiet() *audit.Log {
	return audit.New(slog.New(slog.NewTextHandler(io.Discard, nil)), nil, time.Now)
}

func TestHostOutsideAllowlistGets421(t *testing.T) {
	h := Hosts(quiet(), []string{"mcp.example.com", "internal:8080"}, ok)
	cases := map[string]int{
		"mcp.example.com":     http.StatusNoContent,
		"MCP.Example.com":     http.StatusNoContent,
		"mcp.example.com:443": http.StatusNoContent,
		"internal:8080":       http.StatusNoContent,
		"internal":            http.StatusMisdirectedRequest,
		"evil.example":        http.StatusMisdirectedRequest,
		"mcp.example.com:444": http.StatusMisdirectedRequest,
		"":                    http.StatusMisdirectedRequest,
	}
	for host, want := range cases {
		r := httptest.NewRequest("GET", "/", nil)
		r.Host = host
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != want {
			t.Errorf("host %q: got %d want %d", host, w.Code, want)
		}
	}
}

func TestInternalListenerAcceptsAddressesAndListedNamesOnly(t *testing.T) {
	h := InternalHosts(quiet(), []string{"byward-metrics.monitoring.svc:8080"}, ok)
	cases := map[string]int{
		"127.0.0.1:9090":                     http.StatusNoContent,
		"10.244.1.17:9090":                   http.StatusNoContent, // kubelet and Prometheus use the pod IP
		"[::1]:9090":                         http.StatusNoContent,
		"[fd00::17]":                         http.StatusNoContent,
		"localhost:9090":                     http.StatusNoContent,
		"LOCALHOST":                          http.StatusNoContent,
		"byward-metrics.monitoring.svc:9090": http.StatusNoContent, // listed name, any port
		"rebind.attacker.example:9090":       http.StatusMisdirectedRequest,
		"localhost.attacker.example":         http.StatusMisdirectedRequest,
		"127.0.0.1.nip.io:9090":              http.StatusMisdirectedRequest,
		"":                                   http.StatusMisdirectedRequest,
	}
	for host, want := range cases {
		r := httptest.NewRequest("GET", "/metrics", nil)
		r.Host = host
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != want {
			t.Errorf("host %q: got %d want %d", host, w.Code, want)
		}
	}
}

func TestOriginOutsideAllowlistGets403(t *testing.T) {
	h := Origins(quiet(), []string{"https://app.example"}, ok)
	cases := []struct {
		name    string
		origins []string
		want    int
	}{
		{"missing passes", nil, http.StatusNoContent},
		{"allowed", []string{"https://app.example"}, http.StatusNoContent},
		{"case-insensitive", []string{"HTTPS://APP.EXAMPLE"}, http.StatusNoContent},
		{"other origin", []string{"https://evil.example"}, http.StatusForbidden},
		{"other port", []string{"https://app.example:8443"}, http.StatusForbidden},
		{"other scheme", []string{"http://app.example"}, http.StatusForbidden},
		{"null", []string{"null"}, http.StatusForbidden},
		{"multiple", []string{"https://app.example", "https://app.example"}, http.StatusForbidden},
	}
	for _, c := range cases {
		r := httptest.NewRequest("POST", "/mcp", nil)
		for _, o := range c.origins {
			r.Header.Add("Origin", o)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != c.want {
			t.Errorf("%s: got %d want %d", c.name, w.Code, c.want)
		}
	}
}

func TestEmptyOriginAllowlistRejectsBrowsers(t *testing.T) {
	h := Origins(quiet(), nil, ok)
	r := httptest.NewRequest("POST", "/mcp", nil)
	r.Header.Set("Origin", "http://localhost:6274")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusForbidden {
		t.Fatalf("got %d", w.Code)
	}
}

func TestListedOriginGetsCORSAndPreflight(t *testing.T) {
	reached := false
	h := Origins(quiet(), []string{"https://app.example"}, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		reached = true
		w.WriteHeader(http.StatusUnauthorized)
	}))
	r := httptest.NewRequest("OPTIONS", "/mcp", nil)
	r.Header.Set("Origin", "https://app.example")
	r.Header.Set("Access-Control-Request-Method", "POST")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusNoContent || reached || w.Header().Get("Access-Control-Allow-Origin") != "https://app.example" ||
		w.Header().Get("Access-Control-Allow-Credentials") != "" || !strings.Contains(w.Header().Get("Access-Control-Allow-Headers"), "Authorization") {
		t.Fatalf("preflight: code=%d reached=%v headers=%v", w.Code, reached, w.Header())
	}
	r = httptest.NewRequest("POST", "/mcp", nil)
	r.Header.Set("Origin", "https://app.example")
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if !reached || !strings.Contains(w.Header().Get("Access-Control-Expose-Headers"), "WWW-Authenticate") || w.Header().Get("Access-Control-Allow-Origin") != "https://app.example" {
		t.Fatalf("actual request: headers=%v", w.Header())
	}
}

func TestNoCORSWithoutOrigin(t *testing.T) {
	w := httptest.NewRecorder()
	Origins(quiet(), []string{"https://app.example"}, ok).ServeHTTP(w, httptest.NewRequest("OPTIONS", "/mcp", nil))
	if w.Header().Get("Access-Control-Allow-Origin") != "" {
		t.Fatal("CORS headers without an Origin")
	}
}

func TestOriginRejectionNamesTheFix(t *testing.T) {
	r := httptest.NewRequest("POST", "/mcp", nil)
	r.Header.Set("Origin", "https://evil.example")
	w := httptest.NewRecorder()
	Origins(quiet(), nil, ok).ServeHTTP(w, r)
	if w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "BYWARD_ALLOWED_ORIGINS") {
		t.Fatalf("got %d %q", w.Code, w.Body)
	}
}

func recording() (*audit.Log, *strings.Builder) {
	var b strings.Builder
	return audit.New(slog.New(slog.NewJSONHandler(&b, nil)), nil, time.Now), &b
}

func TestRejectionsAreAudited(t *testing.T) {
	rec, out := recording()
	hosts := Hosts(rec, []string{"mcp.example.com"}, ok)
	r := httptest.NewRequest("GET", "/mcp", nil)
	r.Host = "evil.example"
	hosts.ServeHTTP(httptest.NewRecorder(), r)
	origins := Origins(rec, []string{"https://app.example"}, ok)
	r = httptest.NewRequest("POST", "/mcp", nil)
	r.Header.Set("Origin", "https://evil.example")
	origins.ServeHTTP(httptest.NewRecorder(), r)
	for _, want := range []string{`"event":"host_rejected","outcome":"failure","host":"evil.example"`,
		`"event":"origin_rejected","outcome":"failure","origin":"https://evil.example"`} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("audit stream lacks %s:\n%s", want, out.String())
		}
	}
}

func TestAllowedRequestsAreNotAudited(t *testing.T) {
	rec, out := recording()
	r := httptest.NewRequest("POST", "/mcp", nil)
	r.Host = "mcp.example.com"
	r.Header.Set("Origin", "https://app.example")
	Hosts(rec, []string{"mcp.example.com"}, Origins(rec, []string{"https://app.example"}, ok)).ServeHTTP(httptest.NewRecorder(), r)
	if out.Len() != 0 {
		t.Fatalf("an allowed request produced audit records: %s", out.String())
	}
}
