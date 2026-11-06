package origin

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
)

var ok = http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })

func quiet() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func TestHosts(t *testing.T) {
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

func TestOrigins(t *testing.T) {
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
