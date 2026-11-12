package server

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"testing"

	"github.com/byward-dev/byward/internal/logging"
)

// #225: with an https public URL every answer of the public listener carries
// Strict-Transport-Security, max-age one year and no includeSubDomains or preload: pages, OAuth
// endpoints, metadata, the MCP endpoint and refusals alike. With a --dev http public URL none does,
// and the internal listener never does.
func TestEveryPublicAnswerCarriesHSTSWhenThePublicURLIsHTTPS(t *testing.T) {
	answers := []struct {
		name, method, path, host string
		contentType, body        string
		status                   int
	}{
		{"a page", http.MethodGet, "/authorize?client_id=unknown", "", "", "", http.StatusBadRequest},
		{"an OAuth endpoint", http.MethodPost, "/token", "", "application/x-www-form-urlencoded", "grant_type=authorization_code", http.StatusUnauthorized},
		{"protected-resource metadata", http.MethodGet, "/.well-known/oauth-protected-resource/mcp", "", "", "", http.StatusOK},
		{"authorization-server metadata", http.MethodGet, "/.well-known/oauth-authorization-server", "", "", "", http.StatusOK},
		{"the MCP endpoint", http.MethodPost, "/mcp", "", "application/json", `{"jsonrpc":"2.0","id":1,"method":"ping"}`, http.StatusUnauthorized},
		{"an unknown path", http.MethodGet, "/nope", "", "", "", http.StatusNotFound},
		{"a refused host", http.MethodGet, "/mcp", "evil.example", "", "", http.StatusMisdirectedRequest},
	}
	for _, mode := range []struct {
		name, publicURL string
		extra           []string
		want            []string
	}{
		{"https", "https://m.example/mcp", nil, []string{"max-age=31536000"}},
		{"--dev over http", "http://127.0.0.1:8080/mcp", []string{"BYWARD_DEV=true"}, nil},
	} {
		srv, err := New(loadConfig(t, mode.publicURL, mode.extra...), logging.New(io.Discard, "json"))
		if err != nil {
			t.Fatal(err)
		}
		public, _ := url.Parse(mode.publicURL)
		for _, a := range answers {
			t.Run(mode.name+"/"+a.name, func(t *testing.T) {
				req := httptest.NewRequest(a.method, mode.publicURL[:len(mode.publicURL)-len(public.Path)]+a.path, strings.NewReader(a.body))
				if a.contentType != "" {
					req.Header.Set("Content-Type", a.contentType)
				}
				if a.host != "" {
					req.Host = a.host
				}
				rec := httptest.NewRecorder()
				srv.Public.Handler.ServeHTTP(rec, req)
				if got := rec.Header().Values("Strict-Transport-Security"); rec.Code != a.status || !slices.Equal(got, mode.want) {
					t.Fatalf("%s %s: status %d, Strict-Transport-Security %q; want %d and %q", a.method, a.path, rec.Code, got, a.status, mode.want)
				}
			})
		}
		t.Run(mode.name+"/the internal listener", func(t *testing.T) {
			for _, path := range []string{"/metrics", "/livez"} {
				rec := httptest.NewRecorder()
				srv.Internal.Handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "http://127.0.0.1:9090"+path, nil))
				if rec.Code != http.StatusOK || rec.Header().Get("Strict-Transport-Security") != "" {
					t.Errorf("internal %s: status %d, Strict-Transport-Security %q; want 200 and none", path, rec.Code, rec.Header().Get("Strict-Transport-Security"))
				}
			}
		})
	}
}
