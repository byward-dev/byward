package server

import (
	"crypto/tls"
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
// endpoints, metadata, the MCP endpoint and refusals alike, whether TLS ends at byward or at an
// ingress. With a --dev http public URL none does, even for a request that claims https, and the
// internal listener never does: the public URL decides, never the request.
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
		tls             bool   // the request reaches byward over TLS
		forwardedProto  string // the X-Forwarded-Proto the request carries
		want            []string
	}{
		{"https, TLS at byward", "https://m.example/mcp", nil, true, "", []string{"max-age=31536000"}},
		{"https, TLS at an ingress", "https://m.example/mcp", nil, false, "http", []string{"max-age=31536000"}},
		{"--dev over http", "http://127.0.0.1:8080/mcp", []string{"BYWARD_DEV=true"}, false, "", nil},
		{"--dev over http, a request claiming https", "http://127.0.0.1:8080/mcp", []string{"BYWARD_DEV=true"}, true, "https", nil},
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
				if !mode.tls {
					req.TLS = nil
				} else if req.TLS == nil {
					req.TLS = &tls.ConnectionState{}
				}
				if mode.forwardedProto != "" {
					req.Header.Set("X-Forwarded-Proto", mode.forwardedProto)
				}
				if a.host != "" {
					req.Host = a.host
				}
				rec := httptest.NewRecorder()
				srv.Public.Handler.ServeHTTP(rec, req)
				res := rec.Result() // what was sent, not the header map as it is afterwards
				if got := res.Header.Values("Strict-Transport-Security"); res.StatusCode != a.status || !slices.Equal(got, mode.want) {
					t.Fatalf("%s %s: status %d, Strict-Transport-Security %q; want %d and %q", a.method, a.path, res.StatusCode, got, a.status, mode.want)
				}
			})
		}
		t.Run(mode.name+"/the internal listener", func(t *testing.T) {
			for _, path := range []string{"/metrics", "/livez"} {
				rec := httptest.NewRecorder()
				srv.Internal.Handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "http://127.0.0.1:9090"+path, nil))
				if res := rec.Result(); res.StatusCode != http.StatusOK || res.Header.Get("Strict-Transport-Security") != "" {
					t.Errorf("internal %s: status %d, Strict-Transport-Security %q; want 200 and none", path, res.StatusCode, res.Header.Get("Strict-Transport-Security"))
				}
			}
		})
	}
}
