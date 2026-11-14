package server

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"

	"github.com/byward-dev/byward/internal/config"
)

// The broker's cookies are __Host- and Secure exactly when the public URL is https; over the http
// loopback URL --dev accepts they are neither, or a browser would drop them (#355's audit of what
// --dev relaxes: the "http public URL on loopback" relaxation covers this).
func TestCookiesAreHostPrefixedAndSecureOnlyOverHTTPS(t *testing.T) {
	for _, tc := range []struct {
		name, publicURL string
		dev, secure     bool
	}{
		{"https", "https://mcp.example.com/mcp", false, true},
		{"http on loopback with --dev", "http://127.0.0.1:8080/mcp", true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			env := append(authEnv(t), "BYWARD_PUBLIC_URL="+tc.publicURL, "BYWARD_UPSTREAM_URL=http://u/mcp")
			if tc.dev {
				env = append(env, "BYWARD_DEV=true")
			}
			cfg, _, err := config.Load(nil, env, os.ReadFile)
			if err != nil {
				t.Fatal(err)
			}
			a, err := buildAuth(cfg, discard, Observability{})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { stop(t, a) })
			srv := httptest.NewServer(Handler(cfg, discard, httpUpstream(cfg, discard), a.validator, a.register, a.sessions, Observability{}))
			t.Cleanup(srv.Close)
			q := url.Values{"client_id": {"test-app"}, "redirect_uri": {"http://127.0.0.1/callback"}, "response_type": {"code"}, "scope": {"mcp"},
				"code_challenge": {pkce(strings.Repeat("v", 43))}, "code_challenge_method": {"S256"}}
			r, _ := http.NewRequest(http.MethodGet, srv.URL+"/authorize?"+q.Encode(), nil)
			r.Host = cfg.PublicURL.Host
			res, err := (&http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}).Do(r)
			if err != nil {
				t.Fatal(err)
			}
			_ = res.Body.Close()
			cookies := res.Cookies()
			if len(cookies) == 0 {
				t.Fatalf("authorize answered %d with no cookie; want the consent page's", res.StatusCode)
			}
			for _, c := range cookies {
				if strings.HasPrefix(c.Name, "__Host-") != tc.secure || c.Secure != tc.secure {
					t.Fatalf("cookie %s (Secure %v); want __Host- and Secure: %v", c.Name, c.Secure, tc.secure)
				}
			}
		})
	}
}
