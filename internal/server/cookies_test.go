package server

import (
	"os"
	"testing"

	"github.com/byward-dev/byward/internal/config"
)

// The broker is wired for __Host- and Secure cookies exactly when the public URL is https; over the
// http loopback URL --dev accepts it is not, or a browser would drop them (#355's audit of what
// --dev relaxes: the "http public URL on loopback" relaxation covers this). The broker's own tests
// pin what SecureCookies does to each cookie.
func TestCookiesAreSecureOnlyOverAnHTTPSPublicURL(t *testing.T) {
	for _, tc := range []struct {
		name, publicURL string
		dev, secure     bool
	}{
		{"https", "https://mcp.example.com/mcp", false, true},
		{"https with --dev", "https://mcp.example.com/mcp", true, true}, // the scheme decides, not --dev
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
			got := captureBroker(t, nil)
			a, err := buildAuth(cfg, discard, Observability{})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { stop(t, a) })
			if got.SecureCookies != tc.secure {
				t.Fatalf("SecureCookies %v, want %v", got.SecureCookies, tc.secure)
			}
		})
	}
}
