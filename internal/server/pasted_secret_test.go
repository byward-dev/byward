package server

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/byward-dev/byward/internal/config"
	"github.com/byward-dev/byward/internal/idp"
)

// #461: a secret file the proxy checks at startup, check and doctor, but that cannot be found, is
// named by its setting and the cause, never its path, which is the secret when one was pasted where
// the path belongs (an absolute one passes config's path check).
func TestAMissingSecretFileIsNamedWithoutItsPath(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "eyJS3CRETjwt")
	for _, tc := range []struct {
		name string
		cfg  *config.Config
		want string
	}{
		{"the federated token", &config.Config{EntraFederatedTokenFile: missing, Values: &config.Values{}}, "BYWARD_ENTRA_FEDERATED_TOKEN_FILE: no such file or directory"},
		{"the TLS key", &config.Config{TLSKeyFile: missing, Values: &config.Values{}}, "BYWARD_TLS_KEY_FILE: no such file or directory"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if errs := looseSecretFiles(tc.cfg); len(errs) != 1 || errs[0].Error() != tc.want {
				t.Fatalf("errors %v, want only %q", errs, tc.want)
			}
		})
	}
}

// readyDiscovery is an IdP whose discovery succeeds.
type readyDiscovery struct{}

func (readyDiscovery) Ready(context.Context) error { return nil }

// #458: doctor names a URL setting as logs may show it, its query marked as left out, never the API
// key a query can hold; the identity assertion's aud is shown the same way (security invariant 2).
func TestDoctorNamesAURLSettingWithoutItsQuery(t *testing.T) {
	const key = "S3CRET-api-key"
	t.Run("the upstream", func(t *testing.T) {
		cfg := &config.Config{UpstreamURL: mustURL(t, "https://up.example/mcp?api_key="+key), AssertionHeader: "Authorization"}
		want := "HTTP upstream https://up.example/mcp?…; doctor checks the proxy in front of it, not the upstream itself; " +
			"requests carry the identity assertion in Authorization, with aud https://up.example/mcp?…"
		if got := upstreamResult(cfg, noProxy).Message; got != want {
			t.Errorf("doctor says %q, want %q", got, want)
		}
	})
	const issuer = "https://idp.example/realms/acme;k=" + key // config refuses a query or fragment, not path parameters
	for _, tc := range []struct {
		name string
		p    idp.Readiness
		want string
	}{
		{"discovery that works", readyDiscovery{}, "discovery at https://idp.example/realms/acme;… matches the configured issuer"},
		{"discovery that fails", failingDiscovery{}, "the IdP's discovery document at https://idp.example/realms/acme;… failed: connection refused"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := diagnoseDiscovery(context.Background(), tc.p, issuer, false)
			if len(r) != 1 || r[0].Message != tc.want {
				t.Errorf("results %+v, want one saying %q", r, tc.want)
			}
		})
	}
}
