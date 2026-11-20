package server

import (
	"context"
	"net/http"
	"path/filepath"
	"strings"
	"testing"

	"github.com/byward-dev/byward/internal/config"
	"github.com/byward-dev/byward/internal/doctor"
	"github.com/byward-dev/byward/internal/idp"
	"github.com/byward-dev/byward/internal/testutil/fakeidp"
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

// #458: doctor names a URL setting as its shape shows it, its query marked as left out, never the API
// key a query can hold; the identity assertion's aud is shown the same way (security invariant 2).
func TestDoctorNamesAURLSettingWithoutTheParts(t *testing.T) {
	const key = "S3CRET-api-key"
	t.Run("the upstream", func(t *testing.T) {
		cfg := loadConfig(t, "https://mcp.example.com/mcp", "BYWARD_UPSTREAM_URL=https://up.example/mcp?api_key="+key)
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
			r := diagnoseDiscovery(context.Background(), tc.p, loadOIDC(t, "oidc", issuer, "app").ShownIssuer(), false)
			if len(r) != 1 || r[0].Message != tc.want {
				t.Errorf("results %+v, want one saying %q", r, tc.want)
			}
		})
	}
	// Through the wiring: doctor hands discovery the issuer as its shape shows it, never as given.
	t.Run("doctor's discovery line", func(t *testing.T) {
		app := fakeidp.Client{ID: fakeidp.NewGUID(), Secrets: []string{"s3cret"}}
		fake := fakeidp.New(t, fakeidp.Generic, fakeidp.WithClient(app))
		rep, err := Doctor(context.Background(), loadOIDC(t, "oidc", fake.Issuer()+"/x;k="+key, app.ID), DoctorOptions{IdP: fake.HTTPClient(), Proxy: &http.Client{Transport: refuse{}}})
		if err != nil {
			t.Fatal(err)
		}
		var discovery []doctor.Result
		for _, r := range rep.Checks {
			if r.Name == "discovery" {
				discovery = append(discovery, r)
			}
		}
		if len(discovery) != 1 || !strings.Contains(discovery[0].Message, fake.Issuer()+"/x;…") || strings.Contains(discovery[0].Message+discovery[0].Fix, key) {
			t.Errorf("discovery %+v, want one naming the issuer as %s/x;… and never its key", discovery, fake.Issuer())
		}
	})
}
