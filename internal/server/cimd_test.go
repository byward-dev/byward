package server

import (
	"context"
	"errors"
	"io"
	"net/http/httptest"
	"os"
	"slices"
	"strings"
	"testing"

	"code.dny.dev/ssrf"

	"github.com/byward-dev/byward/internal/broker"
	"github.com/byward-dev/byward/internal/config"
	"github.com/byward-dev/byward/internal/logging"
	"github.com/byward-dev/byward/internal/registration"
)

// With CIMD on, document URLs reach the CIMD registry through the SSRF guard: a loopback URL is
// refused at dial, with no request leaving the process. With it off they are simply unknown.
func TestCIMDClientsAreResolvedThroughTheGuardOnlyWhenOn(t *testing.T) {
	const loopbackDoc = "https://127.0.0.1/client.json"
	for name, tc := range map[string]struct {
		env    []string
		on     bool
		reason string // in the lookup error; "" means the plain unknown-client error
	}{
		"on by default": {on: true, reason: "resolves to a non-public address"},
		"off":           {env: []string{"BYWARD_CIMD=false"}},
	} {
		t.Run(name, func(t *testing.T) {
			var got broker.Config
			orig := newBroker
			newBroker = func(c broker.Config) (*broker.Broker, error) { got = c; return orig(c) }
			t.Cleanup(func() { newBroker = orig })
			cfg, _, err := config.Load(nil, gateEnv(t, tc.env...), os.ReadFile)
			if err != nil {
				t.Fatal(err)
			}
			srv, err := New(cfg, logging.New(io.Discard, "json"))
			if err != nil {
				t.Fatal(err)
			}
			_, err = got.Clients.Client(context.Background(), loopbackDoc)
			wantErr := registration.ErrUnknownClient.Error()
			if tc.reason != "" {
				wantErr = tc.reason
			}
			if got.CIMD != tc.on || !errors.Is(err, registration.ErrUnknownClient) || !strings.Contains(err.Error(), wantErr) || (tc.reason == "" && err != registration.ErrUnknownClient) {
				t.Fatalf("CIMD %v (want %v), lookup error %v", got.CIMD, tc.on, err)
			}
			rec := httptest.NewRecorder()
			srv.Internal.Handler.ServeHTTP(rec, httptest.NewRequest("GET", "/metrics", nil))
			if counted := strings.Contains(rec.Body.String(), `byward_cimd_fetches_total{outcome="refused"} 1`); counted != tc.on {
				t.Fatalf("refused fetch counted: %v, want %v", counted, tc.on)
			}
			if c, err := got.Clients.Client(context.Background(), "test-app"); err != nil || c.ID() != "test-app" {
				t.Fatalf("static client: %v, %v", c, err)
			}
		})
	}
}

// The operator's host lists reach the registry: a host off the allowlist is refused before any
// fetch (no guard reason, nothing counted), a trusted host is still allowed, and each list lands
// in its own field; jwks_uri keys go through the guard too.
func TestTheCIMDHostListsReachTheRegistry(t *testing.T) {
	var got broker.Config
	orig := newBroker
	newBroker = func(c broker.Config) (*broker.Broker, error) { got = c; return orig(c) }
	t.Cleanup(func() { newBroker = orig })
	var wired registration.CIMDConfig
	origReg := newCIMDRegistry
	newCIMDRegistry = func(c registration.CIMDConfig) *registration.CIMDRegistry { wired = c; return origReg(c) }
	t.Cleanup(func() { newCIMDRegistry = origReg })
	cfg, _, err := config.Load(nil, gateEnv(t, "BYWARD_CIMD_ALLOWED_HOSTS=apps.example.com", "BYWARD_CIMD_TRUSTED_HOSTS=127.0.0.1.nip.example"), os.ReadFile)
	if err != nil {
		t.Fatal(err)
	}
	srv, err := New(cfg, logging.New(io.Discard, "json"))
	if err != nil {
		t.Fatal(err)
	}
	// Trust labels need a fetched document, so the lists are checked where they are wired.
	if !slices.Equal(wired.TrustedHosts, []string{"127.0.0.1.nip.example"}) || !slices.Equal(wired.AllowedHosts, []string{"apps.example.com"}) {
		t.Fatalf("trusted %v, allowed %v", wired.TrustedHosts, wired.AllowedHosts)
	}
	// jwks_uri keys are fetched with the guard's client: a loopback address is refused at dial.
	if res, err := wired.KeysClient.Get("https://127.0.0.1/jwks"); err == nil {
		_ = res.Body.Close()
		t.Fatal("the jwks_uri client reached a loopback address")
	} else if !errors.Is(err, ssrf.ErrProhibitedIP) {
		t.Fatalf("jwks_uri client: %v, want the guard's refusal", err)
	}
	_, err = got.Clients.Client(context.Background(), "https://other.example/client.json")
	if !errors.Is(err, registration.ErrUnknownClient) || !strings.Contains(err.Error(), "not allowed") {
		t.Fatalf("host off the allowlist: %v", err)
	}
	rec := httptest.NewRecorder()
	srv.Internal.Handler.ServeHTTP(rec, httptest.NewRequest("GET", "/metrics", nil))
	if strings.Contains(rec.Body.String(), "byward_cimd_fetches_total{") {
		t.Fatalf("a host off the allowlist was fetched:\n%s", rec.Body.String())
	}
	// Trusted hosts count as allowed: this one gets as far as the guard.
	if _, err := got.Clients.Client(context.Background(), "https://127.0.0.1.nip.example/client.json"); err == nil || strings.Contains(err.Error(), "not allowed") {
		t.Fatalf("trusted host: %v", err)
	}
}
