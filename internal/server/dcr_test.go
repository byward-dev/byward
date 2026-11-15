package server

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/byward-dev/byward/internal/broker"
	"github.com/byward-dev/byward/internal/logging"
	"github.com/byward-dev/byward/internal/registration"
	"github.com/go-jose/go-jose/v4"
)

// newWired builds the server from env and returns it with the broker configuration it wired.
func newWired(t *testing.T, env ...string) (*Servers, broker.Config) {
	t.Helper()
	got := captureBroker(t, nil)
	cfg := loadConfig(t, "https://m.example/mcp", env...)
	srv, err := New(cfg, logging.New(io.Discard, "json"))
	if err != nil {
		t.Fatal(err)
	}
	return srv, *got
}

// registerAt posts a registration to the wired public handler.
func registerAt(srv *Servers, body string) *httptest.ResponseRecorder {
	r := httptest.NewRequest("POST", "https://m.example/register", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	srv.Public.Handler.ServeHTTP(rec, r)
	return rec
}

// DCR is on by default: a registration through the wired server is stored, counted and resolves
// after the static clients. Off, /register is not served.
func TestRegisterIssuesUsableClientsOnlyWhenDCRIsOn(t *testing.T) {
	const body = `{"client_name":"App","redirect_uris":["https://app.example/cb"]}`
	t.Run("on by default", func(t *testing.T) {
		srv, got := newWired(t)
		rec := registerAt(srv, body)
		var reg map[string]any
		_ = json.Unmarshal(rec.Body.Bytes(), &reg)
		id, _ := reg["client_id"].(string)
		if rec.Code != http.StatusCreated || id == "" {
			t.Fatalf("register: %d %s", rec.Code, rec.Body)
		}
		if c, err := got.Clients.Client(context.Background(), id); err != nil || c.Trust() != registration.NotVerified {
			t.Fatalf("registered client: %v, %v", c, err)
		}
		if c, err := got.Clients.Client(context.Background(), "test-app"); err != nil || c.ID() != "test-app" {
			t.Fatalf("static client: %v, %v", c, err)
		}
		if m := internalMetrics(t, srv.Internal.Handler); !strings.Contains(m, `byward_dcr_registrations_total{outcome="registered"} 1`) {
			t.Fatalf("registration not counted:\n%s", m)
		}
	})
	t.Run("off", func(t *testing.T) {
		srv, _ := newWired(t, "BYWARD_DCR=false")
		if rec := registerAt(srv, body); rec.Code != http.StatusNotFound {
			t.Fatalf("/register with DCR off: %d, want 404", rec.Code)
		}
	})
}

// The operator's denylist reaches registration.
func TestADeniedHostIsRefusedAtRegistration(t *testing.T) {
	srv, _ := newWired(t, "BYWARD_CLIENT_DENYLIST=app.example")
	if rec := registerAt(srv, `{"client_name":"App","redirect_uris":["https://app.example/cb"]}`); rec.Code != http.StatusBadRequest ||
		!strings.Contains(rec.Body.String(), "invalid_redirect_uri") {
		t.Fatalf("registration returning to a denied host: %d %s", rec.Code, rec.Body)
	}
}

// A denylist entry that is not a valid CIMD client ID refuses to start, naming the setting (a host
// entry that is not a host name is refused earlier, by config).
func TestABadDenylistEntryRefusesToStartNamingTheSetting(t *testing.T) {
	cfg := loadConfig(t, "https://m.example/mcp", "BYWARD_CLIENT_DENYLIST=https://app.example/client.json?v=1")
	if _, err := New(cfg, logging.New(io.Discard, "json")); err == nil || !strings.Contains(err.Error(), "BYWARD_CLIENT_DENYLIST") {
		t.Fatalf("New with a bad denylist entry: %v, want an error naming BYWARD_CLIENT_DENYLIST", err)
	}
}

// A registered client's jwks_uri is fetched through the SSRF guard: keys at a loopback address are
// refused by the guard at dial time, not merely unreachable.
func TestARegisteredClientsKeysAreFetchedThroughTheGuard(t *testing.T) {
	srv, got := newWired(t)
	rec := registerAt(srv, `{"client_name":"App","redirect_uris":["https://app.example/cb"],"token_endpoint_auth_method":"private_key_jwt","jwks_uri":"https://127.0.0.1/jwks.json"}`)
	var reg map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &reg)
	id, _ := reg["client_id"].(string)
	if rec.Code != http.StatusCreated {
		t.Fatalf("register: %d %s", rec.Code, rec.Body)
	}
	c, err := got.Clients.Client(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	signer, _ := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: key}, (&jose.SignerOptions{}).WithHeader("kid", "k1"))
	jws, _ := signer.Sign([]byte(`{"iss":"` + id + `","sub":"` + id + `"}`))
	assertion, _ := jws.CompactSerialize()
	form := map[string][]string{"client_id": {id}, "client_assertion_type": {"urn:ietf:params:oauth:client-assertion-type:jwt-bearer"},
		"client_assertion": {assertion}}
	err = c.Authenticate(context.Background(), form, http.Header{}, "https://m.example/token", time.Now())
	if err == nil || !strings.Contains(err.Error(), "is not a permitted destination") {
		t.Fatalf("authenticating with keys at a loopback jwks_uri: %v, want the SSRF guard's refusal", err)
	}
}

// The denylist also reaches the CIMD registry: a denied document URL is unknown without a fetch.
func TestADeniedCIMDClientIsRefused(t *testing.T) {
	const denied = "https://evil.example/client.json"
	_, got := newWired(t, "BYWARD_CLIENT_DENYLIST="+denied)
	if _, err := got.Clients.Client(context.Background(), denied); !errors.Is(err, registration.ErrUnknownClient) || !strings.Contains(err.Error(), "denylist") {
		t.Fatalf("denied CIMD client: %v, want unknown because of the denylist", err)
	}
}
