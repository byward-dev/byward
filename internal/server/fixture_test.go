package server

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/byward-dev/byward/internal/broker"
	"github.com/byward-dev/byward/internal/config"
	"github.com/byward-dev/byward/internal/idp"
	"github.com/byward-dev/byward/internal/logging"
	"github.com/byward-dev/byward/internal/store"
	"github.com/byward-dev/byward/internal/testutil/assertionkey"
	"github.com/byward-dev/byward/internal/token"
)

// fixtureTenant is the Entra tenant authEnv configures.
const fixtureTenant = "00000000-0000-0000-0000-000000000001"

// authEnv writes a key directory, a static-clients file and an IdP secret into a temp dir and
// returns the settings that point at them.
func authEnv(t testing.TB) []string {
	t.Helper()
	dir := t.TempDir()
	keys := filepath.Join(dir, "keys")
	if err := os.Mkdir(keys, 0o700); err != nil {
		t.Fatal(err)
	}
	k := make([]byte, 32)
	_, _ = rand.Read(k)
	write := func(p, content string) {
		if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write(filepath.Join(keys, "2026-11-06"), base64.StdEncoding.EncodeToString(k))
	write(filepath.Join(dir, "clients.json"), `{"clients":[{"client_id":"test-app","client_name":"Test app","token_endpoint_auth_method":"none","redirect_uris":["http://127.0.0.1/callback"]}]}`)
	write(filepath.Join(dir, "secret"), "s3cret-entra")
	return []string{
		"BYWARD_ENTRA_TENANT=" + fixtureTenant,
		"BYWARD_ENTRA_CLIENT_ID=00000000-0000-0000-0000-000000000002",
		"BYWARD_ENTRA_CLIENT_SECRET_FILE=" + filepath.Join(dir, "secret"),
		"BYWARD_KEYS_DIR=" + keys,
		"BYWARD_STATIC_CLIENTS_FILE=" + filepath.Join(dir, "clients.json"),
		"BYWARD_STORE_DIR=" + filepath.Join(dir, "state"), // the counter file defaults to dir/store-writes
		"BYWARD_ASSERTION_KEYS_DIR=" + assertionkey.Dir(t),
	}
}

// loadConfig loads authenticated-mode settings for publicURL plus extra env entries.
func loadConfig(t testing.TB, publicURL string, extra ...string) *config.Config {
	t.Helper()
	env := append(authEnv(t), "BYWARD_PUBLIC_URL="+publicURL, "BYWARD_UPSTREAM_URL=http://u/mcp")
	cfg, _, err := config.Load(nil, append(env, extra...), os.ReadFile)
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

// captureBroker makes the next New or buildAuth record the broker configuration it wires,
// optionally changed by wrap first, and restores the real constructor when the test ends.
func captureBroker(t testing.TB, wrap func(broker.Config) broker.Config) *broker.Config {
	t.Helper()
	got := new(broker.Config)
	orig := newBroker
	newBroker = func(c broker.Config) (*broker.Broker, error) {
		if wrap != nil {
			c = wrap(c)
		}
		*got = c
		return orig(c)
	}
	t.Cleanup(func() { newBroker = orig })
	return got
}

const (
	signedInSubject = fixtureTenant + ":11111111-1111-1111-1111-1111111111dd"
	signedInIssuer  = "https://login.microsoftonline.com/" + fixtureTenant + "/v2.0"
	seededIdPToken  = "idp-refresh-1"
)

// refreshingIdP stands in for the IdP adapter where a test needs a signed-in user's refresh but
// not the sign-in itself (cimd_session_test.go drives a full sign-in through the fake IdP): it
// renews only the IdP refresh token seedSignedInUser sealed, as the signed-in user.
type refreshingIdP struct{ broker.IdP }

func (refreshingIdP) Refresh(_ context.Context, rt string) (*idp.Identity, idp.Tokens, error) {
	if rt != seededIdPToken {
		return nil, idp.Tokens{}, fmt.Errorf("unexpected IdP refresh token %q", rt)
	}
	return &idp.Identity{Subject: signedInSubject, Issuer: signedInIssuer, Claims: map[string]any{"tid": fixtureTenant}},
		idp.Tokens{RefreshToken: seededIdPToken}, nil
}

// signedInServer starts the proxy on cfg's store with refreshingIdP, logging to the returned
// buffer (operator log and audit stream), and returns a stopServer function that closes its store
// once; the store is closed at the end of the test either way.
func signedInServer(t *testing.T, cfg *config.Config) (s *Servers, wired *broker.Config, logs *bytes.Buffer, stopServer func()) {
	t.Helper()
	wired = captureBroker(t, func(c broker.Config) broker.Config { c.IdP = refreshingIdP{c.IdP}; return c })
	logs = new(bytes.Buffer)
	s, err := New(cfg, logging.New(logs, "json"))
	if err != nil {
		t.Fatal(err)
	}
	var once sync.Once
	stopServer = func() {
		once.Do(func() {
			if err := s.closeStore(); err != nil {
				t.Error(err)
			}
		})
	}
	t.Cleanup(stopServer)
	return s, wired, logs, stopServer
}

// seedSignedInUser stores what a sign-in leaves behind: grant id with IdP tokens sealed by the
// server's own box, and its current refresh token, which it returns.
func seedSignedInUser(t *testing.T, wired *broker.Config, id string, now time.Time) string {
	t.Helper()
	sealed, err := wired.IdPTokenBox.Seal([]byte(`{"RefreshToken":"`+seededIdPToken+`"}`), now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	g := store.Grant{ID: id, ClientID: "test-app", Subject: signedInSubject, Issuer: signedInIssuer,
		Resource: "https://mcp.example.com/mcp", CreatedAt: now, ExpiresAt: now.Add(time.Hour), IdPTokens: []byte(sealed)}
	if _, err := wired.Store.CreateGrant(context.Background(), g); err != nil {
		t.Fatal(err)
	}
	rt, hash := token.NewRefreshToken()
	if err := wired.Store.PutRefreshToken(context.Background(), store.RefreshToken{Hash: hash, GrantID: id, ClientID: "test-app",
		CreatedAt: now, IdleExpiresAt: now.Add(14 * 24 * time.Hour)}); err != nil {
		t.Fatal(err)
	}
	return rt
}

// postRefresh sends a refresh grant to the public /token endpoint and returns the status and the
// decoded body.
func postRefresh(t *testing.T, s *Servers, rt string) (int, map[string]any) {
	t.Helper()
	form := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {rt}, "client_id": {"test-app"}}
	r := httptest.NewRequest(http.MethodPost, "https://mcp.example.com/token", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	s.Public.Handler.ServeHTTP(w, r)
	var body map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &body)
	return w.Code, body
}
