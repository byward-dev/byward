package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/byward-dev/byward/internal/broker"
	"github.com/byward-dev/byward/internal/config"
	"github.com/byward-dev/byward/internal/idp"
	"github.com/byward-dev/byward/internal/idp/entra"
	"github.com/byward-dev/byward/internal/logging"
	"github.com/byward-dev/byward/internal/metrics"
	"github.com/byward-dev/byward/internal/registration"
	"github.com/byward-dev/byward/internal/ssrfguard"
	"github.com/byward-dev/byward/internal/store"
	"github.com/byward-dev/byward/internal/testutil/assertionkey"
	"github.com/byward-dev/byward/internal/testutil/clientdocs"
	"github.com/byward-dev/byward/internal/testutil/fakeidp"
	"github.com/byward-dev/byward/internal/testutil/sealingkey"
	"github.com/byward-dev/byward/internal/token"
)

// The Entra tenant, app and secret authEnv configures and fixtureEntra accepts.
const (
	fixtureTenant   = "00000000-0000-0000-0000-000000000001"
	fixtureClientID = "00000000-0000-0000-0000-000000000002"
	fixtureSecret   = "s3cret-entra"
)

// fixtureEntra is a fake Entra tenant that accepts authEnv's app and secret.
func fixtureEntra(t testing.TB) *fakeidp.IdP {
	t.Helper()
	return fakeidp.New(t, fakeidp.Entra, fakeidp.WithTenantID(fixtureTenant),
		fakeidp.WithClient(fakeidp.Client{ID: fixtureClientID, Secrets: []string{fixtureSecret}}))
}

// authEnv writes a key directory, a static-clients file and an IdP secret into a temp dir and
// returns the settings that point at them.
func authEnv(t testing.TB) []string {
	t.Helper()
	dir := t.TempDir()
	keys := filepath.Join(dir, "keys")
	sealingkey.Write(t, keys, "2026-11-06")
	write := func(p, content string) {
		if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write(filepath.Join(dir, "clients.json"), `{"clients":[{"client_id":"test-app","client_name":"Test app","token_endpoint_auth_method":"none","redirect_uris":["http://127.0.0.1/callback"]}]}`)
	write(filepath.Join(dir, "secret"), fixtureSecret)
	return []string{
		"BYWARD_ENTRA_TENANT=" + fixtureTenant,
		"BYWARD_ENTRA_CLIENT_ID=" + fixtureClientID,
		"BYWARD_ENTRA_CLIENT_SECRET_FILE=" + filepath.Join(dir, "secret"),
		"BYWARD_KEYS_DIR=" + keys,
		"BYWARD_STATIC_CLIENTS_FILE=" + filepath.Join(dir, "clients.json"),
		"BYWARD_STORE_DIR=" + filepath.Join(dir, "state"), // the counter file defaults to dir/store-writes
		"BYWARD_ASSERTION_KEYS_DIR=" + assertionkey.Dir(t),
	}
}

// stdioAuthEnv is authEnv for a stdio upstream: without the assertion key directory, which config
// refuses with one (a stdio upstream gets no assertion, ADR-0016 §6). The data directory is the
// test's own, so no default path reaches the host's.
func stdioAuthEnv(t testing.TB) []string {
	t.Helper()
	env := slices.DeleteFunc(authEnv(t), func(kv string) bool { return strings.HasPrefix(kv, "BYWARD_ASSERTION_KEYS_DIR=") })
	return append(env, "BYWARD_DATA_DIR="+t.TempDir())
}

// postgresEnv is authEnv on a PostgreSQL store with the given DSN instead of a SQLite state
// directory, for the public URL https://mcp.example.com/mcp and the given upstream.
func postgresEnv(t testing.TB, dsn, upstreamURL string) []string {
	t.Helper()
	file := filepath.Join(t.TempDir(), "postgres-dsn")
	if err := os.WriteFile(file, []byte(dsn), 0o600); err != nil {
		t.Fatal(err)
	}
	var env []string
	for _, kv := range authEnv(t) {
		if !strings.HasPrefix(kv, "BYWARD_STORE_DIR=") {
			env = append(env, kv)
		}
	}
	return append(env, "BYWARD_STORE_POSTGRES_DSN_FILE="+file, "BYWARD_PUBLIC_URL=https://mcp.example.com/mcp", "BYWARD_UPSTREAM_URL="+upstreamURL)
}

// loadConfig loads authenticated-mode settings for publicURL with the upstream http://u/mcp, plus
// extra env entries; an extra entry overrides a default one (a later entry wins).
func loadConfig(t testing.TB, publicURL string, extra ...string) *config.Config {
	t.Helper()
	env := append(authEnv(t), "BYWARD_PUBLIC_URL="+publicURL, "BYWARD_UPSTREAM_URL=http://u/mcp")
	cfg, _, err := config.Load(nil, append(env, extra...), os.ReadFile)
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

// noAuthEnv is the settings without authentication for the public URL http://127.0.0.1:8080/mcp
// and upstreamURL, plus extra entries; an extra entry overrides a default one (a later entry wins).
func noAuthEnv(upstreamURL string, extra ...string) []string {
	return append([]string{"BYWARD_PUBLIC_URL=http://127.0.0.1:8080/mcp", "BYWARD_UPSTREAM_URL=" + upstreamURL,
		"BYWARD_INSECURE_NO_AUTH=true"}, extra...)
}

// loadNoAuthConfig loads noAuthEnv(upstreamURL, extra...).
func loadNoAuthConfig(t testing.TB, upstreamURL string, extra ...string) *config.Config {
	t.Helper()
	cfg, _, err := config.Load(nil, noAuthEnv(upstreamURL, extra...), os.ReadFile)
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

// keyRing is the sealing-key ring the server under cfg loads.
func keyRing(t testing.TB, cfg *config.Config) *token.KeyRing {
	t.Helper()
	ring, err := token.LoadKeyRing(cfg.KeysDir)
	if err != nil {
		t.Fatal(err)
	}
	return ring
}

// proxySealer seals access tokens as the server under cfg does.
func proxySealer(t testing.TB, cfg *config.Config) *token.Sealer {
	t.Helper()
	s, err := token.NewSealer(keyRing(t, cfg), cfg.PublicURL.String())
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// checkOffline is check --offline's warnings and error for cfg.
func checkOffline(cfg *config.Config) ([]Warning, error) {
	r, err := CheckOfflineReport(cfg)
	return r.Warnings, err
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

// useFakeEntra points the wired Entra provider at fake, as app with its first secret, until the test
// ends; the wiring's other settings, its redirect URL among them, stay as configured.
func useFakeEntra(t testing.TB, fake *fakeidp.IdP, app fakeidp.Client) {
	t.Helper()
	orig := newEntraProvider
	newEntraProvider = func(c entra.Config) (*entra.Provider, error) {
		c.Tenant, c.ClientID, c.ClientAuth, c.HTTPClient = fake.TenantID(), app.ID, idp.ClientSecret(app.Secrets[0]), fake.HTTPClient()
		return entra.New(c) // not orig: under a nested use, the innermost fake wins
	}
	t.Cleanup(func() { newEntraProvider = orig })
}

// serveCIMDFrom makes the wired CIMD registry fetch client documents and their keys from served
// until the test ends.
func serveCIMDFrom(t testing.TB, served *clientdocs.Server) {
	t.Helper()
	orig := newCIMDRegistry
	newCIMDRegistry = func(c registration.CIMDConfig) *registration.CIMDRegistry {
		guard := ssrfguard.New(ssrfguard.Config{RootCAs: served.RootCAs, Dial: served.Dial})
		c.Fetch, c.KeysClient = guard, guard.HTTPClient()
		return orig(c)
	}
	t.Cleanup(func() { newCIMDRegistry = orig })
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

// fakeStdioDir is where fakeStdio built the fake stdio upstream, if a test asked for it; TestMain
// removes it once every test has run (t.Cleanup cannot: the fake outlives the test that built it).
// A run that ends in a panic, os.Exit or a timeout leaves it behind, as it would a test's TempDir
// after os.Exit or a timeout; removing old ones at start would delete other runs' fakes.
var fakeStdioDir string

// TestMain keeps the package's tests off the system resolver: startup and doctor resolve the
// upstream's host, and a test that needs a name resolved gives its own resolver. It removes
// fakeStdioDir last.
func TestMain(m *testing.M) {
	lookupNetIP = func(context.Context, string) ([]netip.Addr, error) {
		return nil, errors.New("the tests resolve no names")
	}
	code := m.Run()
	if fakeStdioDir != "" {
		_ = os.RemoveAll(fakeStdioDir)
	}
	os.Exit(code)
}

// readDoc is the text of a file under docs/, by its path relative to docs/.
func readDoc(t *testing.T, rel string) string {
	t.Helper()
	b, err := os.ReadFile("../../docs/" + rel) //nolint:gosec // G304: a page under docs/ that the test names
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// scrapeMetrics is what /metrics shows of m.
func scrapeMetrics(t *testing.T, m *metrics.Metrics) string {
	t.Helper()
	rec := httptest.NewRecorder()
	m.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	return rec.Body.String()
}

// internalMetrics is what /metrics on the internal listener h shows.
func internalMetrics(t *testing.T, h http.Handler) string {
	t.Helper()
	code, body := getBody(t, h, "127.0.0.1:9090", "/metrics") // the internal listener answers only IP or listed hosts
	if code != http.StatusOK {
		t.Fatalf("/metrics on the internal listener: %d %s", code, body)
	}
	return body
}
