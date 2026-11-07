package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"

	"github.com/byward-dev/byward/internal/assertion"
	"github.com/byward-dev/byward/internal/audit"
	"github.com/byward-dev/byward/internal/broker"
	"github.com/byward-dev/byward/internal/config"
	"github.com/byward-dev/byward/internal/logging"
	"github.com/byward-dev/byward/internal/store"
	"github.com/byward-dev/byward/internal/store/sqlite"
	"github.com/byward-dev/byward/internal/testutil/assertionkey"
	"github.com/byward-dev/byward/internal/testutil/fakeupstream"
	"github.com/byward-dev/byward/internal/token"
)

// asserting is the proxy, wired as in production, in front of a fake HTTP upstream.
type asserting struct {
	cfg      *config.Config
	public   http.Handler
	internal http.Handler
	up       *fakeupstream.Server
	sealer   *token.Sealer
	logs     *bytes.Buffer // everything the proxy logged
}

func newAsserting(t *testing.T, extra ...string) asserting {
	t.Helper()
	up := fakeupstream.New()
	t.Cleanup(up.Close)
	env := append(authEnv(t), "BYWARD_PUBLIC_URL=https://mcp.example.com/mcp", "BYWARD_UPSTREAM_URL="+up.URL+"/mcp", "BYWARD_INTERNAL_LISTEN=127.0.0.1:0")
	cfg, _, err := config.Load(nil, append(env, extra...), os.ReadFile)
	if err != nil {
		t.Fatal(err)
	}
	var logs bytes.Buffer
	s, err := New(cfg, logging.New(&logs, "text")) // the proxy's logger, with its key allowlist
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.closeStore() })
	ring, err := token.LoadKeyRing(cfg.KeysDir)
	if err != nil {
		t.Fatal(err)
	}
	sealer, err := token.NewSealer(ring, cfg.PublicURL.String())
	if err != nil {
		t.Fatal(err)
	}
	return asserting{cfg: cfg, public: s.Public.Handler, internal: s.Internal.Handler, up: up, sealer: sealer, logs: &logs}
}

// call sends an MCP request with a proxy token for c and returns the request the upstream got.
func (a asserting) call(t *testing.T, c token.Claims, header http.Header) fakeupstream.Request {
	t.Helper()
	now := time.Now()
	c.IssuedAt, c.ExpiresAt = now, now.Add(time.Hour)
	tok, err := a.sealer.Seal(token.Access, c)
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest(http.MethodPost, "https://mcp.example.com/mcp", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"ping"}`))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Accept", "application/json, text/event-stream")
	for k, v := range header {
		r.Header[k] = v
	}
	r.Header.Set("Authorization", "Bearer "+tok)
	rec := httptest.NewRecorder()
	a.public.ServeHTTP(rec, r)
	if rec.Code != http.StatusOK {
		t.Fatalf("MCP request: %d %s", rec.Code, rec.Body)
	}
	got, ok := a.up.Last()
	if !ok {
		t.Fatal("the upstream got no request")
	}
	return got
}

// jwks fetches the JWKS from h, as an upstream's verifier does.
func jwks(t *testing.T, h http.Handler, host string) jose.JSONWebKeySet {
	t.Helper()
	r := httptest.NewRequest(http.MethodGet, "http://"+host+"/.well-known/jwks.json", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	var set jose.JSONWebKeySet
	body, _ := io.ReadAll(rec.Body)
	if rec.Code != http.StatusOK || json.Unmarshal(body, &set) != nil || len(set.Keys) == 0 {
		t.Fatalf("JWKS at %s: %d %s", host, rec.Code, body)
	}
	return set
}

// verified checks an assertion with set the way go-sdk's and FastMCP's verifiers do: ES256, the
// kid in the JWKS, typ at+jwt, aud the upstream URL exactly as configured, not expired.
func verified(t *testing.T, set jose.JSONWebKeySet, raw, audience string) map[string]any {
	t.Helper()
	tok, err := jwt.ParseSigned(raw, []jose.SignatureAlgorithm{jose.ES256})
	if err != nil {
		t.Fatalf("not a JWS: %v", err)
	}
	if typ := tok.Headers[0].ExtraHeaders["typ"]; typ != "at+jwt" {
		t.Fatalf("typ %v", typ)
	}
	keys := set.Key(tok.Headers[0].KeyID)
	if len(keys) != 1 {
		t.Fatalf("kid %q is not in the JWKS", tok.Headers[0].KeyID)
	}
	var std jwt.Claims
	var all map[string]any
	if err := tok.Claims(keys[0].Key, &std, &all); err != nil {
		t.Fatalf("signature: %v", err)
	}
	if err := std.ValidateWithLeeway(jwt.Expected{AnyAudience: jwt.Audience{audience}, Time: time.Now()}, 30*time.Second); err != nil {
		t.Fatalf("claims: %v", err)
	}
	return all
}

// The upstream learns who the user is from the assertion, never from the client's token
// (invariant 1, ADR-0016 §2); the JWKS that verifies it is on both listeners (§3).
func TestTheUpstreamGetsAnAssertionItCanVerifyInsteadOfTheClientsToken(t *testing.T) {
	a := newAsserting(t)
	got := a.call(t, token.Claims{GrantID: "g1", Subject: "tid:oid", ClientID: "claude-code", Roles: []string{"byward.user"}}, nil)
	raw, ok := strings.CutPrefix(got.Header.Get("Authorization"), "Bearer ")
	if !ok || strings.HasPrefix(raw, token.AccessPrefix) {
		t.Fatalf("upstream Authorization %q", got.Header.Get("Authorization"))
	}
	c := verified(t, jwks(t, a.public, "mcp.example.com"), raw, a.cfg.UpstreamURL.String())
	if c["sub"] != "tid:oid" || c["client_id"] != "claude-code" || c["iss"] != "https://mcp.example.com" ||
		!reflect.DeepEqual(c["roles"], []any{"byward.user"}) {
		t.Fatalf("claims %v", c)
	}
	internal := jwks(t, a.internal, "127.0.0.1")
	if len(internal.Keys) != 1 || internal.Keys[0].KeyID != "k1" {
		t.Fatalf("internal JWKS %+v", internal)
	}
}

// With its own header the assertion still replaces whatever the client sent there, in any
// spelling, and the client's token still never reaches the upstream (ADR-0016 §2, §4).
func TestAClientCannotSupplyTheAssertionHeader(t *testing.T) {
	a := newAsserting(t, "BYWARD_ASSERTION_HEADER=X-Byward-Identity")
	got := a.call(t, token.Claims{GrantID: "g1", Subject: "tid:oid", ClientID: "c"},
		// The underscore spelling is the one only the strip removes (Set overwrites the other); the
		// relay's test has every spelling.
		http.Header{"X_byward_identity": {"Bearer forged"}, "X-Byward-Identity": {"Bearer forged"}})
	if vals := got.Header.Values("X-Byward-Identity"); len(vals) != 1 || strings.Contains(vals[0], "forged") {
		t.Fatalf("assertion header %q", vals)
	}
	if _, ok := got.Header["X_byward_identity"]; ok {
		t.Fatal("the underscore spelling reached the upstream: the strip is not wired")
	}
	if auth := got.Header.Get("Authorization"); auth != "" {
		t.Fatalf("the client's token reached the upstream: %q", auth)
	}
	raw := strings.TrimPrefix(got.Header.Get("X-Byward-Identity"), "Bearer ")
	verified(t, jwks(t, a.public, "mcp.example.com"), raw, a.cfg.UpstreamURL.String())
}

// Without an assertion key the proxy does not start (ADR-0016 §10), naming the setting.
func TestAnHTTPUpstreamWithoutAnAssertionKeyRefusesToStart(t *testing.T) {
	cfg := loadConfig(t, "https://mcp.example.com/mcp", "BYWARD_ASSERTION_KEYS_DIR="+t.TempDir())
	noKey := func(err error) bool {
		return err != nil && strings.Contains(err.Error(), "BYWARD_ASSERTION_KEYS_DIR") && strings.Contains(err.Error(), "has no key files")
	}
	if _, err := New(cfg, slog.New(slog.DiscardHandler)); !noKey(err) {
		t.Fatalf("err = %v", err)
	}
	if _, err := CheckOffline(cfg); !noKey(err) {
		t.Fatalf("check --offline: err = %v", err)
	}
}

// A request with no identity to assert is refused and never reaches the upstream without its
// assertion (ADR-0016 §2); Mint's own refusals are the assertion package's tests.
func TestARequestWithoutAnIdentityNeverReachesTheUpstream(t *testing.T) {
	k, err := assertion.LoadKeys(assertionkey.Dir(t), func(string) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	m, err := assertion.NewMinter(k, "https://mcp.example.com", "http://u/mcp", time.Now)
	if err != nil {
		t.Fatal(err)
	}
	reached := false
	h := withAssertion(m, slog.New(slog.DiscardHandler), http.HandlerFunc(func(http.ResponseWriter, *http.Request) { reached = true }))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/mcp", nil))
	if rec.Code != http.StatusInternalServerError || reached {
		t.Fatalf("status %d, reached the upstream: %v", rec.Code, reached)
	}
}

// BYWARD_ASSERTION_CLAIMS selects exactly the claims the broker seals, each name its own claim.
func TestEachAssertionClaimNameSelectsItsOwnClaim(t *testing.T) {
	const unverified = "BYWARD_ASSERTION_UNVERIFIED_EMAIL=true"
	for _, tc := range []struct {
		claims, extra string
		want          broker.Asserted
	}{
		{"none", "", broker.Asserted{}},
		{"roles", "", broker.Asserted{Roles: true}},
		{"groups,email,name", "", broker.Asserted{Groups: true, Email: true, Name: true}},
		{"email", unverified, broker.Asserted{Email: true, UnverifiedEmail: true}},
		{"roles", unverified, broker.Asserted{Roles: true}}, // no email to assert unverified
	} {
		env := []string{"BYWARD_ASSERTION_CLAIMS=" + tc.claims}
		if tc.extra != "" {
			env = append(env, tc.extra)
		}
		cfg := loadConfig(t, "https://mcp.example.com/mcp", env...)
		if got := assertedClaims(cfg); got != tc.want {
			t.Errorf("%s %s: %+v, want %+v", tc.claims, tc.extra, got, tc.want)
		}
	}
}

// Every start says which emails the assertion leaves out or carries unverified, naming the setting
// that changes it (ADR-0016, 2026-11-07 amendment).
func TestStartupSaysWhichEmailsTheAssertionLeavesOutOrCarriesUnverified(t *testing.T) {
	for _, tc := range []struct {
		name, claims string
		unverified   bool
		entra        bool
		want         string // "" for no warning
	}{
		{"no email", "roles", false, true, ""},
		{"an OIDC IdP leaves out unverified emails", "email", false, false, "leaves out emails the IdP has not verified"},
		{"Entra asserts no email", "email", false, true, "Entra never verifies an email"},
		{"the opt-in carries unverified emails", "email", true, true, "carries emails the IdP has not verified"},
		{"the opt-in without email does nothing", "roles", true, false, "BYWARD_ASSERTION_UNVERIFIED_EMAIL has no effect"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ws := emailWarnings(&config.Config{AssertionClaims: strings.Split(tc.claims, ","), AssertionUnverifiedEmail: tc.unverified}, tc.entra)
			if tc.want == "" {
				if len(ws) != 0 {
					t.Fatalf("warnings %v, want none", ws)
				}
				return
			}
			if len(ws) != 1 || !strings.Contains(ws[0].Message, tc.want) || !strings.Contains(ws[0].String(), "BYWARD_ASSERTION_") {
				t.Fatalf("warnings %v, want one saying %q and naming the setting", ws, tc.want)
			}
		})
	}
}

// The email warning reaches the startup log.
func TestAnEntraProxyAssertingEmailWarnsAtStartup(t *testing.T) {
	cfg := loadConfig(t, "https://mcp.example.com/mcp", "BYWARD_ASSERTION_CLAIMS=email")
	logs := &syncBuffer{}
	if _, err := New(cfg, slog.New(slog.NewJSONHandler(logs, nil))); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(logs.String(), "Entra never verifies an email") || !strings.Contains(logs.String(), `"setting":"BYWARD_ASSERTION_UNVERIFIED_EMAIL"`) {
		t.Fatalf("no email warning in the startup log: %s", logs)
	}
}

// stdioAuthConfig is authenticated mode in front of a stdio upstream, with an empty assertion key
// directory: a stdio upstream gets its identity at spawn, not as an assertion (ADR-0016 §6).
func stdioAuthConfig(t *testing.T, command string) *config.Config {
	t.Helper()
	cfg, _, err := config.Load([]string{"--", command}, append(authEnv(t), "BYWARD_PUBLIC_URL=https://mcp.example.com/mcp",
		"BYWARD_INTERNAL_LISTEN=127.0.0.1:0", "BYWARD_ASSERTION_KEYS_DIR="+t.TempDir()), os.ReadFile)
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

// A stdio upstream needs no assertion key, and the proxy serves no JWKS for it.
func TestAStdioUpstreamStartsWithoutAssertionKeysAndServesNoJWKS(t *testing.T) {
	sh, err := exec.LookPath("sh")
	if err != nil {
		t.Skip("no sh")
	}
	s, err := New(stdioAuthConfig(t, sh), slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.closeStore() })
	for host, h := range map[string]http.Handler{"mcp.example.com": s.Public.Handler, "127.0.0.1": s.Internal.Handler} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "http://"+host+"/.well-known/jwks.json", nil))
		if rec.Code != http.StatusNotFound {
			t.Errorf("JWKS on %s: %d, want 404", host, rec.Code)
		}
	}
}

// The store is opened before the upstream is built, so a failing upstream must close it again.
func TestAnUpstreamThatFailsToStartClosesTheStore(t *testing.T) {
	var st *sqlite.Store
	orig := wireStore
	t.Cleanup(func() { wireStore = orig })
	wireStore = func(cfg *config.Config, log *slog.Logger, rec *audit.Log) (*sqlite.Store, error) {
		s, err := orig(cfg, log, rec)
		st = s
		return s, err
	}
	if _, err := New(stdioAuthConfig(t, "byward-no-such-command"), slog.New(slog.DiscardHandler)); err == nil || !strings.Contains(err.Error(), "BYWARD_UPSTREAM_COMMAND") {
		t.Fatalf("New = %v, want the missing command", err)
	}
	if st == nil {
		t.Fatal("the store was never opened")
	}
	if _, err := st.Grant(context.Background(), "g"); err == nil || errors.Is(err, store.ErrNotFound) {
		t.Fatalf("the store still answers after New failed: %v", err)
	}
}
