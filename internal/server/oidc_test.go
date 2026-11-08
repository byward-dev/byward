package server

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/byward-dev/byward/internal/config"
	"github.com/byward-dev/byward/internal/resource"
	"github.com/byward-dev/byward/internal/testutil/fakeidp"
	"github.com/byward-dev/byward/internal/testutil/fakeupstream"
	"github.com/byward-dev/byward/internal/upstream/stdio"
)

// oidcEnv is authEnv with an OIDC IdP (BYWARD_IDP=idpName) instead of Entra; the gate is left empty
// and allowed.
func oidcEnv(t *testing.T, idpName, issuer, clientID, secret string, extra ...string) []string {
	t.Helper()
	file := filepath.Join(t.TempDir(), "oidc-secret")
	if err := os.WriteFile(file, []byte(secret), 0o600); err != nil {
		t.Fatal(err)
	}
	env := slices.DeleteFunc(authEnv(t), func(kv string) bool { return strings.HasPrefix(kv, "BYWARD_ENTRA_") })
	return append(env, append([]string{"BYWARD_IDP=" + idpName, "BYWARD_OIDC_ISSUER=" + issuer, "BYWARD_OIDC_CLIENT_ID=" + clientID,
		"BYWARD_OIDC_CLIENT_SECRET_FILE=" + file, "BYWARD_GATE_ALLOW_EMPTY=true"}, extra...)...)
}

// loadOIDC loads a development-mode configuration for an OIDC IdP (a fake serves http on loopback).
func loadOIDC(t *testing.T, idpName, issuer, clientID string, extra ...string) *config.Config {
	t.Helper()
	cfg, _, err := config.Load([]string{"--dev"}, append(oidcEnv(t, idpName, issuer, clientID, "s3cret", extra...),
		"BYWARD_PUBLIC_URL=https://mcp.example.com/mcp", "BYWARD_UPSTREAM_URL=http://u/mcp"), os.ReadFile)
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

// The wiring end to end with a generic OIDC IdP: the static client signs a user in through
// /callback/oidc and gets a code, and the IdP calls are labelled oidc.
func TestTheWiredServerSignsInThroughAnOIDCIdP(t *testing.T) {
	const public = "https://mcp.example.com"
	app := fakeidp.Client{ID: fakeidp.NewGUID(), Secrets: []string{"s3cret"}, RedirectURIs: []string{public + "/callback/oidc"}}
	fake := fakeidp.New(t, fakeidp.Generic, fakeidp.WithClient(app))
	// The fake serves http on loopback, which only development mode accepts for an issuer.
	cfg := loadOIDC(t, "oidc", fake.Issuer(), app.ID, "BYWARD_OIDC_SCOPES=groups")
	var logs syncBuffer
	srv, err := New(cfg, slog.New(slog.NewJSONHandler(&logs, nil)))
	if err != nil {
		t.Fatal(err)
	}
	h := httptest.NewServer(srv.Public.Handler)
	t.Cleanup(h.Close)
	b := newTestBrowser(t, h.URL, public)
	send := b.send
	q := url.Values{"client_id": {"test-app"}, "redirect_uri": {"http://127.0.0.1:5555/callback"}, "response_type": {"code"},
		"code_challenge": {pkce("verifier-0123456789-0123456789-0123456789-abc")}, "code_challenge_method": {"S256"}}
	page := send(http.MethodGet, "/authorize?"+q.Encode(), nil, nil)
	body := readAll(t, page)
	host := strings.TrimPrefix(fake.Issuer(), "http://")
	// The technical details list the scopes asked of the IdP, the extra one included.
	if page.StatusCode != http.StatusOK || !strings.Contains(body, "sign in with "+host+" next") || !strings.Contains(body, "<code>groups</code>") {
		t.Fatalf("consent page: %d, want it to name the IdP by its issuer's host %s", page.StatusCode, host)
	}
	allow := b.allow(page, body)
	idpRes, err := fake.HTTPClient().Get(allow.Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	_ = idpRes.Body.Close()
	cb, _ := url.Parse(idpRes.Header.Get("Location"))
	if cb.Path != "/callback/oidc" {
		t.Fatalf("the IdP returned to %s, want /callback/oidc", cb.Path)
	}
	back := send(http.MethodGet, cb.Path+"?"+cb.RawQuery, nil, allow.Cookies())
	if back.StatusCode != http.StatusFound || !strings.Contains(back.Header.Get("Location"), "code=") {
		t.Fatalf("callback: %d to %q", back.StatusCode, back.Header.Get("Location"))
	}
	scrape := httptest.NewRequest("GET", "/metrics", nil)
	scrape.Host = "127.0.0.1:9090"
	m := httptest.NewRecorder()
	srv.Internal.Handler.ServeHTTP(m, scrape)
	if !strings.Contains(m.Body.String(), `idp="oidc"`) || strings.Contains(m.Body.String(), `idp="entra"`) {
		t.Fatalf("IdP metrics not labelled oidc:\n%s", m.Body)
	}
	// Startup tells the operator the redirect URI to register at the IdP, and nothing secret.
	if l := logs.String(); !strings.Contains(l, "register this redirect URI with the IdP app: https://mcp.example.com/callback/oidc") || strings.Contains(l, "s3cret") {
		t.Fatalf("startup log lacks the redirect URI or holds the secret:\n%s", l)
	}
}

// Outside development mode an http issuer refuses to start, naming the settings family.
func TestAnHTTPIssuerNeedsDevelopmentMode(t *testing.T) {
	cfg, _, err := config.Load(nil, append(oidcEnv(t, "oidc", "http://127.0.0.1:9000", "c", "s3cret"),
		"BYWARD_PUBLIC_URL=https://mcp.example.com/mcp", "BYWARD_UPSTREAM_URL=http://u/mcp"), os.ReadFile)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := New(cfg, discard); err == nil || !strings.Contains(err.Error(), "BYWARD_OIDC_*") || !strings.Contains(err.Error(), "must use https") {
		t.Fatalf("New with an http issuer outside development mode: %v", err)
	}
}

// With an OIDC IdP the upstream's assertion is still byward's own: iss is byward's issuer, never
// the IdP's, sub is the IdP's subject claim as the user key, and the opted-in claims come from the
// IdP's ID token (ADR-0016 §1).
func TestAnOIDCUsersAssertionIsByWardsWithTheIdPsSubject(t *testing.T) {
	user := fakeidp.User{Subject: "248289761001", Name: "Jane", Groups: []string{"mcp-users"}}
	c := oidcAssertion(t, user, "BYWARD_ASSERTION_CLAIMS=groups,name")
	if c["iss"] != "https://mcp.example.com" || c["sub"] != user.Subject || c["client_id"] != "test-app" || c["name"] != "Jane" || !reflect.DeepEqual(c["groups"], []any{"mcp-users"}) {
		t.Fatalf("assertion claims %v", c)
	}
}

// An OIDC IdP's email is asserted only when its email_verified is true, unless the operator opted
// in to unverified emails; email_verified says which (ADR-0016, 2026-11-07 amendment).
func TestAnOIDCUsersEmailIsAssertedOnlyWhenVerifiedOrTheOperatorOptedIn(t *testing.T) {
	const email = "jane@example.com"
	for _, tc := range []struct {
		name             string
		verified, absent bool // the user's email_verified; absent: the IdP sends no such claim
		optIn            bool // BYWARD_ASSERTION_UNVERIFIED_EMAIL
		wantEmail        any  // nil: left out
		wantVerified     any  // email_verified; nil: left out
	}{
		{name: "verified", verified: true, wantEmail: email, wantVerified: true},
		{name: "unverified is left out"},
		{name: "no email_verified claim is left out", verified: true, absent: true},
		{name: "unverified with the opt-in", optIn: true, wantEmail: email, wantVerified: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			settings := []string{"BYWARD_ASSERTION_CLAIMS=email"}
			if tc.optIn {
				settings = append(settings, "BYWARD_ASSERTION_UNVERIFIED_EMAIL=true")
			}
			s := signInOIDC(t, []fakeidp.Option{fakeidp.WithUser(fakeidp.User{Subject: "u1", Email: email, EmailVerified: tc.verified}),
				fakeidp.WithoutEmailVerified(tc.absent)}, settings...)
			if c := s.assertion(t); c["email"] != tc.wantEmail || c["email_verified"] != tc.wantVerified {
				t.Fatalf("email %v, email_verified %v; want %v, %v", c["email"], c["email_verified"], tc.wantEmail, tc.wantVerified)
			}
		})
	}
}

// Every refresh decides again from the IdP's new ID token: an email verified at sign-in and
// unverified now is no longer asserted as verified.
func TestARefreshAssertsTheEmailAsTheIdPVerifiesItNow(t *testing.T) {
	const email = "jane@example.com"
	for _, tc := range []struct {
		name         string
		optIn        bool
		wantEmail    any
		wantVerified any
	}{
		{"left out", false, nil, nil},
		{"unverified with the opt-in", true, email, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			settings := []string{"BYWARD_ASSERTION_CLAIMS=email"}
			if tc.optIn {
				settings = append(settings, "BYWARD_ASSERTION_UNVERIFIED_EMAIL=true")
			}
			// The same OID: the fake reissues a user's current claims only to that user.
			user := fakeidp.User{Subject: "u1", OID: fakeidp.NewGUID(), Email: email, EmailVerified: true}
			s := signInOIDC(t, []fakeidp.Option{fakeidp.WithUser(user)}, settings...)
			if c := s.assertion(t); c["email"] != email || c["email_verified"] != true {
				t.Fatalf("at sign-in: email %v, email_verified %v; want %s, true", c["email"], c["email_verified"], email)
			}
			user.EmailVerified = false
			s.fake.Set(fakeidp.WithUser(user))
			s.refresh(t)
			if c := s.assertion(t); c["email"] != tc.wantEmail || c["email_verified"] != tc.wantVerified {
				t.Fatalf("after refresh: email %v, email_verified %v; want %v, %v", c["email"], c["email_verified"], tc.wantEmail, tc.wantVerified)
			}
		})
	}
}

// oidcSession is a client signed in through a generic OIDC IdP: its tokens, the proxy and the
// upstream behind it.
type oidcSession struct {
	fake            *fakeidp.IdP
	cfg             *config.Config
	srv             *Servers
	h               *httptest.Server
	b               *testBrowser
	up              *fakeupstream.Server
	access, renewal string // the access and refresh tokens
}

// oidcAssertion signs user in through a generic OIDC IdP with the settings given, makes one MCP
// request, and returns the claims of the verified assertion the upstream got.
func oidcAssertion(t *testing.T, user fakeidp.User, settings ...string) map[string]any {
	t.Helper()
	return signInOIDC(t, []fakeidp.Option{fakeidp.WithUser(user)}, settings...).assertion(t)
}

// signInOIDC wires the proxy to a fake generic OIDC IdP set up by idp, with the settings given, and
// signs a client in for mcp and offline_access.
func signInOIDC(t *testing.T, idp []fakeidp.Option, settings ...string) *oidcSession {
	t.Helper()
	const public = "https://mcp.example.com"
	s := &oidcSession{up: fakeupstream.New()}
	t.Cleanup(s.up.Close)
	app := fakeidp.Client{ID: fakeidp.NewGUID(), Secrets: []string{"s3cret"}, RedirectURIs: []string{public + "/callback/oidc"}}
	s.fake = fakeidp.New(t, fakeidp.Generic, append([]fakeidp.Option{fakeidp.WithClient(app)}, idp...)...)
	var err error
	if s.cfg, _, err = config.Load([]string{"--dev"}, append(oidcEnv(t, "oidc", s.fake.Issuer(), app.ID, "s3cret", settings...),
		"BYWARD_PUBLIC_URL="+public+"/mcp", "BYWARD_UPSTREAM_URL="+s.up.URL+"/mcp"), os.ReadFile); err != nil {
		t.Fatal(err)
	}
	if s.srv, err = New(s.cfg, discard); err != nil {
		t.Fatal(err)
	}
	s.h = httptest.NewServer(s.srv.Public.Handler)
	t.Cleanup(s.h.Close)
	s.b = newTestBrowser(t, s.h.URL, public)
	const verifier = "verifier-0123456789-0123456789-0123456789-abc"
	q := url.Values{"client_id": {"test-app"}, "redirect_uri": {"http://127.0.0.1/callback"}, "response_type": {"code"}, "scope": {"mcp offline_access"},
		"code_challenge": {pkce(verifier)}, "code_challenge_method": {"S256"}}
	page := s.b.send(http.MethodGet, "/authorize?"+q.Encode(), nil, nil)
	allow := s.b.allow(page, readAll(t, page))
	idpRes, err := s.fake.HTTPClient().Get(allow.Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	_ = idpRes.Body.Close()
	cb, _ := url.Parse(idpRes.Header.Get("Location"))
	back := s.b.send(http.MethodGet, cb.Path+"?"+cb.RawQuery, nil, allow.Cookies())
	done, _ := url.Parse(back.Header.Get("Location"))
	s.tokens(t, url.Values{"grant_type": {"authorization_code"}, "code": {done.Query().Get("code")}, "client_id": {"test-app"},
		"redirect_uri": {"http://127.0.0.1/callback"}, "code_verifier": {verifier}})
	return s
}

// tokens posts form to /token and keeps the tokens it answers with.
func (s *oidcSession) tokens(t *testing.T, form url.Values) {
	t.Helper()
	res := s.b.send(http.MethodPost, "/token", form, nil)
	var body struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
	}
	if err := json.NewDecoder(res.Body).Decode(&body); err != nil || body.AccessToken == "" {
		t.Fatalf("token: %d %v", res.StatusCode, err)
	}
	s.access, s.renewal = body.AccessToken, body.RefreshToken
}

// refresh redeems the session's refresh token for new tokens.
func (s *oidcSession) refresh(t *testing.T) {
	t.Helper()
	if s.renewal == "" {
		t.Fatal("no refresh token")
	}
	s.tokens(t, url.Values{"grant_type": {"refresh_token"}, "refresh_token": {s.renewal}, "client_id": {"test-app"}})
}

// assertion makes one MCP request with the session's access token and returns the claims of the
// verified assertion the upstream got.
func (s *oidcSession) assertion(t *testing.T) map[string]any {
	t.Helper()
	r, _ := http.NewRequest(http.MethodPost, s.h.URL+"/mcp", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"ping"}`))
	r.Host = "mcp.example.com"
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Accept", "application/json, text/event-stream")
	r.Header.Set("Authorization", "Bearer "+s.access)
	res, err := http.DefaultClient.Do(r)
	if err != nil {
		t.Fatal(err)
	}
	_ = res.Body.Close()
	got, ok := s.up.Last()
	if res.StatusCode != http.StatusOK || !ok {
		t.Fatalf("MCP request: %d, upstream reached %v", res.StatusCode, ok)
	}
	raw, _ := strings.CutPrefix(got.Header.Get("Authorization"), "Bearer ")
	return verified(t, jwks(t, s.srv.Public.Handler, "mcp.example.com"), raw, s.cfg.UpstreamURL.String())
}

// A stdio process for an OIDC user runs under byward's issuer with the IdP's subject, as an Entra
// user's does (ADR-0016 §6).
func TestAStdioProcessForAnOIDCUserHasByWardsIssuer(t *testing.T) {
	cfg := loadOIDC(t, "keycloak", "http://127.0.0.1:9/realms/acme", "c")
	var got stdio.Identity
	var ok bool
	h := resource.Guard(resource.Metadata{Resource: cfg.PublicURL}, oneSubject("f:2a5e-kc-sub"), nil,
		http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) { got, ok = stdioIdentity(cfg)(r) }))
	r := httptest.NewRequest(http.MethodPost, "/mcp", nil)
	r.Header.Set("Authorization", "Bearer t")
	h.ServeHTTP(httptest.NewRecorder(), r)
	if !ok || got.Subject != "f:2a5e-kc-sub" || got.Issuer != "https://mcp.example.com" {
		t.Fatalf("stdio identity %+v, %v", got, ok)
	}
}

// oneSubject admits every token as the same subject.
type oneSubject string

func (s oneSubject) Validate(context.Context, string) (resource.Identity, error) {
	return resource.Identity{Subject: string(s)}, nil
}
