package oidc

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/byward-dev/byward/internal/idp"
	"github.com/byward-dev/byward/internal/testutil/fakeidp"
)

const (
	redirect = "http://127.0.0.1:8080/callback/oidc"
	secret   = "test-secret-value"
)

type env struct {
	fake   *fakeidp.IdP
	client fakeidp.Client
	p      *Provider
}

func newEnv(t *testing.T, cfg Config, opts ...fakeidp.Option) *env {
	t.Helper()
	c := fakeidp.Client{ID: fakeidp.NewGUID(), Secrets: []string{secret}, RedirectURIs: []string{redirect}}
	fake := fakeidp.New(t, fakeidp.Generic, append([]fakeidp.Option{fakeidp.WithClient(c), fakeidp.WithClock(now)}, opts...)...)
	if cfg.Issuer == "" {
		cfg.Issuer = fake.Issuer()
		cfg.AllowLoopbackHTTP = true // the fake serves http on loopback, as in development mode
	}
	cfg.ClientID, cfg.RedirectURL = c.ID, redirect
	if cfg.Now == nil {
		cfg.Now = now
	}
	if cfg.ClientAuth == nil {
		cfg.ClientAuth = idp.ClientSecret(secret)
	}
	p, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return &env{fake: fake, client: c, p: p}
}

// now is the shared fixed clock of the fake and the adapter.
func now() time.Time { return time.Unix(1_800_000_000, 0) }

var login = idp.Login{State: "state-1", Nonce: "nonce-1", CodeVerifier: "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"}

// signIn follows the login URL to the fake (auto-login) and returns the callback query.
func signIn(t *testing.T, e *env, l idp.Login) url.Values {
	t.Helper()
	u, err := e.p.AuthCodeURL(context.Background(), l)
	if err != nil {
		t.Fatal(err)
	}
	return e.fake.Authorize(t, u)
}

func TestGenericLoginReturnsIdentityAndTokens(t *testing.T) {
	e := newEnv(t, Config{}, fakeidp.WithUser(fakeidp.User{Email: "test.user@contoso.example", EmailVerified: true, Groups: []string{"g1"}}))
	q := signIn(t, e, login)
	id, tok, err := e.p.Callback(context.Background(), q, login)
	if err != nil {
		t.Fatal(err)
	}
	u := e.fake.User()
	if id.Subject != u.Subject || id.Issuer != e.fake.Issuer() || id.Email != u.Email || !id.EmailVerified ||
		len(id.Groups) != 1 || id.Claims["nonce"] != "nonce-1" || id.Claims["aud"] != e.client.ID {
		t.Fatalf("identity = %+v", id)
	}
	if tok.IDToken == "" || tok.AccessToken == "" || tok.RefreshToken == "" || tok.Expiry.IsZero() {
		t.Fatalf("tokens = %v", tok)
	}
}

func TestAuthCodeURLCarriesPKCEStateNonceAndPresetParams(t *testing.T) {
	e := newEnv(t, Config{Scopes: []string{"groups", "email"}})
	l := login
	l.LoginHint, l.SelectAccount = "someone", true
	raw, err := e.p.AuthCodeURL(context.Background(), l)
	if err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(raw)
	q := u.Query()
	want := map[string]string{
		"response_type": "code", "client_id": e.client.ID, "redirect_uri": redirect, "state": "state-1", "nonce": "nonce-1",
		"code_challenge": idp.CodeChallenge(login.CodeVerifier), "code_challenge_method": "S256",
		"scope": "openid profile email offline_access groups", "login_hint": "someone", "prompt": "select_account",
	}
	for k, v := range want {
		if q.Get(k) != v {
			t.Errorf("%s = %q, want %q", k, q.Get(k), v)
		}
	}
	if strings.HasPrefix(raw, e.fake.AuthorizeURL("")) == false {
		t.Errorf("login URL %s is not the discovered authorization endpoint", raw)
	}
	if _, err := e.p.AuthCodeURL(context.Background(), idp.Login{State: "s"}); err == nil {
		t.Error("login without nonce and verifier accepted")
	}
}

func TestCallbackRequiresIssWhenAdvertised(t *testing.T) {
	e := newEnv(t, Config{})
	q := signIn(t, e, login)
	q.Set("iss", "https://evil.example")
	if _, _, err := e.p.Callback(context.Background(), q, login); idp.ClassOf(err) != idp.Fatal || !strings.Contains(fmt.Sprint(err), "iss mismatch") {
		t.Fatalf("wrong iss: %v", err)
	}
	q.Del("iss")
	if _, _, err := e.p.Callback(context.Background(), q, login); idp.ClassOf(err) != idp.Fatal || !strings.Contains(fmt.Sprint(err), "iss mismatch") {
		t.Fatalf("missing iss: %v", err)
	}
}

func TestCallbackAcceptsMissingIssWhenNotAdvertised(t *testing.T) {
	e := newEnv(t, Config{}, fakeidp.WithIssParameter(false))
	if _, _, err := e.p.Callback(context.Background(), signIn(t, e, login), login); err != nil {
		t.Fatal(err)
	}
}

func TestCallbackRejects(t *testing.T) {
	for name, tc := range map[string]struct {
		edit   func(q url.Values, l *idp.Login)
		reason string
	}{
		"other state":    {edit: func(q url.Values, _ *idp.Login) { q.Set("state", "other") }, reason: "state mismatch"},
		"other nonce":    {edit: func(_ url.Values, l *idp.Login) { l.Nonce = "other" }, reason: "nonce mismatch"},
		"wrong verifier": {edit: func(_ url.Values, l *idp.Login) { l.CodeVerifier = strings.Repeat("a", 43) }, reason: "invalid_grant"},
	} {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t, Config{})
			q := signIn(t, e, login)
			l := login
			tc.edit(q, &l)
			if _, _, err := e.p.Callback(context.Background(), q, l); err == nil || !strings.Contains(err.Error(), tc.reason) {
				t.Fatalf("err = %v, want %q", err, tc.reason)
			}
		})
	}
}

func TestCallbackErrorResponseIsClassified(t *testing.T) {
	e := newEnv(t, Config{}, fakeidp.FailAuthorize(&fakeidp.UserNotAssigned))
	_, _, err := e.p.Callback(context.Background(), signIn(t, e, login), login)
	var ie *idp.Error
	if !asError(err, &ie) || ie.OAuth != "access_denied" || ie.Class != idp.Fatal || ie.UserMessage == "" {
		t.Fatalf("err = %#v", err)
	}
}

func TestDiscoveryIssuerMustMatchExactly(t *testing.T) {
	e := newEnv(t, Config{}, fakeidp.WithIssuer("https://other.example"))
	p, err := New(Config{Issuer: e.fake.URL(), ClientID: e.client.ID, RedirectURL: redirect, AllowLoopbackHTTP: true})
	if err != nil {
		t.Fatal(err)
	}
	err = p.Ready(context.Background())
	if idp.ClassOf(err) != idp.Fatal || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("err = %v", err)
	}
	// Errors are not cached: once the IdP is fixed, discovery succeeds.
	e.fake.Set(fakeidp.WithIssuer(""))
	if err := p.Ready(context.Background()); err != nil {
		t.Fatalf("after fix: %v", err)
	}
}

type refused struct{}

func (refused) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, errors.New("connection refused")
}

func TestDiscoveryUnreachableIsUnavailable(t *testing.T) {
	p, err := New(Config{Issuer: "https://idp.example", ClientID: "c", RedirectURL: redirect, HTTPClient: &http.Client{Transport: refused{}}})
	if err != nil {
		t.Fatal(err)
	}
	p.fetch.Backoff = 0
	if idp.ClassOf(p.Ready(context.Background())) != idp.Unavailable {
		t.Fatal("unreachable discovery is not Unavailable")
	}
}

func TestRefreshReturnsIdentityAndFreshTokens(t *testing.T) {
	e := newEnv(t, Config{})
	_, tok, err := e.p.Callback(context.Background(), signIn(t, e, login), login)
	if err != nil {
		t.Fatal(err)
	}
	id, fresh, err := e.p.Refresh(context.Background(), tok.RefreshToken)
	if err != nil {
		t.Fatal(err)
	}
	if id == nil || id.Subject != e.fake.User().Subject || fresh.AccessToken == "" {
		t.Fatalf("identity %+v, tokens %v", id, fresh)
	}
}

func TestTokenErrorsAreClassified(t *testing.T) {
	for name, tc := range map[string]struct {
		f     *fakeidp.Failure
		class idp.Class
		alert idp.Alert
	}{
		"invalid_grant":   {&fakeidp.RefreshTokenExpired, idp.SignInAgain, ""},
		"invalid_client":  {&fakeidp.InvalidClientSecret, idp.Unavailable, idp.AlertCredentialRejected},
		"503":             {&fakeidp.TemporarilyUnavailable, idp.Unavailable, ""},
		"invalid_request": {&fakeidp.InvalidRequest, idp.Fatal, ""},
		// The same failure as Entra's 700016 row: the app is unknown, so both adapters alert.
		"unknown app": {&fakeidp.UnknownClient, idp.Fatal, idp.AlertCredentialRejected},
	} {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t, Config{})
			_, tok, err := e.p.Callback(context.Background(), signIn(t, e, login), login)
			if err != nil {
				t.Fatal(err)
			}
			e.fake.Set(fakeidp.FailToken(fakeidp.GrantRefreshToken, tc.f))
			_, _, err = e.p.Refresh(context.Background(), tok.RefreshToken)
			var ie *idp.Error
			if !asError(err, &ie) || ie.Class != tc.class || ie.Alert != tc.alert {
				t.Fatalf("err = %#v", err)
			}
		})
	}
}

func TestPrivateKeyJWTWithKid(t *testing.T) {
	cert := fakeidp.NewCertificate(t)
	ca, err := idp.PrivateKeyJWT(cert.Key, nil, cert.ThumbprintSHA256())
	if err != nil {
		t.Fatal(err)
	}
	e := newEnv(t, Config{ClientAuth: ca})
	c := e.client
	c.Secrets, c.Certificates = nil, []*fakeidp.Certificate{cert}
	e.fake.Set(fakeidp.WithClient(c))
	if _, _, err := e.p.Callback(context.Background(), signIn(t, e, login), login); err != nil {
		t.Fatal(err)
	}
}

func TestPublicClientSignsInWithoutCredential(t *testing.T) {
	c := fakeidp.Client{ID: fakeidp.NewGUID(), RedirectURIs: []string{redirect}}
	fake := fakeidp.New(t, fakeidp.Generic, fakeidp.WithClient(c), fakeidp.WithClock(now))
	p, err := New(Config{Issuer: fake.Issuer(), ClientID: c.ID, RedirectURL: redirect, Now: now, AllowLoopbackHTTP: true})
	if err != nil {
		t.Fatal(err)
	}
	e := &env{fake: fake, client: c, p: p}
	if _, _, err := p.Callback(context.Background(), signIn(t, e, login), login); err != nil {
		t.Fatal(err)
	}
}

func TestNonSubSubjectClaimWarnsAndKeysOnThatClaim(t *testing.T) {
	e := newEnv(t, Config{SubjectClaim: "email"}, fakeidp.WithUser(fakeidp.User{Email: "test.user@contoso.example"}))
	if len(e.p.Warnings()) != 1 {
		t.Fatalf("warnings = %v", e.p.Warnings())
	}
	id, _, err := e.p.Callback(context.Background(), signIn(t, e, login), login)
	if err != nil || id.Subject != "test.user@contoso.example" {
		t.Fatalf("subject %q, err %v", id.Subject, err)
	}
	if len(newEnv(t, Config{}).p.Warnings()) != 0 {
		t.Error("warning for sub")
	}
}

func TestGooglePresetQuirks(t *testing.T) {
	e := newEnv(t, Config{Preset: "google", HostedDomain: "contoso.example"},
		fakeidp.WithEmailVerifiedAsString(true),
		fakeidp.WithUser(fakeidp.User{Email: "test.user@contoso.example", EmailVerified: true, HostedDomain: "contoso.example"}))
	raw, _ := e.p.AuthCodeURL(context.Background(), login)
	if u, _ := url.Parse(raw); u.Query().Get("access_type") != "offline" || strings.Contains(u.Query().Get("scope"), "offline_access") ||
		u.Query().Get("hd") != "contoso.example" {
		t.Errorf("google login URL = %s", raw)
	}
	id, _, err := e.p.Callback(context.Background(), signIn(t, e, login), login)
	if err != nil || !id.EmailVerified {
		t.Fatalf("identity %+v, err %v", id, err)
	}

	e.fake.Set(fakeidp.WithUser(fakeidp.User{HostedDomain: "other.example"}))
	if _, _, err := e.p.Callback(context.Background(), signIn(t, e, login), login); err == nil {
		t.Fatal("other hosted domain accepted")
	}
}

// An email is verified only when the ID token says email_verified true: the boolean, or the string
// "true" from an IdP whose preset sends strings (Google). Absent, false, the string "false" or a
// string from an IdP without that preset is unverified (ADR-0016, 2026-11-07 amendment).
func TestAnEmailIsVerifiedOnlyWhenTheIDTokenSaysTrue(t *testing.T) {
	for _, tc := range []struct {
		name     string
		preset   string
		verified bool   // the user's email_verified
		sends    string // how the IdP sends it: "bool", "string" or "absent"
		want     bool
	}{
		{"the boolean true", "", true, "bool", true},
		{"the boolean false", "", false, "bool", false},
		{"no email_verified claim", "", true, "absent", false},
		{"the string true without a preset that sends strings", "", true, "string", false},
		{"Google's string true", "google", true, "string", true},
		{"Google's string false", "google", false, "string", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := newEnv(t, Config{Preset: tc.preset}, fakeidp.WithEmailVerifiedAsString(tc.sends == "string"), fakeidp.WithoutEmailVerified(tc.sends == "absent"),
				fakeidp.WithUser(fakeidp.User{Email: "test.user@contoso.example", EmailVerified: tc.verified}))
			id, _, err := e.p.Callback(context.Background(), signIn(t, e, login), login)
			if err != nil || id.Email == "" || id.EmailVerified != tc.want {
				t.Fatalf("identity %+v, err %v; want EmailVerified %v", id, err, tc.want)
			}
		})
	}
}

func TestAMisconfiguredIssuerOrClientIsRefusedAndAGoodOneAccepted(t *testing.T) {
	ok := Config{Issuer: "https://idp.example", ClientID: "c", RedirectURL: redirect}
	for name, edit := range map[string]func(*Config){
		"unknown preset":                    func(c *Config) { c.Preset = "github" },
		"no issuer":                         func(c *Config) { c.Issuer = "" },
		"no client":                         func(c *Config) { c.ClientID = "" },
		"http issuer":                       func(c *Config) { c.Issuer = "http://idp.example" },
		"okta org server":                   func(c *Config) { c.Preset, c.Issuer = "okta", "https://x.okta.com" },
		"auth0 without slash":               func(c *Config) { c.Preset, c.Issuer = "auth0", "https://x.auth0.com" },
		"keycloak without realms":           func(c *Config) { c.Preset, c.Issuer = "keycloak", "https://kc.example" },
		"loopback http outside development": func(c *Config) { c.Issuer = "http://127.0.0.1:9000" },
	} {
		c := ok
		edit(&c)
		if _, err := New(c); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	for name, edit := range map[string]func(*Config){
		"plain":                        func(*Config) {},
		"okta custom":                  func(c *Config) { c.Preset, c.Issuer = "okta", "https://x.okta.com/oauth2/default" },
		"auth0":                        func(c *Config) { c.Preset, c.Issuer = "auth0", "https://x.auth0.com/" },
		"keycloak":                     func(c *Config) { c.Preset, c.Issuer = "keycloak", "https://kc.example/realms/r" },
		"loopback http in development": func(c *Config) { c.Issuer, c.AllowLoopbackHTTP = "http://127.0.0.1:9000", true },
		"https on a private address":   func(c *Config) { c.Issuer = "https://10.0.0.5/realms/r" },
	} {
		c := ok
		edit(&c)
		if _, err := New(c); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestDiscoveredEndpointsMustBeHTTPSUnlessALoopbackIssuerRunsInDevelopment(t *testing.T) {
	for _, tc := range []struct {
		name, raw, issuer string
		development, ok   bool
	}{
		{"https", "https://idp.example/token", "https://idp.example", false, true},
		{"http for an https issuer", "http://evil.example/token", "https://idp.example", false, false},
		{"http for an https issuer in development", "http://evil.example/token", "https://idp.example", true, false},
		{"loopback http for an https issuer in development", "http://127.0.0.1/token", "https://idp.example", true, false},
		{"a relative endpoint", "/relative", "https://idp.example", false, false},
		{"https without a host", "https:///token", "https://idp.example", false, false},
		{"loopback http outside development", "http://127.0.0.1:9000/token", "http://127.0.0.1:9000", false, false},
		{"loopback http of a loopback issuer in development", "http://127.0.0.1:9000/token", "http://127.0.0.1:9000", true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := checkURL(tc.raw, tc.issuer, tc.development); (err == nil) != tc.ok {
				t.Fatalf("checkURL(%q, %q, development %v) = %v, want ok %v", tc.raw, tc.issuer, tc.development, err, tc.ok)
			}
		})
	}
}

func asError(err error, target **idp.Error) bool { return errors.As(err, target) }

func TestRefreshWithoutTokenSignsInAgain(t *testing.T) {
	e := newEnv(t, Config{})
	if _, _, err := e.p.Refresh(context.Background(), ""); idp.ClassOf(err) != idp.SignInAgain {
		t.Fatalf("err = %v", err)
	}
}

func validClaims(iss, aud string) map[string]any {
	return map[string]any{"iss": iss, "aud": aud, "sub": "u1", "nonce": "nonce-1", "iat": now().Unix(), "exp": now().Add(time.Hour).Unix()}
}

func TestIDTokenIssuerMustBeTheConfiguredOne(t *testing.T) {
	e := newEnv(t, Config{})
	if err := e.p.Ready(context.Background()); err != nil {
		t.Fatal(err)
	}
	for iss, ok := range map[string]bool{e.p.cfg.Issuer: true, e.p.cfg.Issuer + "/": false, "https://evil.example": false} {
		_, err := e.p.identity(context.Background(), e.fake.Mint(validClaims(iss, e.client.ID)), "nonce-1")
		if ok != (err == nil) || (!ok && (idp.ClassOf(err) != idp.Fatal || !strings.Contains(err.Error(), "issuer"))) {
			t.Errorf("iss %q: err = %v", iss, err)
		}
	}
}

func TestGooglePresetAcceptsBothIssuerForms(t *testing.T) {
	fake := fakeidp.New(t, fakeidp.Generic)
	p, err := New(Config{Preset: "google", Issuer: "https://accounts.google.com", ClientID: "cid", RedirectURL: redirect, Now: now})
	if err != nil {
		t.Fatal(err)
	}
	// Point the key set at the fake; discovery of the real Google is not needed for this rule.
	p.keys = idp.NewKeySet(idp.NewFetcher(nil), fake.JWKSURL(""), now)
	for iss, ok := range map[string]bool{"https://accounts.google.com": true, "accounts.google.com": true, "https://accounts.google.com/": false} {
		_, err := p.identity(context.Background(), fake.Mint(validClaims(iss, "cid")), "nonce-1")
		if ok != (err == nil) {
			t.Errorf("iss %q: err = %v", iss, err)
		}
	}
}

func TestTokenTransportFailureIsUnavailable(t *testing.T) {
	e := newEnv(t, Config{})
	if err := e.p.Ready(context.Background()); err != nil {
		t.Fatal(err)
	}
	e.p.fetch.Client = &http.Client{Transport: refused{}}
	_, _, err := e.p.Refresh(context.Background(), "rt")
	var ie *idp.Error
	if !asError(err, &ie) || ie.Class != idp.Unavailable || ie.Alert != "" {
		t.Fatalf("err = %#v", err)
	}
}

// A token answer that succeeds without tokens breaks the protocol: Fatal, never Unavailable.
func TestATokenSuccessWithoutTokensIsFatal(t *testing.T) {
	e := newEnv(t, Config{})
	if err := e.p.Ready(context.Background()); err != nil {
		t.Fatal(err)
	}
	e.p.fetch.Client = &http.Client{Transport: emptySuccess{}}
	_, _, err := e.p.Refresh(context.Background(), "rt")
	var ie *idp.Error
	if !asError(err, &ie) || ie.Class != idp.Fatal || ie.Alert != idp.AlertProtocol {
		t.Fatalf("err = %#v, want Fatal with an operator alert", err)
	}
}

// emptySuccess answers every request 200 with an empty JSON object.
type emptySuccess struct{}

func (emptySuccess) RoundTrip(r *http.Request) (*http.Response, error) {
	return &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": {"application/json"}},
		Body: io.NopCloser(strings.NewReader("{}")), Request: r}, nil
}

func TestConcurrentFirstLoginsShareDiscovery(t *testing.T) {
	e := newEnv(t, Config{})
	errs := make(chan error, 8)
	for range 8 {
		go func() {
			_, err := e.p.AuthCodeURL(context.Background(), login)
			errs <- err
		}()
	}
	for range 8 {
		if err := <-errs; err != nil {
			t.Fatal(err)
		}
	}
}

func TestRefreshWhileJWKSIsDownIsUnavailable(t *testing.T) {
	clock := fakeidp.NewClock(now())
	e := newEnv(t, Config{Now: clock.Now}, fakeidp.WithClock(clock.Now))
	e.p.fetch.Backoff = 0 // the outage fails fast instead of sleeping through retries
	_, tok, err := e.p.Callback(context.Background(), signIn(t, e, login), login)
	if err != nil {
		t.Fatal(err)
	}
	e.fake.RotateKeys(t)
	e.fake.Set(fakeidp.WithJWKSUnavailable(true))
	clock.Advance(idp.MinJWKSRefresh)
	_, _, err = e.p.Refresh(context.Background(), tok.RefreshToken)
	var ie *idp.Error
	if !errors.As(err, &ie) || ie.Class != idp.Unavailable || ie.OperatorHint != "" {
		t.Fatalf("err = %#v, want Unavailable without a hint", err)
	}
}

// Silent sends prompt=none, and wins over SelectAccount: a silent sign-in must never show a page.
func TestASilentLoginAsksTheIdPWithPromptNoneEvenWhenAccountSelectionIsAsked(t *testing.T) {
	e := newEnv(t, Config{})
	l := login
	l.Silent, l.SelectAccount = true, true
	raw, err := e.p.AuthCodeURL(context.Background(), l)
	if err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(raw)
	if got := u.Query()["prompt"]; len(got) != 1 || got[0] != "none" {
		t.Fatalf("prompt = %q, want only none", got)
	}
}

// The IdP is the operator's, not client-supplied, so its discovery is not behind the SSRF guard:
// a self-hosted IdP on a private or loopback address works over https (ADR-0011 §7).
func TestAnHTTPSIssuerOnANonPublicAddressIsDiscovered(t *testing.T) {
	var srv *httptest.Server
	srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprintf(w, `{"issuer":%q,"authorization_endpoint":%q,"token_endpoint":%q,"jwks_uri":%q}`,
			srv.URL+"/realms/r", srv.URL+"/realms/r/auth", srv.URL+"/realms/r/token", srv.URL+"/realms/r/certs")
	}))
	t.Cleanup(srv.Close)
	p, err := New(Config{Preset: "keycloak", Issuer: srv.URL + "/realms/r", ClientID: "c", RedirectURL: redirect, HTTPClient: srv.Client()})
	if err != nil {
		t.Fatal(err)
	}
	if err := p.Ready(context.Background()); err != nil {
		t.Fatalf("discovery of an https issuer on %s: %v", srv.URL, err)
	}
}

// Google returns a refresh token only on the first code exchange, so every sign-in asks for
// consent again; asking to pick an account keeps that (prompt is a list). A silent sign-in sends
// none alone, which may not be combined with other values (OIDC Core §3.1.2.1): it accepts that
// Google may return no new refresh token.
func TestGoogleIsAskedForConsentEverySignInExceptASilentOne(t *testing.T) {
	e := newEnv(t, Config{Preset: "google"})
	for name, tc := range map[string]struct {
		selectAccount, silent bool
		want                  string
	}{
		"plain":                             {want: "consent"},
		"selecting an account":              {selectAccount: true, want: "consent select_account"},
		"silent":                            {silent: true, want: "none"},
		"silent, also selecting an account": {selectAccount: true, silent: true, want: "none"},
	} {
		l := login
		l.SelectAccount, l.Silent = tc.selectAccount, tc.silent
		raw, err := e.p.AuthCodeURL(context.Background(), l)
		if err != nil {
			t.Fatal(err)
		}
		u, _ := url.Parse(raw)
		if got := u.Query()["prompt"]; len(got) != 1 || got[0] != tc.want || u.Query().Get("access_type") != "offline" {
			t.Errorf("%s: prompt %q access_type %q, want only %q and offline", name, got, u.Query().Get("access_type"), tc.want)
		}
	}
}

// A credential the proxy cannot make (an assertion file that is missing) fails before any request,
// as an ErrCredential that alerts the operator, the same as with Entra.
func TestAnUnusableClientCredentialAlertsTheOperator(t *testing.T) {
	e := newEnv(t, Config{ClientAuth: idp.AssertionFile(t.TempDir() + "/missing-token")})
	_, _, err := e.p.Refresh(context.Background(), "rt")
	var ie *idp.Error
	if !errors.Is(err, idp.ErrCredential) || !errors.As(err, &ie) || ie.Class != idp.Unavailable || ie.Alert != idp.AlertCredentialUnusable {
		t.Fatalf("err = %v, want an alerting, unavailable ErrCredential", err)
	}
}

// #204: the callback query is the browser's, so an invalid_client in it is forgeable and never an
// operator alert; only the token endpoint's answer can say the proxy's credential was refused.
func TestACallbackErrorNeverAlertsTheOperator(t *testing.T) {
	for _, oauth := range []string{"invalid_client", "unauthorized_client"} { // both alert at the token endpoint
		t.Run(oauth, func(t *testing.T) {
			e := newEnv(t, Config{})
			q := signIn(t, e, login)
			q.Del("code")
			q.Set("error", oauth)
			_, _, err := e.p.Callback(context.Background(), q, login)
			var ie *idp.Error
			if !errors.As(err, &ie) || ie.OAuth != oauth || ie.Alert != "" {
				t.Fatalf("err = %#v, want the IdP's %s without an alert", err, oauth)
			}
		})
	}
}
