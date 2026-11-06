package oidc

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/corker/mcp-authproxy/internal/idp"
	"github.com/corker/mcp-authproxy/internal/testutil/fakeidp"
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
	fake := fakeidp.New(t, fakeidp.Generic, append([]fakeidp.Option{fakeidp.WithClient(c)}, opts...)...)
	if cfg.Issuer == "" {
		cfg.Issuer = fake.Issuer()
	}
	cfg.ClientID, cfg.RedirectURL = c.ID, redirect
	if cfg.ClientAuth == nil {
		cfg.ClientAuth = idp.ClientSecret(secret)
	}
	p, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return &env{fake: fake, client: c, p: p}
}

var login = idp.Login{State: "state-1", Nonce: "nonce-1", CodeVerifier: "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"}

// signIn follows the login URL to the fake (auto-login) and returns the callback query.
func signIn(t *testing.T, e *env, l idp.Login) url.Values {
	t.Helper()
	u, err := e.p.AuthCodeURL(context.Background(), l)
	if err != nil {
		t.Fatal(err)
	}
	c := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := c.Get(u)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	loc, err := url.Parse(resp.Header.Get("Location"))
	if err != nil || resp.StatusCode != http.StatusFound {
		t.Fatalf("authorize: status %d, %v", resp.StatusCode, err)
	}
	return loc.Query()
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
		len(id.Groups) != 1 || id.Claims["nonce"] != "nonce-1" {
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
	if _, _, err := e.p.Callback(context.Background(), q, login); err == nil {
		t.Fatal("wrong iss accepted")
	}
	q.Del("iss")
	if _, _, err := e.p.Callback(context.Background(), q, login); err == nil {
		t.Fatal("missing iss accepted")
	}
}

func TestCallbackWithoutIssWhenNotAdvertised(t *testing.T) {
	e := newEnv(t, Config{}, fakeidp.WithIssParameter(false))
	if _, _, err := e.p.Callback(context.Background(), signIn(t, e, login), login); err != nil {
		t.Fatal(err)
	}
}

func TestCallbackRejects(t *testing.T) {
	for name, tc := range map[string]struct {
		edit func(q url.Values, l *idp.Login)
	}{
		"other state":    {edit: func(q url.Values, _ *idp.Login) { q.Set("state", "other") }},
		"other nonce":    {edit: func(_ url.Values, l *idp.Login) { l.Nonce = "other" }},
		"wrong verifier": {edit: func(_ url.Values, l *idp.Login) { l.CodeVerifier = strings.Repeat("a", 43) }},
	} {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t, Config{})
			q := signIn(t, e, login)
			l := login
			tc.edit(q, &l)
			if _, _, err := e.p.Callback(context.Background(), q, l); err == nil {
				t.Fatal("accepted")
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
	p, err := New(Config{Issuer: e.fake.URL(), ClientID: e.client.ID, RedirectURL: redirect})
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

func TestDiscoveryUnreachableIsUnavailable(t *testing.T) {
	p, err := New(Config{Issuer: "http://127.0.0.1:1", ClientID: "c", RedirectURL: redirect})
	if err != nil {
		t.Fatal(err)
	}
	p.fetch.Backoff = 0
	if idp.ClassOf(p.Ready(context.Background())) != idp.Unavailable {
		t.Fatal("unreachable discovery is not Unavailable")
	}
}

func TestRefresh(t *testing.T) {
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
		alert bool
	}{
		"invalid_grant":   {&fakeidp.RefreshTokenExpired, idp.SignInAgain, false},
		"invalid_client":  {&fakeidp.InvalidClientSecret, idp.Unavailable, true},
		"503":             {&fakeidp.TemporarilyUnavailable, idp.Unavailable, false},
		"invalid_request": {&fakeidp.InvalidRequest, idp.Fatal, false},
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

func TestPublicClient(t *testing.T) {
	c := fakeidp.Client{ID: fakeidp.NewGUID(), RedirectURIs: []string{redirect}}
	fake := fakeidp.New(t, fakeidp.Generic, fakeidp.WithClient(c))
	p, err := New(Config{Issuer: fake.Issuer(), ClientID: c.ID, RedirectURL: redirect})
	if err != nil {
		t.Fatal(err)
	}
	e := &env{fake: fake, client: c, p: p}
	if _, _, err := p.Callback(context.Background(), signIn(t, e, login), login); err != nil {
		t.Fatal(err)
	}
}

func TestSubjectClaim(t *testing.T) {
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
	if u, _ := url.Parse(raw); u.Query().Get("access_type") != "offline" || strings.Contains(u.Query().Get("scope"), "offline_access") {
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

func TestStringEmailVerifiedOnlyWithPreset(t *testing.T) {
	e := newEnv(t, Config{}, fakeidp.WithEmailVerifiedAsString(true),
		fakeidp.WithUser(fakeidp.User{Email: "test.user@contoso.example", EmailVerified: true}))
	id, _, err := e.p.Callback(context.Background(), signIn(t, e, login), login)
	if err != nil || id.EmailVerified {
		t.Fatalf("string email_verified honoured without preset: %+v %v", id, err)
	}
}

func TestGoogleAcceptsBareIssuer(t *testing.T) {
	p := &Provider{cfg: Config{Issuer: "https://accounts.google.com"}, preset: Presets["google"]}
	if alt := p.preset.AlsoAcceptIssuer(p.cfg.Issuer); alt != "accounts.google.com" {
		t.Fatalf("alt = %q", alt)
	}
}

func TestNewValidates(t *testing.T) {
	ok := Config{Issuer: "https://idp.example", ClientID: "c", RedirectURL: redirect}
	for name, edit := range map[string]func(*Config){
		"unknown preset":          func(c *Config) { c.Preset = "github" },
		"no issuer":               func(c *Config) { c.Issuer = "" },
		"no client":               func(c *Config) { c.ClientID = "" },
		"http issuer":             func(c *Config) { c.Issuer = "http://idp.example" },
		"okta org server":         func(c *Config) { c.Preset, c.Issuer = "okta", "https://x.okta.com" },
		"auth0 without slash":     func(c *Config) { c.Preset, c.Issuer = "auth0", "https://x.auth0.com" },
		"keycloak without realms": func(c *Config) { c.Preset, c.Issuer = "keycloak", "https://kc.example" },
	} {
		c := ok
		edit(&c)
		if _, err := New(c); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	for name, edit := range map[string]func(*Config){
		"plain":         func(*Config) {},
		"okta custom":   func(c *Config) { c.Preset, c.Issuer = "okta", "https://x.okta.com/oauth2/default" },
		"auth0":         func(c *Config) { c.Preset, c.Issuer = "auth0", "https://x.auth0.com/" },
		"keycloak":      func(c *Config) { c.Preset, c.Issuer = "keycloak", "https://kc.example/realms/r" },
		"loopback http": func(c *Config) { c.Issuer = "http://127.0.0.1:9000" },
	} {
		c := ok
		edit(&c)
		if _, err := New(c); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestDiscoveredEndpointsMustBeHTTPS(t *testing.T) {
	if err := checkURL("http://evil.example/token", "https://idp.example"); err == nil {
		t.Error("http endpoint for https issuer accepted")
	}
	if err := checkURL("http://127.0.0.1/token", "https://idp.example"); err == nil {
		t.Error("loopback http endpoint for https issuer accepted")
	}
	if err := checkURL("/relative", "https://idp.example"); err == nil {
		t.Error("relative endpoint accepted")
	}
}

func TestIdentityKeepsRawClaimsForRules(t *testing.T) {
	e := newEnv(t, Config{}, fakeidp.WithClock(func() time.Time { return time.Now() }))
	id, _, err := e.p.Callback(context.Background(), signIn(t, e, login), login)
	if err != nil || id.Claims["aud"] != e.client.ID {
		t.Fatalf("claims %v, err %v", id.Claims, err)
	}
}

func asError(err error, target **idp.Error) bool {
	e, ok := err.(*idp.Error)
	if ok {
		*target = e
	}
	return ok
}
