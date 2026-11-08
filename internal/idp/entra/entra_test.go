package entra

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/byward-dev/byward/internal/idp"
	"github.com/byward-dev/byward/internal/testutil/fakeidp"
)

const (
	redirect = "https://proxy.example/callback/entra"
	secret   = "test-secret-value"
)

// now is the shared fixed clock of the fake and the adapter.
func now() time.Time { return time.Unix(1_800_000_000, 0) }

var login = idp.Login{State: "state-1", Nonce: "nonce-1", CodeVerifier: "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"}

type env struct {
	fake   *fakeidp.IdP
	client fakeidp.Client
	p      *Provider
}

// newEnv registers the IdP app at a fake Entra and builds the adapter; cfg.Tenant defaults to the
// fake's tenant and cfg.ClientAuth to the client secret.
func newEnv(t *testing.T, cfg Config, opts ...fakeidp.Option) *env {
	t.Helper()
	c := fakeidp.Client{ID: fakeidp.NewGUID(), Secrets: []string{secret}, RedirectURIs: []string{redirect}}
	fake := fakeidp.New(t, fakeidp.Entra, append([]fakeidp.Option{fakeidp.WithClient(c), fakeidp.WithClock(now)}, opts...)...)
	if cfg.Tenant == "" {
		cfg.Tenant = fake.TenantID()
	}
	if cfg.ClientAuth == nil {
		cfg.ClientAuth = idp.ClientSecret(secret)
	}
	cfg.ClientID, cfg.RedirectURL, cfg.HTTPClient = c.ID, redirect, fake.HTTPClient()
	if cfg.Now == nil {
		cfg.Now = now
	}
	p, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	p.fetch.Backoff = 0 // retries are idp's to test; here they would only add wall time
	return &env{fake: fake, client: c, p: p}
}

func signIn(t *testing.T, e *env, l idp.Login) url.Values {
	t.Helper()
	u, err := e.p.AuthCodeURL(context.Background(), l)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(u, Authority+"/") {
		t.Fatalf("login URL %s is not under %s", u, Authority)
	}
	return e.fake.Authorize(t, u)
}

func callback(t *testing.T, e *env) (idp.Identity, idp.Tokens, error) {
	t.Helper()
	return e.p.Callback(context.Background(), signIn(t, e, login), login)
}

func TestLoginKeysUserOnTidOidAndKeepsAccessAsUserToken(t *testing.T) {
	e := newEnv(t, Config{}, fakeidp.WithUser(fakeidp.User{Email: "test.user@contoso.example", Roles: []string{"MCP.User"}, Groups: []string{fakeidp.NewGUID()}}))
	id, tok, err := callback(t, e)
	if err != nil {
		t.Fatal(err)
	}
	u := e.fake.User()
	if id.Subject != u.TenantID+":"+u.OID {
		t.Errorf("subject = %q", id.Subject)
	}
	if k, ok := UserKey(id.Subject); !ok || k != id.Subject {
		t.Errorf("UserKey(%q) = %q, %v: the operator's key must name the user sign-in stores", id.Subject, k, ok)
	}
	if id.Issuer != Authority+"/"+u.TenantID+"/v2.0" || id.EmailVerified || id.Email != u.Email {
		t.Errorf("identity = %+v", id)
	}
	if len(id.Roles) != 1 || len(id.Groups) != 1 || id.GroupsUnavailable {
		t.Errorf("roles %v groups %v unavailable %v", id.Roles, id.Groups, id.GroupsUnavailable)
	}
	if tok.AccessToken == "" || tok.RefreshToken == "" || tok.IDToken == "" {
		t.Errorf("tokens = %v", tok)
	}
}

func TestAuthCodeURLTargetsTenantAuthorizeWithAccessAsUserScope(t *testing.T) {
	e := newEnv(t, Config{})
	l := login
	l.LoginHint, l.DomainHint, l.SelectAccount = "u", "contoso.example", true
	raw, err := e.p.AuthCodeURL(context.Background(), l)
	if err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(raw)
	if got, want := u.Scheme+"://"+u.Host+u.Path, Authority+"/"+e.fake.TenantID()+"/oauth2/v2.0/authorize"; got != want {
		t.Errorf("endpoint = %s, want %s", got, want)
	}
	q := u.Query()
	for k, v := range map[string]string{
		"scope":         "openid profile email offline_access api://" + e.client.ID + "/access_as_user",
		"response_mode": "query", "code_challenge_method": "S256", "code_challenge": idp.CodeChallenge(login.CodeVerifier),
		"nonce": "nonce-1", "state": "state-1", "login_hint": "u", "domain_hint": "contoso.example", "prompt": "select_account",
	} {
		if q.Get(k) != v {
			t.Errorf("%s = %q, want %q", k, q.Get(k), v)
		}
	}
	if q.Has("resource") {
		t.Error("resource sent")
	}
}

func TestGroupsOverageMakesGroupsUnavailable(t *testing.T) {
	e := newEnv(t, Config{}, fakeidp.WithUser(fakeidp.User{Groups: []string{fakeidp.NewGUID()}, GroupsOverage: true}))
	id, _, err := callback(t, e)
	if err != nil || !id.GroupsUnavailable || id.Groups != nil || id.Claims["groups"] != nil {
		t.Fatalf("identity %+v, err %v", id, err)
	}
}

func TestCertificateCredential(t *testing.T) {
	cert := fakeidp.NewCertificate(t)
	ca, err := idp.PrivateKeyJWT(cert.Key, cert.X509, "")
	if err != nil {
		t.Fatal(err)
	}
	e := newEnv(t, Config{ClientAuth: ca})
	c := e.client
	c.Secrets, c.Certificates = nil, []*fakeidp.Certificate{cert}
	e.fake.Set(fakeidp.WithClient(c))
	if _, _, err := callback(t, e); err != nil {
		t.Fatal(err)
	}

	stranger, _ := idp.PrivateKeyJWT(fakeidp.NewCertificate(t).Key, cert.X509, "")
	e.p.cfg.ClientAuth = stranger
	_, _, err = callback(t, e)
	var ie *idp.Error
	if !errors.As(err, &ie) || ie.Code != 700027 || ie.Class != idp.Unavailable || !ie.Alert {
		t.Fatalf("wrong key: %#v", err)
	}
}

func TestOrganizationsAllowlist(t *testing.T) {
	guest := fakeidp.NewGUID()
	e := newEnv(t, Config{Tenant: Organizations, AllowedTenants: []string{guest}}, fakeidp.WithUser(fakeidp.User{TenantID: guest}))
	id, _, err := callback(t, e)
	if err != nil || !strings.HasPrefix(id.Subject, guest+":") || id.Issuer != Authority+"/"+guest+"/v2.0" {
		t.Fatalf("identity %+v, err %v", id, err)
	}
	e.fake.Set(fakeidp.WithUser(fakeidp.User{TenantID: fakeidp.NewGUID()}))
	if _, _, err := callback(t, e); err == nil || !strings.Contains(err.Error(), "not allowed") {
		t.Fatalf("tenant outside the allowlist: %v", err)
	}
}

// v2Claims are valid claims of a token from tenant tid for client.
func v2Claims(tid, client string) map[string]any {
	return map[string]any{"iss": issuerFor(tid), "aud": client, "tid": tid, "oid": fakeidp.NewGUID(), "ver": "2.0",
		"sub": "pairwise", "iat": now().Unix(), "exp": now().Add(time.Hour).Unix()}
}

func TestSingleTenantRejectsAnotherTenantsIDToken(t *testing.T) {
	e := newEnv(t, Config{})
	_, err := e.p.identity(context.Background(), e.fake.Mint(v2Claims(fakeidp.NewGUID(), e.client.ID)), "")
	if err == nil || !strings.Contains(err.Error(), "not the configured tenant") {
		t.Fatalf("err = %v", err)
	}
}

func TestHasGroupsMeansGroupsUnavailable(t *testing.T) {
	e := newEnv(t, Config{})
	for has, want := range map[bool]bool{true: true, false: false} {
		c := v2Claims(e.fake.TenantID(), e.client.ID)
		c["hasgroups"] = has
		id, err := e.p.identity(context.Background(), e.fake.Mint(c), "")
		if err != nil || id.GroupsUnavailable != want || id.Groups != nil {
			t.Errorf("hasgroups %v: identity %+v err %v", has, id, err)
		}
	}
}

func TestAccessTokenMustBeOwnV2AccessAsUser(t *testing.T) {
	e := newEnv(t, Config{})
	tid := e.fake.TenantID()
	withScp := func(c map[string]any, scp string) map[string]any { c["scp"] = scp; return c }
	graph := withScp(v2Claims(tid, fakeidp.GraphAppID), "User.Read")
	graph["iss"], graph["ver"] = "https://sts.windows.net/"+tid+"/", "1.0"
	for name, tc := range map[string]struct {
		raw string
		ok  bool
	}{
		"own access_as_user": {raw: e.fake.Mint(withScp(v2Claims(tid, e.client.ID), "access_as_user")), ok: true},
		"missing":            {raw: ""},
		"other scope":        {raw: e.fake.Mint(withScp(v2Claims(tid, e.client.ID), "User.Read"))},
		"Graph v1 token":     {raw: e.fake.Mint(graph)},
	} {
		t.Run(name, func(t *testing.T) {
			err := e.p.checkAccessToken(context.Background(), tc.raw)
			if tc.ok {
				if err != nil {
					t.Fatal(err)
				}
				return
			}
			var ie *idp.Error
			if !errors.As(err, &ie) || ie.Class != idp.Fatal || !strings.Contains(ie.OperatorHint, "requestedAccessTokenVersion") {
				t.Fatalf("err = %#v", err)
			}
		})
	}
}

func TestIssuerMustMatchTokenTenantAndAllowlist(t *testing.T) {
	tid := fakeidp.NewGUID()
	single := &Provider{cfg: Config{Tenant: tid}}
	multi := &Provider{cfg: Config{Tenant: Organizations}, allowed: map[string]bool{tid: true}}
	v2 := func(t, iss string) map[string]any { return map[string]any{"tid": t, "ver": "2.0", "iss": iss} }
	for name, tc := range map[string]struct {
		p      *Provider
		claims map[string]any
		ok     bool
	}{
		"single ok":         {single, v2(tid, issuerFor(tid)), true},
		"single upper tid":  {single, v2(strings.ToUpper(tid), issuerFor(tid)), true},
		"single other tid":  {single, v2(fakeidp.NewGUID(), issuerFor(tid)), false},
		"iss for other tid": {single, v2(tid, issuerFor(fakeidp.NewGUID())), false},
		"v1 issuer":         {single, v2(tid, "https://sts.windows.net/"+tid+"/"), false},
		"template iss":      {multi, v2(tid, issuerFor("{tenantid}")), false},
		"multi ok":          {multi, v2(tid, issuerFor(tid)), true},
		"multi not allowed": {multi, v2(fakeidp.NewGUID(), issuerFor(tid)), false},
		"tid not a GUID":    {multi, v2("organizations", issuerFor("organizations")), false},
		"ver 1.0":           {single, map[string]any{"tid": tid, "ver": "1.0", "iss": issuerFor(tid)}, false},
	} {
		t.Run(name, func(t *testing.T) {
			err := tc.p.checkIssuer(tc.claims["iss"].(string), tc.claims)
			if (err == nil) != tc.ok {
				t.Fatalf("err = %v, want ok %v", err, tc.ok)
			}
		})
	}
}

func TestReadyChecksDiscoveryIssuer(t *testing.T) {
	e := newEnv(t, Config{})
	if err := e.p.Ready(context.Background()); err != nil {
		t.Fatal(err)
	}
	guest := fakeidp.NewGUID()
	org := newEnv(t, Config{Tenant: Organizations, AllowedTenants: []string{guest}})
	if err := org.p.Ready(context.Background()); err != nil {
		t.Fatal(err)
	}
	wrong := newEnv(t, Config{}, fakeidp.WithAuthority("https://login.example"))
	if err := wrong.p.Ready(context.Background()); err == nil || idp.ClassOf(err) != idp.Fatal {
		t.Fatalf("issuer under another authority: %v", err)
	}
}

func TestRefreshReturnsNoRefreshTokenWhenEntraDoesNotRotate(t *testing.T) {
	e := newEnv(t, Config{})
	_, tok, err := callback(t, e)
	if err != nil {
		t.Fatal(err)
	}
	id, fresh, err := e.p.Refresh(context.Background(), tok.RefreshToken)
	if err != nil || id == nil || fresh.RefreshToken == "" || fresh.AccessToken == "" {
		t.Fatalf("identity %+v tokens %v err %v", id, fresh, err)
	}
	e.fake.Set(fakeidp.WithRefreshTokenRotation(false))
	if _, fresh, err = e.p.Refresh(context.Background(), tok.RefreshToken); err != nil || fresh.RefreshToken != "" {
		t.Fatalf("without rotation: tokens %v err %v", fresh, err)
	}
}

func TestTokenErrorsMapToADR0012Classes(t *testing.T) {
	for name, tc := range map[string]struct {
		f     *fakeidp.Failure
		class idp.Class
		alert bool
		code  int
		paged bool
	}{
		"700082 expired":      {&fakeidp.RefreshTokenExpired, idp.SignInAgain, false, 700082, false},
		"50076 MFA":           {&fakeidp.MFARequired, idp.SignInAgain, false, 50076, false},
		"65001 consent":       {&fakeidp.ConsentRequired, idp.SignInAgain, false, 65001, true},
		"50173 revoked":       {&fakeidp.RefreshTokenRevoked, idp.SignInAgain, false, 50173, false},
		"7000215 secret":      {&fakeidp.InvalidClientSecret, idp.Unavailable, true, 7000215, false},
		"7000222 expired key": {&fakeidp.ExpiredClientSecret, idp.Unavailable, true, 7000222, true},
		"503":                 {&fakeidp.TemporarilyUnavailable, idp.Unavailable, false, 0, false},
		"invalid_request":     {&fakeidp.InvalidRequest, idp.Fatal, false, 9002313, false},
		"700016 unknown app":  {&fakeidp.UnknownClient, idp.Unavailable, true, 700016, true},
		"5002723 thumbprint":  {&fakeidp.MissingThumbprint, idp.Unavailable, true, 5002723, false},
		"70043 by code":       {&fakeidp.Failure{Error: "invalid_request", Code: 70043}, idp.SignInAgain, false, 70043, false},
		"429":                 {&fakeidp.Failure{Status: 429, Error: "invalid_request"}, idp.Unavailable, false, 0, false},
		"503 invalid_client":  {&fakeidp.Failure{Status: 503, Error: "invalid_client", Code: 7000215}, idp.Unavailable, true, 7000215, false},
	} {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t, Config{})
			_, tok, err := callback(t, e)
			if err != nil {
				t.Fatal(err)
			}
			e.fake.Set(fakeidp.FailToken(fakeidp.GrantRefreshToken, tc.f))
			reqID := fakeidp.NewGUID()
			_, _, err = e.p.Refresh(idp.WithRequestID(context.Background(), reqID), tok.RefreshToken)
			var ie *idp.Error
			if !errors.As(err, &ie) {
				t.Fatalf("err = %v", err)
			}
			if ie.Class != tc.class || ie.Alert != tc.alert || ie.Code != tc.code {
				t.Errorf("class %v alert %v code %d", ie.Class, ie.Alert, ie.Code)
			}
			if ie.CorrelationID != reqID || ie.TraceID == "" {
				t.Errorf("correlation %q (want request ID %q), trace %q", ie.CorrelationID, reqID, ie.TraceID)
			}
			if (ie.OperatorHint != "") != tc.paged || ie.UserMessage == "" {
				t.Errorf("hint %q, user message %q", ie.OperatorHint, ie.UserMessage)
			}
			if strings.Contains(ie.Error(), "AADSTS") && strings.Contains(ie.Error(), "Trace ID") {
				t.Errorf("Error() carries the raw description: %s", ie.Error())
			}
		})
	}
}

func TestCallbackErrorRedirectIsMapped(t *testing.T) {
	e := newEnv(t, Config{}, fakeidp.FailAuthorize(&fakeidp.UserNotAssigned))
	_, _, err := callback(t, e)
	var ie *idp.Error
	if !errors.As(err, &ie) || ie.Code != 50105 || ie.OperatorHint == "" || strings.Contains(ie.UserMessage, "AADSTS") {
		t.Fatalf("err = %#v", err)
	}
}

func TestNonGUIDRequestIDIsNotSent(t *testing.T) {
	e := newEnv(t, Config{})
	_, tok, _ := callback(t, e)
	e.fake.Set(fakeidp.FailToken(fakeidp.GrantRefreshToken, &fakeidp.RefreshTokenExpired))
	_, _, err := e.p.Refresh(idp.WithRequestID(context.Background(), "not-a-guid"), tok.RefreshToken)
	var ie *idp.Error
	if !errors.As(err, &ie) || ie.CorrelationID == "not-a-guid" || ie.CorrelationID == "" {
		t.Fatalf("err = %#v", err)
	}
}

func TestNewValidates(t *testing.T) {
	ok := Config{Tenant: fakeidp.NewGUID(), ClientID: fakeidp.NewGUID(), ClientAuth: idp.ClientSecret("s"), RedirectURL: redirect}
	for name, edit := range map[string]func(*Config){
		"common":                     func(c *Config) { c.Tenant = "common" },
		"consumers":                  func(c *Config) { c.Tenant = "consumers" },
		"domain tenant":              func(c *Config) { c.Tenant = "contoso.onmicrosoft.com" },
		"organizations no allowlist": func(c *Config) { c.Tenant = Organizations },
		"allowlist not GUIDs":        func(c *Config) { c.Tenant, c.AllowedTenants = Organizations, []string{"contoso"} },
		"allowlist single tenant":    func(c *Config) { c.AllowedTenants = []string{fakeidp.NewGUID()} },
		"client not GUID":            func(c *Config) { c.ClientID = "app" },
		"no credential":              func(c *Config) { c.ClientAuth = nil },
		"no redirect":                func(c *Config) { c.RedirectURL = "" },
	} {
		c := ok
		edit(&c)
		if _, err := New(c); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := New(ok); err != nil {
		t.Fatal(err)
	}
}

func TestErrorCodePrefersErrorCodesOverDescription(t *testing.T) {
	if codeOf([]int{50105}, "AADSTS1: x") != 50105 || codeOf(nil, "AADSTS50105: x") != 50105 || codeOf(nil, "nope") != 0 {
		t.Fatal("codeOf")
	}
}

func TestTokenTransportFailureIsUnavailable(t *testing.T) {
	e := newEnv(t, Config{})
	if err := e.p.Ready(context.Background()); err != nil {
		t.Fatal(err)
	}
	e.p.fetch.Client = &http.Client{Transport: deadline{}}
	_, _, err := e.p.Refresh(context.Background(), "rt")
	var ie *idp.Error
	if !errors.As(err, &ie) || ie.Class != idp.Unavailable || ie.Alert {
		t.Fatalf("err = %#v", err)
	}
}

// A token answer that succeeds without tokens breaks the protocol: Fatal (fail the request, keep the
// grant), never Unavailable, which would tell the client to try the same thing again.
func TestATokenSuccessWithoutTokensIsFatal(t *testing.T) {
	e := newEnv(t, Config{})
	if err := e.p.Ready(context.Background()); err != nil {
		t.Fatal(err)
	}
	e.p.fetch.Client = &http.Client{Transport: emptySuccess{}}
	_, _, err := e.p.Refresh(context.Background(), "rt")
	var ie *idp.Error
	if !errors.As(err, &ie) || ie.Class != idp.Fatal || !ie.Alert {
		t.Fatalf("err = %#v, want Fatal with an operator alert", err)
	}
}

// emptySuccess answers every request 200 with an empty JSON object.
type emptySuccess struct{}

func (emptySuccess) RoundTrip(r *http.Request) (*http.Response, error) {
	return &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": {"application/json"}},
		Body: io.NopCloser(strings.NewReader("{}")), Request: r}, nil
}

type deadline struct{}

func (deadline) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, context.DeadlineExceeded
}

func TestRefreshWithoutTokenSignsInAgainWithoutCallingEntra(t *testing.T) {
	p, err := New(Config{Tenant: fakeidp.NewGUID(), ClientID: fakeidp.NewGUID(), ClientAuth: idp.ClientSecret("s"), RedirectURL: redirect,
		HTTPClient: &http.Client{Transport: failingTransport{t}}, Now: now})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := p.Refresh(context.Background(), ""); idp.ClassOf(err) != idp.SignInAgain {
		t.Fatalf("err = %v", err)
	}
}

type failingTransport struct{ t *testing.T }

func (f failingTransport) RoundTrip(*http.Request) (*http.Response, error) {
	f.t.Error("unexpected network call")
	return nil, errors.New("no network")
}

func TestConcurrentFirstLoginsWaitForReadiness(t *testing.T) {
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

// outageEnv is an env on a step clock whose adapter does not back off between JWKS retries, so an
// outage fails fast.
func outageEnv(t *testing.T) (*env, *fakeidp.Clock) {
	t.Helper()
	clock := fakeidp.NewClock(now())
	e := newEnv(t, Config{Now: clock.Now}, fakeidp.WithClock(clock.Now))
	e.p.fetch.Backoff = 0
	return e, clock
}

func TestRefreshWhileJWKSIsDownIsUnavailable(t *testing.T) {
	e, clock := outageEnv(t)
	_, tok, err := callback(t, e)
	if err != nil {
		t.Fatal(err)
	}
	e.fake.RotateKeys(t) // the refreshed tokens are signed with a kid the cache does not have
	e.fake.Set(fakeidp.WithJWKSUnavailable(true))
	clock.Advance(idp.MinJWKSRefresh)
	_, _, err = e.p.Refresh(context.Background(), tok.RefreshToken)
	var ie *idp.Error
	if !errors.As(err, &ie) || ie.Class != idp.Unavailable {
		t.Fatalf("err = %#v, want Unavailable", err)
	}
}

// checkAccessToken directly: the refresh path above fails on the ID token first.
func TestAccessTokenCheckWhileJWKSIsDownIsUnavailableWithoutHint(t *testing.T) {
	e, clock := outageEnv(t)
	access := func() string {
		c := v2Claims(e.fake.TenantID(), e.client.ID)
		c["scp"] = "access_as_user"
		return e.fake.Mint(c)
	}
	if err := e.p.Ready(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := e.p.checkAccessToken(context.Background(), access()); err != nil { // warms the key cache
		t.Fatal(err)
	}
	e.fake.RotateKeys(t)
	e.fake.Set(fakeidp.WithJWKSUnavailable(true))
	clock.Advance(idp.MinJWKSRefresh)
	var ie *idp.Error
	if err := e.p.checkAccessToken(context.Background(), access()); !errors.As(err, &ie) || ie.Class != idp.Unavailable || ie.OperatorHint != "" {
		t.Fatalf("keys down: %#v", err)
	}
}

// An operator types the user key from the audit stream or the Entra portal (either case); anything
// that is not tid:oid is refused, so a typo cannot pass for a done revocation.
func TestUserKeyAcceptsTidOidInAnyCaseAndRefusesTheRest(t *testing.T) {
	const tid, oid = "00000000-0000-0000-0000-00000000000a", "11111111-1111-1111-1111-11111111111a"
	for _, tc := range []struct {
		name, in, want string
	}{
		{"canonical", tid + ":" + oid, tid + ":" + oid},
		{"upper case", strings.ToUpper(tid + ":" + oid), tid + ":" + oid},
		{"surrounding spaces", "  " + tid + ":" + oid + "\n", tid + ":" + oid},
		{"empty", "", ""},
		{"an email", "alice@contoso.example", ""},
		{"no colon", tid + oid, ""},
		{"one GUID", oid, ""},
		{"an extra segment", tid + ":" + oid + ":x", ""},
		{"tenant not a GUID", "contoso:" + oid, ""},
		{"object not a GUID", tid + ":alice", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := UserKey(tc.in)
			if got != tc.want || ok != (tc.want != "") {
				t.Fatalf("UserKey(%q) = %q, %v; want %q", tc.in, got, ok, tc.want)
			}
		})
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
