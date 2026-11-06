package fakeidp

import (
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestEntraLoginIssuesV2TokensForOwnAPI(t *testing.T) {
	clock := newClock()
	f := newFixture(t, Entra, WithClock(clock.Now), WithUser(User{
		Email: "test.user@contoso.example", Roles: []string{"MCP.User"}, Groups: []string{NewGUID()},
	}))
	u := f.idp.User()
	r := f.login(t)

	if r.str("token_type") != "Bearer" || r.str("refresh_token") == "" {
		t.Fatalf("token response = %v", r.body)
	}
	wantClaim(t, r.body, "scope", f.ownScope())
	wantClaim(t, r.body, "expires_in", 3600)

	iss := "https://login.microsoftonline.com/" + f.tenant + "/v2.0"
	_, id := f.verified(t, r.str("id_token"))
	wantClaim(t, id, "iss", iss)
	wantClaim(t, id, "aud", f.client.ID)
	wantClaim(t, id, "tid", f.tenant)
	wantClaim(t, id, "oid", u.OID)
	wantClaim(t, id, "ver", "2.0")
	wantClaim(t, id, "nonce", "nonce-1")
	wantClaim(t, id, "iat", clock.Now().Unix())
	wantClaim(t, id, "exp", clock.Now().Add(time.Hour).Unix())
	wantClaim(t, id, "email", u.Email)
	wantClaim(t, id, "preferred_username", u.PreferredUsername)
	wantClaim(t, id, "roles", u.Roles)
	wantClaim(t, id, "groups", u.Groups)
	if id["sub"] == u.OID || id["sub"] == "" {
		t.Errorf("Entra sub must be pairwise, got %v", id["sub"])
	}

	header, at := f.verified(t, r.str("access_token"))
	wantClaim(t, header, "typ", "JWT")
	wantClaim(t, at, "iss", iss)
	wantClaim(t, at, "aud", f.client.ID)
	wantClaim(t, at, "scp", "access_as_user")
	wantClaim(t, at, "azp", f.client.ID)
	wantClaim(t, at, "azpacr", "1")
	wantClaim(t, at, "oid", u.OID)
	wantClaim(t, at, "ver", "2.0")
	if _, ok := at["idtyp"]; ok {
		t.Error("delegated token must not carry idtyp=app")
	}
}

func TestEntraPairwiseSubDiffersPerApp(t *testing.T) {
	f := newFixture(t, Entra)
	other := Client{ID: NewGUID(), Secrets: []string{testSecret}, RedirectURIs: []string{testRedirect}}
	f.idp.Set(WithClient(other))

	_, a := f.verified(t, f.login(t).str("id_token"))
	g := &fixture{idp: f.idp, client: other, tenant: f.tenant}
	_, b := g.verified(t, g.login(t).str("id_token"))
	if a["sub"] == b["sub"] || a["oid"] != b["oid"] {
		t.Fatalf("sub a=%v b=%v, oid a=%v b=%v", a["sub"], b["sub"], a["oid"], b["oid"])
	}
	_, again := f.verified(t, f.login(t).str("id_token"))
	if again["sub"] != a["sub"] {
		t.Fatal("pairwise sub is not stable")
	}
}

func TestEntraOwnDefaultScopeReturnsOnlyIDToken(t *testing.T) {
	f := newFixture(t, Entra)
	r := f.redeem(t, f.code(t, url.Values{"scope": {"openid api://" + f.client.ID + "/.default"}}))
	wantStatus(t, r, http.StatusOK)
	if r.str("id_token") == "" || r.str("access_token") != "" {
		t.Fatalf("body = %v, want id_token only", r.body)
	}
}

func TestEntraOIDCOnlyLoginReturnsGraphToken(t *testing.T) {
	f := newFixture(t, Entra)
	r := f.redeem(t, f.code(t, url.Values{"scope": {"openid profile"}}))
	wantStatus(t, r, http.StatusOK)
	_, at := f.verified(t, r.str("access_token"))
	wantClaim(t, at, "aud", GraphAppID)
	if r.str("refresh_token") != "" {
		t.Error("refresh token issued without offline_access")
	}
}

func TestGroupsOverage(t *testing.T) {
	many := make([]string, groupsOverageLimit+1)
	for i := range many {
		many[i] = NewGUID()
	}
	for name, u := range map[string]User{
		"flag":       {Groups: []string{NewGUID()}, GroupsOverage: true},
		"over limit": {Groups: many},
	} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t, Entra, WithUser(u))
			for _, tok := range []string{"id_token", "access_token"} {
				_, c := f.verified(t, f.login(t).str(tok))
				if _, ok := c["groups"]; ok {
					t.Errorf("%s has groups despite overage", tok)
				}
				wantClaim(t, c, "_claim_names", map[string]string{"groups": "src1"})
			}
		})
	}
}

func TestCodeIsSingleUseAndShortLived(t *testing.T) {
	clock := newClock()
	f := newFixture(t, Entra, WithClock(clock.Now))
	code := f.code(t, nil)
	wantStatus(t, f.redeem(t, code), http.StatusOK)
	wantEntraError(t, f.redeem(t, code), 400, "invalid_grant", 54005)

	code = f.code(t, nil)
	clock.Advance(10 * time.Minute)
	wantEntraError(t, f.redeem(t, code), 400, "invalid_grant", 70008)
}

func TestTokenRechecksCodeBinding(t *testing.T) {
	other := Client{ID: NewGUID(), Secrets: []string{testSecret}}
	for name, tc := range map[string]struct {
		form url.Values
		code int
		err  string
	}{
		"wrong verifier":   {form: url.Values{"code_verifier": {strings.Repeat("a", 43)}}, code: 501481, err: "invalid_grant"},
		"missing verifier": {form: url.Values{"code_verifier": {""}}, code: 501481, err: "invalid_grant"},
		"other redirect":   {form: url.Values{"redirect_uri": {"http://127.0.0.1:9/callback/entra"}}, code: 50011, err: "invalid_grant"},
		"other client":     {form: url.Values{"client_id": {other.ID}}, code: 9002313, err: "invalid_grant"},
		"garbage code":     {form: url.Values{"code": {"nope"}}, code: 9002313, err: "invalid_grant"},
	} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t, Entra, WithClient(other))
			form := url.Values{
				"grant_type":    {GrantAuthorizationCode},
				"code":          {f.code(t, nil)},
				"redirect_uri":  {testRedirect},
				"code_verifier": {testVerifier},
			}
			for k, v := range tc.form {
				form[k] = v
			}
			wantEntraError(t, f.token(t, form), 400, tc.err, tc.code)
		})
	}
}

func TestVerifierWithoutChallengeIsRejected(t *testing.T) {
	f := newFixture(t, Entra)
	code := f.code(t, url.Values{"code_challenge": nil, "code_challenge_method": nil})
	wantEntraError(t, f.redeem(t, code), 400, "invalid_grant", 501481)
}

func TestNoPKCEIsAcceptedUnlessRequired(t *testing.T) {
	f := newFixture(t, Entra)
	code := f.code(t, url.Values{"code_challenge": nil, "code_challenge_method": nil})
	r := f.token(t, url.Values{"grant_type": {GrantAuthorizationCode}, "code": {code}, "redirect_uri": {testRedirect}})
	wantStatus(t, r, http.StatusOK)
}

func TestErrorBodyIsAADSTSShapedAndEchoesClientRequestID(t *testing.T) {
	clock := newClock()
	f := newFixture(t, Entra, WithClock(clock.Now))
	corr := NewGUID()
	r := postToken(t, f.idp.TokenURL(f.tenant), url.Values{
		"grant_type": {GrantAuthorizationCode}, "client_id": {f.client.ID}, "client_secret": {"wrong"},
	}, http.Header{"Client-Request-Id": {corr}})

	wantEntraError(t, r, 401, "invalid_client", 7000215)
	wantClaim(t, r.body, "correlation_id", corr)
	wantClaim(t, r.body, "timestamp", "2026-11-06 12:00:00Z")
	if r.header.Get("client-request-id") != corr {
		t.Errorf("client-request-id header = %q", r.header.Get("client-request-id"))
	}
	trace := r.str("trace_id")
	if !isGUID(trace) {
		t.Errorf("trace_id = %q", trace)
	}
	for _, want := range []string{"Trace ID: " + trace, "Correlation ID: " + corr, "Timestamp: 2026-11-06 12:00:00Z"} {
		if !strings.Contains(r.str("error_description"), want) {
			t.Errorf("error_description lacks %q", want)
		}
	}
	if strings.Contains(r.str("error_description"), "wrong") {
		t.Error("error echoes the submitted secret")
	}
}

func TestGenericErrorIsPlainOAuth(t *testing.T) {
	f := newFixture(t, Generic)
	r := f.token(t, url.Values{"grant_type": {GrantAuthorizationCode}, "code": {"nope"}})
	wantStatus(t, r, 400)
	if r.str("error") != "invalid_grant" || r.body["error_codes"] != nil || strings.Contains(r.str("error_description"), "AADSTS") {
		t.Fatalf("body = %v", r.body)
	}
}

func TestClientAuthentication(t *testing.T) {
	cert, rolled := NewCertificate(t), NewCertificate(t)
	stranger := NewCertificate(t)
	for name, tc := range map[string]struct {
		form   func(f *fixture) url.Values
		header func(f *fixture) http.Header
		status int
		err    string
		code   int
		azpacr string
	}{
		"secret post": {
			form: func(f *fixture) url.Values {
				return url.Values{"client_id": {f.client.ID}, "client_secret": {testSecret}}
			},
			status: 200, azpacr: "1",
		},
		"rolled-over secret": {
			form: func(f *fixture) url.Values {
				return url.Values{"client_id": {f.client.ID}, "client_secret": {"previous-secret"}}
			},
			status: 200, azpacr: "1",
		},
		"secret basic": {
			form:   func(*fixture) url.Values { return url.Values{} },
			header: func(f *fixture) http.Header { return basic(f.client.ID, testSecret) },
			status: 200, azpacr: "1",
		},
		"wrong secret": {
			form: func(f *fixture) url.Values {
				return url.Values{"client_id": {f.client.ID}, "client_secret": {"nope"}}
			},
			status: 401, err: "invalid_client", code: 7000215,
		},
		"no credential": {
			form:   func(f *fixture) url.Values { return url.Values{"client_id": {f.client.ID}} },
			status: 401, err: "invalid_client", code: 7000218,
		},
		"two methods": {
			form: func(f *fixture) url.Values {
				return url.Values{"client_id": {f.client.ID}, "client_secret": {testSecret}}
			},
			header: func(f *fixture) http.Header { return basic(f.client.ID, testSecret) },
			status: 400, err: "invalid_request", code: 9002313,
		},
		"unknown client": {
			form: func(*fixture) url.Values {
				return url.Values{"client_id": {NewGUID()}, "client_secret": {testSecret}}
			},
			status: 400, err: "unauthorized_client", code: 700016,
		},
		"PS256 x5t#S256": {
			form: func(f *fixture) url.Values {
				return assertionForm(t, f, cert, "PS256", map[string]any{"x5t#S256": cert.ThumbprintSHA256()}, nil)
			},
			status: 200, azpacr: "2",
		},
		"RS256 x5t (SHA-1)": {
			form: func(f *fixture) url.Values {
				return assertionForm(t, f, cert, "RS256", map[string]any{"x5t": cert.ThumbprintSHA1()}, nil)
			},
			status: 200, azpacr: "2",
		},
		"rolled-over certificate": {
			form: func(f *fixture) url.Values {
				return assertionForm(t, f, rolled, "PS256", map[string]any{"x5t#S256": rolled.ThumbprintSHA256()}, nil)
			},
			status: 200, azpacr: "2",
		},
		"no thumbprint": {
			form:   func(f *fixture) url.Values { return assertionForm(t, f, cert, "PS256", nil, nil) },
			status: 401, err: "invalid_client", code: 5002723,
		},
		"signed by another key": {
			form: func(f *fixture) url.Values {
				return assertionForm(t, f, stranger, "PS256", map[string]any{"x5t#S256": cert.ThumbprintSHA256()}, nil)
			},
			status: 401, err: "invalid_client", code: 700027,
		},
		"unregistered certificate": {
			form: func(f *fixture) url.Values {
				return assertionForm(t, f, stranger, "PS256", map[string]any{"x5t#S256": stranger.ThumbprintSHA256()}, nil)
			},
			status: 401, err: "invalid_client", code: 700027,
		},
		"wrong audience": {
			form: func(f *fixture) url.Values {
				return assertionForm(t, f, cert, "PS256", map[string]any{"x5t#S256": cert.ThumbprintSHA256()}, map[string]any{"aud": "https://elsewhere.example/token"})
			},
			status: 401, err: "invalid_client", code: 700027,
		},
		"authority audience": {
			form: func(f *fixture) url.Values {
				return assertionForm(t, f, cert, "PS256", map[string]any{"x5t#S256": cert.ThumbprintSHA256()},
					map[string]any{"aud": "https://login.microsoftonline.com/" + f.tenant + "/oauth2/v2.0/token"})
			},
			status: 200, azpacr: "2",
		},
		"expired assertion": {
			form: func(f *fixture) url.Values {
				return assertionForm(t, f, cert, "PS256", map[string]any{"x5t#S256": cert.ThumbprintSHA256()}, map[string]any{"exp": time.Now().Add(-time.Minute).Unix()})
			},
			status: 401, err: "invalid_client", code: 700027,
		},
		"assertion for another client": {
			form: func(f *fixture) url.Values {
				return assertionForm(t, f, cert, "PS256", map[string]any{"x5t#S256": cert.ThumbprintSHA256()}, map[string]any{"sub": NewGUID()})
			},
			status: 401, err: "invalid_client", code: 700027,
		},
	} {
		t.Run(name, func(t *testing.T) {
			c := Client{ID: NewGUID(), Secrets: []string{testSecret, "previous-secret"}, Certificates: []*Certificate{cert, rolled}}
			api := Client{ID: NewGUID()}
			idp := New(t, Entra, WithClient(c), WithClient(api))
			f := &fixture{idp: idp, client: c, tenant: idp.TenantID()}
			form := tc.form(f)
			form.Set("grant_type", GrantClientCredentials)
			form.Set("scope", "api://"+api.ID+"/.default")
			var h http.Header
			if tc.header != nil {
				h = tc.header(f)
			}
			r := postToken(t, idp.TokenURL(f.tenant), form, h)
			if tc.status != 200 {
				wantEntraError(t, r, tc.status, tc.err, tc.code)
				return
			}
			wantStatus(t, r, 200)
			_, at := f.verified(t, r.str("access_token"))
			wantClaim(t, at, "azpacr", tc.azpacr)
		})
	}
}

func basic(id, secret string) http.Header {
	req, _ := http.NewRequest(http.MethodPost, "/", nil)
	req.SetBasicAuth(url.QueryEscape(id), url.QueryEscape(secret))
	return req.Header
}

func assertionForm(t *testing.T, f *fixture, cert *Certificate, alg string, header, override map[string]any) url.Values {
	t.Helper()
	now := time.Now()
	claims := map[string]any{
		"iss": f.client.ID, "sub": f.client.ID, "aud": f.idp.TokenURL(f.tenant),
		"jti": NewGUID(), "nbf": now.Unix(), "exp": now.Add(5 * time.Minute).Unix(),
	}
	for k, v := range override {
		claims[k] = v
	}
	s, err := cert.SignJWT(alg, header, claims)
	if err != nil {
		t.Fatal(err)
	}
	return url.Values{"client_id": {f.client.ID}, "client_assertion_type": {clientAssertionType}, "client_assertion": {s}}
}

func refreshForm(rt string) url.Values {
	return url.Values{"grant_type": {GrantRefreshToken}, "refresh_token": {rt}}
}

func TestRefresh(t *testing.T) {
	clock := newClock()
	f := newFixture(t, Entra, WithClock(clock.Now))
	first := f.login(t)
	_, firstID := f.verified(t, first.str("id_token"))

	clock.Advance(time.Minute)
	r := f.token(t, refreshForm(first.str("refresh_token")))
	wantStatus(t, r, http.StatusOK)
	if r.str("refresh_token") == "" || r.str("refresh_token") == first.str("refresh_token") {
		t.Fatal("Entra returns a new refresh token on refresh")
	}
	_, id := f.verified(t, r.str("id_token"))
	wantClaim(t, id, "sub", firstID["sub"])
	wantClaim(t, id, "iat", clock.Now().Unix())
	if _, ok := id["nonce"]; ok {
		t.Error("refreshed ID token carries the login nonce")
	}
	_, at := f.verified(t, r.str("access_token"))
	wantClaim(t, at, "aud", f.client.ID)
}

func TestRefreshFailures(t *testing.T) {
	other := Client{ID: NewGUID(), Secrets: []string{testSecret}}
	for name, tc := range map[string]struct {
		setup func(f *fixture, clock *fakeClock)
		form  func(rt string) url.Values
		code  int
	}{
		"expired":  {setup: func(_ *fixture, c *fakeClock) { c.Advance(91 * 24 * time.Hour) }, code: 700082},
		"revoked":  {setup: func(f *fixture, _ *fakeClock) { f.idp.RevokeRefreshTokens() }, code: 50173},
		"unknown":  {form: func(string) url.Values { return refreshForm("nope") }, code: 70000},
		"injected": {setup: func(f *fixture, _ *fakeClock) { f.idp.Set(FailToken(GrantRefreshToken, &MFARequired)) }, code: 50076},
		"other client": {form: func(rt string) url.Values {
			form := refreshForm(rt)
			form.Set("client_id", other.ID)
			return form
		}, code: 70000},
	} {
		t.Run(name, func(t *testing.T) {
			clock := newClock()
			f := newFixture(t, Entra, WithClock(clock.Now), WithClient(other))
			rt := f.login(t).str("refresh_token")
			if tc.setup != nil {
				tc.setup(f, clock)
			}
			form := refreshForm(rt)
			if tc.form != nil {
				form = tc.form(rt)
			}
			wantEntraError(t, f.token(t, form), 400, "invalid_grant", tc.code)
		})
	}
}

func TestRefreshWithoutRotation(t *testing.T) {
	f := newFixture(t, Entra, WithRefreshTokenRotation(false))
	rt := f.login(t).str("refresh_token")
	for range 2 {
		r := f.token(t, refreshForm(rt))
		wantStatus(t, r, http.StatusOK)
		if r.str("refresh_token") != "" {
			t.Fatal("refresh token returned with rotation off")
		}
	}
}

func TestFailTokenCanBeCleared(t *testing.T) {
	f := newFixture(t, Entra, FailToken(GrantAuthorizationCode, &TemporarilyUnavailable))
	r := f.redeem(t, f.code(t, nil))
	wantStatus(t, r, http.StatusServiceUnavailable)
	wantClaim(t, r.body, "error", "temporarily_unavailable")

	f.idp.Set(FailToken(GrantAuthorizationCode, nil))
	f.login(t)
}

func TestUnsupportedGrantType(t *testing.T) {
	for _, grant := range []string{"password", GrantClientCredentials, GrantJWTBearer} {
		f := newFixture(t, Generic)
		r := f.token(t, url.Values{"grant_type": {grant}})
		wantStatus(t, r, 400)
		wantClaim(t, r.body, "error", "unsupported_grant_type")
	}
	f := newFixture(t, Entra)
	wantEntraError(t, f.token(t, url.Values{"grant_type": {"password"}}), 400, "unsupported_grant_type", 70003)
}

func TestConcurrentLogins(t *testing.T) {
	f := newFixture(t, Entra)
	for i := range 8 {
		t.Run(strconv.Itoa(i), func(t *testing.T) {
			t.Parallel()
			f.login(t)
		})
	}
}

func TestFailTokenDoesNotMakeUnsupportedGrantsSupported(t *testing.T) {
	f := newFixture(t, Generic, FailToken(GrantClientCredentials, &InteractionRequired))
	r := f.token(t, url.Values{"grant_type": {GrantClientCredentials}})
	wantStatus(t, r, 400)
	wantClaim(t, r.body, "error", "unsupported_grant_type")
}

func TestSetTenantMovesDefaultUserButNotExplicitOne(t *testing.T) {
	f := newFixture(t, Entra)
	tid := NewGUID()
	f.idp.Set(WithTenantID(tid))
	f.tenant = tid
	_, id := f.verified(t, f.login(t).str("id_token"))
	wantClaim(t, id, "tid", tid)

	pinned := NewGUID()
	f.idp.Set(WithUser(User{TenantID: pinned}), WithTenantID(NewGUID()))
	if got := f.idp.User().TenantID; got != pinned {
		t.Fatalf("explicit user tenant changed to %s", got)
	}
}
