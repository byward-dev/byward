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
			u := f.idp.User()
			for _, tok := range []string{"id_token", "access_token"} {
				_, c := f.verified(t, f.login(t).str(tok))
				if _, ok := c["groups"]; ok {
					t.Errorf("%s has groups despite overage", tok)
				}
				wantClaim(t, c, "_claim_names", map[string]string{"groups": "src1"})
				wantClaim(t, c, "_claim_sources", map[string]any{"src1": map[string]string{
					"endpoint": "https://graph.windows.net/" + u.TenantID + "/users/" + u.OID + "/getMemberObjects"}})
			}
		})
	}
	t.Run("at limit", func(t *testing.T) {
		f := newFixture(t, Entra, WithUser(User{Groups: many[:groupsOverageLimit]}))
		_, c := f.verified(t, f.login(t).str("id_token"))
		if groups, _ := c["groups"].([]any); len(groups) != groupsOverageLimit {
			t.Errorf("groups has %d entries, want %d", len(groups), groupsOverageLimit)
		}
		if _, ok := c["_claim_names"]; ok {
			t.Error("overage claims at the limit")
		}
	})
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

func TestErrorBodyIsAADSTSShaped(t *testing.T) {
	clock := newClock()
	f := newFixture(t, Entra, WithClock(clock.Now))
	r := postToken(t, f.idp.TokenURL(f.tenant), url.Values{
		"grant_type": {GrantAuthorizationCode}, "client_id": {f.client.ID}, "client_secret": {"wrong"},
	}, nil)

	wantEntraError(t, r, 401, "invalid_client", 7000215)
	wantClaim(t, r.body, "timestamp", "2026-11-06 12:00:00Z")
	trace, corr := r.str("trace_id"), r.str("correlation_id")
	if !isGUID(trace) || !isGUID(corr) {
		t.Errorf("trace_id = %q, correlation_id = %q", trace, corr)
	}
	if r.header.Get("x-ms-request-id") != trace {
		t.Errorf("x-ms-request-id = %q, want trace_id %q", r.header.Get("x-ms-request-id"), trace)
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

func TestClientRequestIDIsEchoedOnlyWhenGUID(t *testing.T) {
	guid := NewGUID()
	for name, tc := range map[string]struct {
		sent string
		echo bool
	}{
		"GUID":           {guid, true},
		"uppercase GUID": {strings.ToUpper(NewGUID()), true},
		"not a GUID":     {"not-a-guid", false},
	} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t, Entra)
			h := http.Header{"Client-Request-Id": {tc.sent}}
			bad := postToken(t, f.idp.TokenURL(f.tenant), url.Values{"grant_type": {GrantAuthorizationCode}, "client_id": {f.client.ID}, "client_secret": {"wrong"}}, h)
			if got := bad.str("correlation_id") == tc.sent; got != tc.echo {
				t.Errorf("correlation_id = %q, echo = %v, want %v", bad.str("correlation_id"), got, tc.echo)
			}
			ok := postToken(t, f.idp.TokenURL(f.tenant), url.Values{"grant_type": {GrantAuthorizationCode}, "client_id": {f.client.ID},
				"client_secret": {testSecret}, "code": {f.code(t, nil)}, "redirect_uri": {testRedirect}, "code_verifier": {testVerifier}}, h)
			wantStatus(t, ok, http.StatusOK)
			for _, r := range []tokenResult{bad, ok} {
				if got := r.header.Get("client-request-id") == tc.sent; got != tc.echo {
					t.Errorf("status %d: client-request-id header = %q, want echo %v", r.status, r.header.Get("client-request-id"), tc.echo)
				}
			}
		})
	}
}

func TestLifetimeOptions(t *testing.T) {
	t.Run("token", func(t *testing.T) {
		clock := newClock()
		f := newFixture(t, Entra, WithClock(clock.Now), WithTokenLifetime(5*time.Minute))
		r := f.login(t)
		wantClaim(t, r.body, "expires_in", 300)
		wantClaim(t, r.body, "ext_expires_in", 300)
		for _, tok := range []string{"id_token", "access_token"} {
			_, c := f.verified(t, r.str(tok))
			wantClaim(t, c, "exp", clock.Now().Add(5*time.Minute).Unix())
		}
	})
	t.Run("code", func(t *testing.T) {
		clock := newClock()
		f := newFixture(t, Entra, WithClock(clock.Now), WithCodeLifetime(30*time.Second))
		code := f.code(t, nil)
		clock.Advance(31 * time.Second)
		wantEntraError(t, f.redeem(t, code), 400, "invalid_grant", 70008)
	})
	t.Run("refresh", func(t *testing.T) {
		clock := newClock()
		f := newFixture(t, Entra, WithClock(clock.Now), WithRefreshTokenLifetime(time.Hour))
		rt := f.login(t).str("refresh_token")
		clock.Advance(59 * time.Minute)
		wantStatus(t, f.token(t, refreshForm(rt)), http.StatusOK)
		clock.Advance(2 * time.Minute)
		wantEntraError(t, f.token(t, refreshForm(rt)), 400, "invalid_grant", 700082)
	})
}

func TestGenericErrorIsPlainOAuth(t *testing.T) {
	f := newFixture(t, Generic)
	r := f.token(t, url.Values{"grant_type": {GrantAuthorizationCode}, "code": {"nope"}})
	wantStatus(t, r, 400)
	if r.str("error") != "invalid_grant" || r.body["error_codes"] != nil || strings.Contains(r.str("error_description"), "AADSTS") {
		t.Fatalf("body = %v", r.body)
	}
}

func refreshForm(rt string) url.Values {
	return url.Values{"grant_type": {GrantRefreshToken}, "refresh_token": {rt}}
}

func TestEntraRefreshRotatesTokenKeepsSubAndDropsNonce(t *testing.T) {
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
		setup func(f *fixture, clock *Clock)
		form  func(rt string) url.Values
		code  int
	}{
		"expired":  {setup: func(_ *fixture, c *Clock) { c.Advance(91 * 24 * time.Hour) }, code: 700082},
		"revoked":  {setup: func(f *fixture, _ *Clock) { f.idp.RevokeRefreshTokens() }, code: 50173},
		"unknown":  {form: func(string) url.Values { return refreshForm("nope") }, code: 70000},
		"injected": {setup: func(f *fixture, _ *Clock) { f.idp.Set(FailToken(GrantRefreshToken, &MFARequired)) }, code: 50076},
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

func TestUnsupportedGrantsAreRefused(t *testing.T) {
	for _, tc := range []struct {
		profile Profile
		grant   string
	}{{Generic, "password"}, {Generic, GrantClientCredentials}, {Generic, GrantJWTBearer}, {Entra, "password"}} {
		t.Run(string(tc.profile)+" "+tc.grant, func(t *testing.T) {
			f := newFixture(t, tc.profile)
			r := f.token(t, url.Values{"grant_type": {tc.grant}})
			if tc.profile == Entra {
				wantEntraError(t, r, 400, "unsupported_grant_type", 70003)
				return
			}
			wantStatus(t, r, 400)
			wantClaim(t, r.body, "error", "unsupported_grant_type")
		})
	}
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
	f.tenant = "organizations"
	_, id = f.verified(t, f.login(t).str("id_token"))
	wantClaim(t, id, "tid", pinned)
}
