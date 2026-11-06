package fakeidp

import (
	"net/http"
	"net/url"
	"testing"
	"time"
)

// m2m is a resource API (the proxy's IdP app) and a headless caller.
func m2m(t *testing.T, api Client, caller Client, opts ...Option) (*fixture, *fixture) {
	t.Helper()
	idp := New(t, Entra, append([]Option{WithClient(api), WithClient(caller)}, opts...)...)
	api, _ = idp.Client(api.ID)
	caller, _ = idp.Client(caller.ID)
	return &fixture{idp: idp, client: api, tenant: idp.TenantID()}, &fixture{idp: idp, client: caller, tenant: idp.TenantID()}
}

func ccForm(api string) url.Values {
	return url.Values{"grant_type": {GrantClientCredentials}, "scope": {"api://" + api + "/.default"}}
}

func TestClientCredentialsAppOnlyToken(t *testing.T) {
	api := Client{ID: NewGUID()}
	caller := Client{ID: NewGUID(), Secrets: []string{testSecret}}
	caller.AppRoles = map[string][]string{api.ID: {"MCP.Invoke"}}
	_, c := m2m(t, api, caller)

	r := c.token(t, ccForm(api.ID))
	wantStatus(t, r, http.StatusOK)
	if r.str("refresh_token") != "" {
		t.Error("client credentials must not return a refresh token")
	}
	header, at := c.verified(t, r.str("access_token"))
	wantClaim(t, header, "typ", "JWT")
	wantClaim(t, at, "aud", api.ID)
	wantClaim(t, at, "iss", "https://login.microsoftonline.com/"+c.tenant+"/v2.0")
	wantClaim(t, at, "idtyp", "app")
	wantClaim(t, at, "roles", []string{"MCP.Invoke"})
	wantClaim(t, at, "azp", caller.ID)
	wantClaim(t, at, "sub", c.client.ServicePrincipalID)
	wantClaim(t, at, "oid", c.client.ServicePrincipalID)
	wantClaim(t, at, "ver", "2.0")
	if _, ok := at["scp"]; ok {
		t.Error("app-only token carries scp")
	}
}

func TestClientCredentialsWithoutRoleStillIssuesToken(t *testing.T) {
	api := Client{ID: NewGUID()}
	_, c := m2m(t, api, Client{ID: NewGUID(), Secrets: []string{testSecret}})
	r := c.token(t, ccForm(api.ID))
	wantStatus(t, r, http.StatusOK)
	_, at := c.verified(t, r.str("access_token"))
	if _, ok := at["roles"]; ok {
		t.Error("roles present without an assignment")
	}
}

func TestClientCredentialsAssignmentRequired(t *testing.T) {
	api := Client{ID: NewGUID(), AssignmentRequired: true}
	_, c := m2m(t, api, Client{ID: NewGUID(), Secrets: []string{testSecret}})
	wantEntraError(t, c.token(t, ccForm(api.ID)), 400, "invalid_grant", 501051)
}

func TestClientCredentialsWithoutIDTypOptionalClaim(t *testing.T) {
	api := Client{ID: NewGUID()}
	_, c := m2m(t, api, Client{ID: NewGUID(), Secrets: []string{testSecret}}, WithIDTypClaim(false))
	_, at := c.verified(t, c.token(t, ccForm(api.ID)).str("access_token"))
	if _, ok := at["idtyp"]; ok {
		t.Error("idtyp present with the optional claim off")
	}
}

func TestClientCredentialsGraphToken(t *testing.T) {
	_, c := m2m(t, Client{ID: NewGUID()}, Client{ID: NewGUID(), Secrets: []string{testSecret}})
	r := c.token(t, url.Values{"grant_type": {GrantClientCredentials}, "scope": {"https://graph.microsoft.com/.default"}})
	wantStatus(t, r, http.StatusOK)
	_, at := c.verified(t, r.str("access_token"))
	wantClaim(t, at, "aud", GraphAppID)
	wantClaim(t, at, "ver", "1.0")
}

func TestClientCredentialsScopeRules(t *testing.T) {
	api := Client{ID: NewGUID()}
	_, c := m2m(t, api, Client{ID: NewGUID(), Secrets: []string{testSecret}})
	for _, scope := range []string{"", "api://" + api.ID + "/access_as_user", "openid api://" + api.ID + "/.default"} {
		r := c.token(t, url.Values{"grant_type": {GrantClientCredentials}, "scope": {scope}})
		wantEntraError(t, r, 400, "invalid_scope", 70011)
	}
}

func TestPublicClientCannotUseClientCredentials(t *testing.T) {
	api := Client{ID: NewGUID()}
	_, c := m2m(t, api, Client{ID: NewGUID()})
	form := ccForm(api.ID)
	form.Set("client_id", c.client.ID)
	wantEntraError(t, postToken(t, c.idp.TokenURL(c.tenant), form, nil), 401, "invalid_client", 7000218)
}

func oboForm(assertion, scope string) url.Values {
	return url.Values{
		"grant_type":          {GrantJWTBearer},
		"requested_token_use": {"on_behalf_of"},
		"assertion":           {assertion},
		"scope":               {scope},
	}
}

func TestOnBehalfOfToGraph(t *testing.T) {
	f := newFixture(t, Entra)
	u := f.idp.User()
	assertion := f.login(t).str("access_token")

	r := f.token(t, oboForm(assertion, "https://graph.microsoft.com/User.Read offline_access"))
	wantStatus(t, r, http.StatusOK)
	wantClaim(t, r.body, "scope", "https://graph.microsoft.com/User.Read")
	if r.str("refresh_token") == "" {
		t.Error("no refresh token with offline_access")
	}
	_, at := f.verified(t, r.str("access_token"))
	wantClaim(t, at, "aud", GraphAppID)
	wantClaim(t, at, "scp", "User.Read")
	wantClaim(t, at, "oid", u.OID)
	wantClaim(t, at, "tid", f.tenant)
	wantClaim(t, at, "appid", f.client.ID)
	wantClaim(t, at, "idtyp", "user")
}

func TestOnBehalfOfToRegisteredAPI(t *testing.T) {
	downstream := Client{ID: NewGUID()}
	f := newFixture(t, Entra, WithClient(downstream))
	r := f.token(t, oboForm(f.login(t).str("access_token"), "api://"+downstream.ID+"/Files.Read"))
	wantStatus(t, r, http.StatusOK)
	_, at := f.verified(t, r.str("access_token"))
	wantClaim(t, at, "aud", downstream.ID)
	wantClaim(t, at, "scp", "Files.Read")
	wantClaim(t, at, "azp", f.client.ID)
}

func TestOnBehalfOfRejectsBadAssertions(t *testing.T) {
	clock := newClock()
	f := newFixture(t, Entra, WithClock(clock.Now))
	login := f.login(t)

	graph := f.redeem(t, f.code(t, url.Values{"scope": {"openid https://graph.microsoft.com/User.Read"}}))
	wantStatus(t, graph, http.StatusOK)

	api := Client{ID: NewGUID(), Secrets: []string{testSecret}}
	f.idp.Set(WithClient(api))
	appOnly := (&fixture{idp: f.idp, client: api, tenant: f.tenant}).token(t, ccForm(f.client.ID)).str("access_token")

	forged := f.idp.Mint(map[string]any{"aud": f.client.ID, "iss": "https://evil.example/", "tid": f.tenant, "scp": "x",
		"exp": clock.Now().Add(time.Hour).Unix()})
	tampered := login.str("access_token")[:len(login.str("access_token"))-4] + "AAAA"

	for name, assertion := range map[string]string{
		"Graph token (wrong aud)": graph.str("access_token"),
		"app-only token":          appOnly,
		"foreign issuer":          forged,
		"bad signature":           tampered,
		"not a JWT":               "opaque",
	} {
		t.Run(name, func(t *testing.T) {
			wantEntraError(t, f.token(t, oboForm(assertion, "https://graph.microsoft.com/User.Read")), 400, "invalid_grant", 50013)
		})
	}

	t.Run("expired", func(t *testing.T) {
		clock.Advance(2 * time.Hour)
		wantEntraError(t, f.token(t, oboForm(login.str("access_token"), "User.Read")), 400, "invalid_grant", 50013)
	})
}

func TestOnBehalfOfNeedsRequestedTokenUse(t *testing.T) {
	f := newFixture(t, Entra)
	form := oboForm(f.login(t).str("access_token"), "User.Read")
	form.Del("requested_token_use")
	wantEntraError(t, f.token(t, form), 400, "invalid_request", 9002313)
}

func TestOnBehalfOfInjectedFailures(t *testing.T) {
	for name, tc := range map[string]struct {
		f         *Failure
		err       string
		code      int
		wantClaim bool
	}{
		"consent required":     {f: &ConsentRequired, err: "invalid_grant", code: 65001},
		"interaction required": {f: &InteractionRequired, err: "interaction_required", code: 50079, wantClaim: true},
	} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t, Entra)
			assertion := f.login(t).str("access_token")
			f.idp.Set(FailToken(GrantJWTBearer, tc.f))
			r := f.token(t, oboForm(assertion, "User.Read"))
			wantEntraError(t, r, 400, tc.err, tc.code)
			if _, ok := r.body["claims"]; ok != tc.wantClaim {
				t.Errorf("claims present = %v, want %v", ok, tc.wantClaim)
			}
		})
	}
}
