package fakeidp

import (
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

func discover(t *testing.T, endpoint string) map[string]any {
	t.Helper()
	resp, err := http.Get(endpoint) //nolint:gosec // G107: test URL from the fake itself
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("discovery status = %d", resp.StatusCode)
	}
	var doc map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		t.Fatal(err)
	}
	return doc
}

func TestEntraDiscoveryIsTenantScopedV2WithEntraOmissions(t *testing.T) {
	f := newFixture(t, Entra)
	doc := discover(t, f.idp.DiscoveryURL(f.tenant))

	wantClaim(t, doc, "issuer", "https://login.microsoftonline.com/"+f.tenant+"/v2.0")
	wantClaim(t, doc, "authorization_endpoint", f.idp.URL()+"/"+f.tenant+"/oauth2/v2.0/authorize")
	wantClaim(t, doc, "token_endpoint", f.idp.URL()+"/"+f.tenant+"/oauth2/v2.0/token")
	wantClaim(t, doc, "jwks_uri", f.idp.URL()+"/"+f.tenant+"/discovery/v2.0/keys")
	wantClaim(t, doc, "subject_types_supported", []string{"pairwise"})
	for _, absent := range []string{"code_challenge_methods_supported", "authorization_response_iss_parameter_supported",
		"pushed_authorization_request_endpoint", "dpop_signing_alg_values_supported", "backchannel_logout_supported"} {
		if _, ok := doc[absent]; ok {
			t.Errorf("Entra discovery must not advertise %s", absent)
		}
	}
}

func TestEntraMultiTenantDiscoveryHasIssuerTemplate(t *testing.T) {
	f := newFixture(t, Entra)
	for _, seg := range []string{"organizations", "common"} {
		doc := discover(t, f.idp.DiscoveryURL(seg))
		wantClaim(t, doc, "issuer", "https://login.microsoftonline.com/{tenantid}/v2.0")
	}
}

func TestEntraUnknownTenantSegmentIsRejected(t *testing.T) {
	f := newFixture(t, Entra)
	resp, err := http.Get(f.idp.DiscoveryURL("consumers"))
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", resp.StatusCode)
	}
}

func TestWithAuthorityChangesIssuerHostOnly(t *testing.T) {
	f := newFixture(t, Entra, WithAuthority("https://login.example/"))
	doc := discover(t, f.idp.DiscoveryURL(f.tenant))
	wantClaim(t, doc, "issuer", "https://login.example/"+f.tenant+"/v2.0")
	wantClaim(t, doc, "token_endpoint", f.idp.TokenURL(f.tenant))
}

func TestGenericDiscoveryAdvertisesPKCEAndIss(t *testing.T) {
	f := newFixture(t, Generic)
	doc := discover(t, f.idp.DiscoveryURL(""))
	wantClaim(t, doc, "issuer", f.idp.URL())
	wantClaim(t, doc, "code_challenge_methods_supported", []string{"S256"})
	wantClaim(t, doc, "authorization_response_iss_parameter_supported", true)
}

func TestJWKSRotationKeepsOldKeysUntilRetired(t *testing.T) {
	f := newFixture(t, Entra)
	before := f.login(t)
	oldHeader, _ := f.verified(t, before.str("id_token"))

	f.idp.RotateKeys(t)
	after := f.login(t)
	newHeader, _ := f.verified(t, after.str("id_token"))
	if newHeader["kid"] == oldHeader["kid"] {
		t.Fatal("rotation did not change the signing kid")
	}
	if n := len(f.jwks(t)); n != 2 {
		t.Fatalf("JWKS has %d keys after rotation, want 2", n)
	}
	f.verified(t, before.str("id_token")) // old key still published

	f.idp.RetireOldKeys()
	keys := f.jwks(t)
	if len(keys) != 1 || keys[0]["kid"] != newHeader["kid"] {
		t.Fatalf("JWKS after retire = %v, want only %v", keys, newHeader["kid"])
	}
}

func TestEntraJWKSKeysCarryEntraFields(t *testing.T) {
	f := newFixture(t, Entra)
	k := f.jwks(t)[0]
	for _, field := range []string{"kty", "use", "kid", "x5t", "n", "e", "x5c", "issuer"} {
		if _, ok := k[field]; !ok {
			t.Errorf("JWKS key lacks %s", field)
		}
	}
	if k["kid"] != k["x5t"] {
		t.Errorf("kid %v != x5t %v", k["kid"], k["x5t"])
	}
}

func TestAuthorizeRedirectsWithCodeAndState(t *testing.T) {
	for _, tc := range []struct {
		profile Profile
		wantIss bool
	}{{Entra, false}, {Generic, true}} {
		t.Run(string(tc.profile), func(t *testing.T) {
			f := newFixture(t, tc.profile)
			q := redirectQuery(t, f.authorize(t, nil))
			if q.Get("code") == "" || q.Get("state") != "state-1" {
				t.Fatalf("redirect query = %v", q)
			}
			if got := q.Has("iss"); got != tc.wantIss {
				t.Fatalf("iss present = %v, want %v", got, tc.wantIss)
			}
			if tc.wantIss && q.Get("iss") != f.idp.Issuer() {
				t.Fatalf("iss = %q, want %q", q.Get("iss"), f.idp.Issuer())
			}
		})
	}
}

func TestWithIssParameterOnEntra(t *testing.T) {
	f := newFixture(t, Entra, WithIssParameter(true))
	q := redirectQuery(t, f.authorize(t, nil))
	if q.Get("iss") != f.idp.Issuer() {
		t.Fatalf("iss = %q", q.Get("iss"))
	}
}

func TestAuthorizeShowsErrorPageWhenRedirectIsUntrusted(t *testing.T) {
	for name, params := range map[string]url.Values{
		"unknown client":      {"client_id": {NewGUID()}},
		"unregistered port":   {"redirect_uri": {"http://127.0.0.1:9999/callback/entra"}},
		"redirect with query": {"redirect_uri": {testRedirect + "?x=1"}},
	} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t, Entra)
			resp := f.authorize(t, params)
			if resp.StatusCode != http.StatusBadRequest || resp.Header.Get("Location") != "" {
				t.Fatalf("status = %d, Location = %q; want 400 without redirect", resp.StatusCode, resp.Header.Get("Location"))
			}
		})
	}
}

func TestAuthorizeErrorsRedirectBackWithState(t *testing.T) {
	for name, tc := range map[string]struct {
		params url.Values
		opts   []Option
		want   string
	}{
		"response_type token": {params: url.Values{"response_type": {"token"}}, want: "unsupported_response_type"},
		"form_post":           {params: url.Values{"response_mode": {"form_post"}}, want: "invalid_request"},
		"plain PKCE":          {params: url.Values{"code_challenge_method": {"plain"}}, want: "invalid_request"},
		"PKCE required":       {params: url.Values{"code_challenge": nil, "code_challenge_method": nil}, opts: []Option{WithRequirePKCE(true)}, want: "invalid_request"},
		"unknown resource":    {params: url.Values{"scope": {"openid api://" + NewGUID() + "/access_as_user"}}, want: "invalid_scope"},
	} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t, Entra, tc.opts...)
			q := redirectQuery(t, f.authorize(t, tc.params))
			if q.Get("error") != tc.want || q.Get("state") != "state-1" || q.Has("code") {
				t.Fatalf("redirect query = %v, want error %s with state", q, tc.want)
			}
		})
	}
}

func TestAuthorizeRefusesScopesForTwoResources(t *testing.T) {
	f := newFixture(t, Entra)
	q := redirectQuery(t, f.authorize(t, url.Values{"scope": {"openid " + f.ownScope() + " https://graph.microsoft.com/User.Read"}}))
	if q.Get("error") != "invalid_scope" || !strings.HasPrefix(q.Get("error_description"), "AADSTS70011:") {
		t.Fatalf("redirect query = %v", q)
	}
}

func TestFailAuthorizeInjectsAADSTSError(t *testing.T) {
	f := newFixture(t, Entra, FailAuthorize(&UserNotAssigned))
	q := redirectQuery(t, f.authorize(t, nil))
	if q.Get("error") != "access_denied" || !strings.HasPrefix(q.Get("error_description"), "AADSTS50105:") {
		t.Fatalf("redirect query = %v", q)
	}

	f.idp.Set(FailAuthorize(nil))
	if q := redirectQuery(t, f.authorize(t, nil)); q.Get("code") == "" {
		t.Fatalf("after clearing, redirect query = %v", q)
	}
}

func TestEntraUserFromAnotherTenant(t *testing.T) {
	other := NewGUID()
	f := newFixture(t, Entra, WithUser(User{TenantID: other}))

	q := redirectQuery(t, f.authorize(t, nil))
	if !strings.HasPrefix(q.Get("error_description"), "AADSTS50020:") {
		t.Fatalf("single-tenant sign-in of a foreign user: %v", q)
	}

	f.tenant = "organizations"
	r := f.login(t)
	_, claims := f.verified(t, r.str("id_token"))
	wantClaim(t, claims, "tid", other)
	wantClaim(t, claims, "iss", "https://login.microsoftonline.com/"+other+"/v2.0")
}

func TestErrorPageHasNoSecretsAndCorrelates(t *testing.T) {
	f := newFixture(t, Entra)
	req, _ := http.NewRequest(http.MethodGet, f.idp.AuthorizeURL(f.tenant)+"?client_id="+NewGUID(), nil)
	corr := NewGUID()
	req.Header.Set("client-request-id", corr)
	resp, err := noRedirects().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "AADSTS700016:") || !strings.Contains(string(body), "Correlation ID: "+corr) {
		t.Fatalf("error page = %q", body)
	}
}
