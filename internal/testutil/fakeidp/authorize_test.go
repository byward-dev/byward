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
		t.Run(seg, func(t *testing.T) {
			doc := discover(t, f.idp.DiscoveryURL(seg))
			wantClaim(t, doc, "issuer", "https://login.microsoftonline.com/{tenantid}/v2.0")
		})
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

func TestJWKSKeyFieldsAndIssuerPerTenantPath(t *testing.T) {
	f := newFixture(t, Entra)
	for seg, issuer := range map[string]string{
		f.tenant:        "https://login.microsoftonline.com/" + f.tenant + "/v2.0",
		"organizations": "https://login.microsoftonline.com/{tenantid}/v2.0",
		"common":        "https://login.microsoftonline.com/{tenantid}/v2.0",
	} {
		t.Run(seg, func(t *testing.T) {
			g := &fixture{idp: f.idp, client: f.client, tenant: seg}
			k := g.jwks(t)[0]
			for _, field := range []string{"kty", "use", "kid", "x5t", "n", "e", "x5c"} {
				if _, ok := k[field]; !ok {
					t.Errorf("JWKS key lacks %s", field)
				}
			}
			if k["kid"] != k["x5t"] {
				t.Errorf("kid %v != x5t %v", k["kid"], k["x5t"])
			}
			wantClaim(t, k, "issuer", issuer)
		})
	}
	t.Run("generic", func(t *testing.T) {
		k := newFixture(t, Generic).jwks(t)[0]
		wantClaim(t, k, "alg", "RS256")
		if _, ok := k["issuer"]; ok {
			t.Error("generic JWKS key carries issuer")
		}
	})
}

func TestAuthorizeRedirectsWithCodeAndState(t *testing.T) {
	for name, tc := range map[string]struct {
		profile Profile
		opts    []Option
		wantIss bool
	}{
		"entra":                 {profile: Entra},
		"generic":               {profile: Generic, wantIss: true},
		"entra with iss option": {profile: Entra, opts: []Option{WithIssParameter(true)}, wantIss: true},
	} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t, tc.profile, tc.opts...)
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
		"no scope":            {params: url.Values{"scope": nil}, want: "invalid_request"},
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

func TestForeignTenantUserIsRefusedSingleTenantButSignsInViaOrganizations(t *testing.T) {
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

func TestErrorPageCorrelatesWithoutEchoingSecrets(t *testing.T) {
	f := newFixture(t, Entra)
	req, err := http.NewRequest(http.MethodGet, f.idp.AuthorizeURL(f.tenant)+"?client_id="+NewGUID()+"&client_secret="+testSecret+"-leak", nil)
	if err != nil {
		t.Fatal(err)
	}
	corr := NewGUID()
	req.Header.Set("client-request-id", corr)
	resp, err := noRedirects().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", resp.StatusCode)
	}
	if !strings.Contains(string(body), "AADSTS700016:") || !strings.Contains(string(body), "Correlation ID: "+corr) {
		t.Fatalf("error page = %q", body)
	}
	if strings.Contains(string(body), testSecret) {
		t.Fatal("error page echoes a submitted secret")
	}
}

func TestGenericErrorsCarryNoEntraHeaders(t *testing.T) {
	f := newFixture(t, Generic, FailAuthorize(&InvalidRequest))
	for name, tc := range map[string]struct {
		query  string
		status int
	}{
		"redirect error": {"?client_id=" + f.client.ID + "&redirect_uri=" + url.QueryEscape(testRedirect) + "&response_type=code&scope=openid&state=s", http.StatusFound},
		"error page":     {"?client_id=unknown", http.StatusBadRequest},
	} {
		t.Run(name, func(t *testing.T) {
			req, err := http.NewRequest(http.MethodGet, f.idp.AuthorizeURL("")+tc.query, nil)
			if err != nil {
				t.Fatal(err)
			}
			req.Header.Set("client-request-id", NewGUID())
			resp, err := noRedirects().Do(req)
			if err != nil {
				t.Fatal(err)
			}
			_ = resp.Body.Close()
			if resp.StatusCode != tc.status {
				t.Fatalf("status = %d, want %d", resp.StatusCode, tc.status)
			}
			if resp.Header.Get("x-ms-request-id") != "" || resp.Header.Get("client-request-id") != "" {
				t.Fatalf("generic response has Entra headers: %v", resp.Header)
			}
		})
	}
	q := redirectQuery(t, f.authorize(t, nil))
	if strings.Contains(q.Get("error_description"), "AADSTS") || strings.Contains(q.Get("error_description"), "Trace ID") {
		t.Fatalf("generic error_description = %q", q.Get("error_description"))
	}
}

func TestWithJWKSUnavailableServes503UntilCleared(t *testing.T) {
	f := newFixture(t, Entra, WithJWKSUnavailable(true))
	resp, err := http.Get(f.idp.JWKSURL(f.tenant))
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("status %d", resp.StatusCode)
	}
	f.idp.Set(WithJWKSUnavailable(false))
	if len(f.jwks(t)) == 0 {
		t.Fatal("JWKS empty after recovery")
	}
}
