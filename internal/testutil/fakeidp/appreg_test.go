package fakeidp

import (
	"net/http"
	"net/url"
	"testing"
)

// App registration misconfigurations doctor reports (#66): v1 tokens, no Application ID URI, and a
// tenant that does not exist.

func ownDefault(f *fixture) url.Values {
	return url.Values{"grant_type": {GrantClientCredentials}, "scope": {"api://" + f.client.ID + "/.default"}}
}

func TestAccessTokenVersion1IssuesV1Tokens(t *testing.T) {
	f := newFixture(t, Entra)
	c := f.client
	c.AccessTokenVersion = 1
	f.idp.Set(WithClient(c))
	for name, tok := range map[string]string{
		"app-only": f.token(t, ownDefault(f)).str("access_token"),
		"delegated": func() string {
			r := f.login(t)
			return r.str("access_token")
		}(),
	} {
		t.Run(name, func(t *testing.T) {
			_, claims := f.verified(t, tok)
			if claims["ver"] != "1.0" || claims["iss"] != "https://sts.windows.net/"+f.tenant+"/" || claims["aud"] != "api://"+f.client.ID {
				t.Fatalf("claims %v, want a v1 token for api://%s", claims, f.client.ID)
			}
			if _, ok := claims["azp"]; ok || claims["appid"] != f.client.ID {
				t.Fatalf("claims %v, want appid instead of azp", claims)
			}
		})
	}
}

func TestDefaultAccessTokenVersionIsV2(t *testing.T) {
	f := newFixture(t, Entra)
	_, claims := f.verified(t, f.token(t, ownDefault(f)).str("access_token"))
	if claims["ver"] != "2.0" || claims["aud"] != f.client.ID || claims["azp"] != f.client.ID {
		t.Fatalf("claims %v, want a v2 token with aud and azp = the client ID", claims)
	}
}

func TestNoIdentifierURIRefusesAPIScopesWithAADSTS500011(t *testing.T) {
	f := newFixture(t, Entra)
	c := f.client
	c.NoIdentifierURI = true
	f.idp.Set(WithClient(c))
	wantEntraError(t, f.token(t, ownDefault(f)), http.StatusBadRequest, "invalid_resource", 500011)
	// The GUID form of the resource does not need the URI.
	r := f.token(t, url.Values{"grant_type": {GrantClientCredentials}, "scope": {f.client.ID + "/.default"}})
	wantStatus(t, r, http.StatusOK)
}

func TestUnknownTenantsAreRefusedOnlyWhenAsked(t *testing.T) {
	cases := []struct {
		name    string
		refuse  bool
		tenant  func(f *fixture) string
		wantGet int
	}{
		{"unknown tenant, refused", true, func(*fixture) string { return NewGUID() }, http.StatusBadRequest},
		{"own tenant, refused mode", true, func(f *fixture) string { return f.tenant }, http.StatusOK},
		{"organizations, refused mode", true, func(*fixture) string { return "organizations" }, http.StatusOK},
		{"any GUID by default", false, func(*fixture) string { return NewGUID() }, http.StatusOK},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t, Entra, WithUnknownTenantsRefused(tc.refuse))
			resp, err := http.Get(f.idp.DiscoveryURL(tc.tenant(f)))
			if err != nil {
				t.Fatal(err)
			}
			_ = resp.Body.Close()
			if resp.StatusCode != tc.wantGet {
				t.Fatalf("discovery: %d, want %d", resp.StatusCode, tc.wantGet)
			}
		})
	}
}

func TestUnknownTenantAtTheTokenEndpointIsAADSTS90002(t *testing.T) {
	f := newFixture(t, Entra, WithUnknownTenantsRefused(true))
	wantEntraError(t, postToken(t, f.idp.TokenURL(NewGUID()), ownDefault(f), nil), http.StatusBadRequest, "invalid_tenant", 90002)
}

func TestEmptyJWKSServesNoKeys(t *testing.T) {
	f := newFixture(t, Entra, WithEmptyJWKS(true))
	if keys := f.jwks(t); len(keys) != 0 {
		t.Fatalf("keys %v", keys)
	}
}
