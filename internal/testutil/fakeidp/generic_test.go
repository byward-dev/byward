package fakeidp

import (
	"encoding/json"
	"net/http"
	"testing"
)

func TestGenericLoginIssuesPlainOIDCTokensWithoutEntraClaims(t *testing.T) {
	f := newFixture(t, Generic, WithUser(User{Email: "test.user@contoso.example", EmailVerified: true,
		HostedDomain: "contoso.example", Groups: []string{"mcp-users"}}))
	u := f.idp.User()
	r := f.login(t)
	if r.str("access_token") == "" || r.str("refresh_token") == "" {
		t.Fatalf("body = %v", r.body)
	}
	_, id := f.verified(t, r.str("id_token"))
	wantClaim(t, id, "iss", f.idp.URL())
	wantClaim(t, id, "aud", f.client.ID)
	wantClaim(t, id, "sub", u.Subject)
	wantClaim(t, id, "azp", f.client.ID)
	wantClaim(t, id, "nonce", "nonce-1")
	wantClaim(t, id, "email_verified", true)
	wantClaim(t, id, "hd", "contoso.example")
	wantClaim(t, id, "groups", []string{"mcp-users"})
	for _, entraOnly := range []string{"tid", "oid", "ver"} {
		if _, ok := id[entraOnly]; ok {
			t.Errorf("generic ID token has %s", entraOnly)
		}
	}

	wantStatus(t, f.token(t, refreshForm(r.str("refresh_token"))), http.StatusOK)
}

func TestGenericEmailVerifiedAsString(t *testing.T) {
	f := newFixture(t, Generic, WithEmailVerifiedAsString(true), WithUser(User{Email: "test.user@contoso.example"}))
	_, id := f.verified(t, f.login(t).str("id_token"))
	wantClaim(t, id, "email_verified", "false")
}

func TestGenericWithIssuer(t *testing.T) {
	f := newFixture(t, Generic, WithIssuer("https://issuer.example/"))
	_, id := f.verified(t, f.login(t).str("id_token"))
	wantClaim(t, id, "iss", "https://issuer.example/")
}

// An issuer with a path, as the keycloak and okta presets need, is discovered under exactly that
// path; any other path, another realm's included, is not found.
func TestGenericDiscoveryIsServedUnderTheIssuersPath(t *testing.T) {
	f := newFixture(t, Generic)
	f.idp.Set(WithIssuer(f.idp.URL() + "/realms/acme"))
	for path, want := range map[string]int{
		"/realms/acme/.well-known/openid-configuration":  http.StatusOK,
		"/realms/acme/anything":                          http.StatusNotFound,
		"/realms/acme/.well-known/other":                 http.StatusNotFound,
		"/realms/other/.well-known/openid-configuration": http.StatusNotFound,
	} {
		t.Run(path, func(t *testing.T) {
			res, err := http.Get(f.idp.URL() + path)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = res.Body.Close() }()
			var doc struct{ Issuer string }
			_ = json.NewDecoder(res.Body).Decode(&doc)
			if res.StatusCode != want || (want == http.StatusOK && doc.Issuer != f.idp.URL()+"/realms/acme") {
				t.Fatalf("status %d, issuer %q; want %d with the issuer under the path", res.StatusCode, doc.Issuer, want)
			}
		})
	}
}

// A user's Claims override the profile's claim of the same name, as their comment says.
func TestUserClaimsOverrideTheProfilesClaims(t *testing.T) {
	f := newFixture(t, Generic, WithUser(User{Groups: []string{"profile-group"}, Claims: map[string]any{"groups": []string{"raw-group"}}}))
	_, id := f.verified(t, f.login(t).str("id_token"))
	wantClaim(t, id, "groups", []string{"raw-group"})
}

func TestNewRejectsUnknownProfile(t *testing.T) {
	ft := &fatalRecorder{TB: t}
	func() {
		defer func() {
			if r := recover(); r != nil && r != "fatal" {
				panic(r)
			}
		}()
		New(ft, "okta")
	}()
	if !ft.failed {
		t.Fatal("unknown profile accepted")
	}
}

type fatalRecorder struct {
	testing.TB
	failed bool
}

func (r *fatalRecorder) Fatalf(string, ...any) { r.failed = true; panic("fatal") }
func (r *fatalRecorder) Helper()               {}
