package fakeidp

import (
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
