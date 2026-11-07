package broker

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"reflect"
	"strings"
	"testing"

	"github.com/byward-dev/byward/internal/idp"
	"github.com/byward-dev/byward/internal/testutil/fakeidp"
	"github.com/byward-dev/byward/internal/token"
)

// opened returns the claims sealed in an access token response.
func (e *env) opened(t *testing.T, body map[string]any) token.Claims {
	t.Helper()
	c, err := e.sealer.Open(token.Access, body["access_token"].(string))
	if err != nil {
		t.Fatalf("access token does not open: %v (%v)", err, body)
	}
	return c
}

func withAssert(a Asserted) func(*Config) { return func(c *Config) { c.Assert = a } }

// The access token carries the client and exactly the identity claims the operator opted in to;
// the user's other attributes stay out (ADR-0016 §1, ADR-0021 §4).
func TestAccessTokensCarryTheClientAndOnlyTheOptedInClaims(t *testing.T) {
	user := fakeidp.User{Roles: []string{"byward.user"}, Groups: []string{fakeidp.NewGUID()}, Email: "alex@contoso.example", Name: "Alex"}
	cases := []struct {
		name                string
		assert              Asserted
		wantRoles, wantGrps []string
		wantEmail, wantName string
	}{
		{name: "nothing opted in"},
		{name: "roles (the default)", assert: Asserted{Roles: true}, wantRoles: user.Roles},
		// Entra never verifies an email, so it is asserted only with the opt-in to unverified ones.
		{name: "everything", assert: Asserted{Roles: true, Groups: true, Email: true, Name: true},
			wantRoles: user.Roles, wantGrps: user.Groups, wantName: user.Name},
		{name: "everything and unverified emails", assert: Asserted{Roles: true, Groups: true, Email: true, Name: true, UnverifiedEmail: true},
			wantRoles: user.Roles, wantGrps: user.Groups, wantEmail: user.Email, wantName: user.Name},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := newEnv(t, withAssert(tc.assert))
			e.fake.Set(fakeidp.WithUser(user))
			c := e.opened(t, e.offline(t))
			if c.ClientID != clientID || !reflect.DeepEqual(c.Roles, tc.wantRoles) || !reflect.DeepEqual(c.Groups, tc.wantGrps) ||
				c.Email != tc.wantEmail || c.EmailVerified || c.Name != tc.wantName {
				t.Fatalf("claims %+v", c)
			}
		})
	}
}

// Only an email the IdP vouches for is asserted, unless the operator opted in to unverified ones;
// EmailVerified then tells the two apart (ADR-0016, 2026-11-07 amendment).
func TestAnEmailIsAssertedOnlyWhenTheIdPVerifiedItOrTheOperatorOptedIn(t *testing.T) {
	const email = "alex@contoso.example"
	verified, unverified := idp.Identity{Email: email, EmailVerified: true}, idp.Identity{Email: email}
	for _, tc := range []struct {
		name   string
		assert Asserted
		id     idp.Identity
		want   assertedClaims
	}{
		{"a verified email", Asserted{Email: true}, verified, assertedClaims{Email: email, EmailVerified: true}},
		{"an unverified email is left out", Asserted{Email: true}, unverified, assertedClaims{}},
		{"an unverified email with the opt-in", Asserted{Email: true, UnverifiedEmail: true}, unverified, assertedClaims{Email: email}},
		{"a verified email with the opt-in", Asserted{Email: true, UnverifiedEmail: true}, verified, assertedClaims{Email: email, EmailVerified: true}},
		{"the opt-in alone asserts no email", Asserted{UnverifiedEmail: true}, verified, assertedClaims{}},
		{"verified but no address", Asserted{Email: true}, idp.Identity{EmailVerified: true}, assertedClaims{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.assert.claimsOf(tc.id); !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("claims %+v, want %+v", got, tc.want)
			}
		})
	}
}

// Every refresh asks the IdP again, so the claims are at most one access-token lifetime old.
func TestRefreshAssertsTheRolesTheIdPReturnsNow(t *testing.T) {
	e := newEnv(t, withAssert(Asserted{Roles: true}))
	e.fake.Set(fakeidp.WithUser(fakeidp.User{Roles: []string{"byward.user"}}))
	body := e.offline(t)
	u := e.fake.User() // the same user, whose roles changed at the IdP
	u.Roles = []string{"byward.user", "byward.admin"}
	e.fake.Set(fakeidp.WithUser(u))
	res, body := e.refresh(t, body["refresh_token"].(string), "")
	if res.StatusCode != http.StatusOK {
		t.Fatalf("refresh: %d %v", res.StatusCode, body)
	}
	if c := e.opened(t, body); !reflect.DeepEqual(c.Roles, []string{"byward.user", "byward.admin"}) {
		t.Fatalf("roles after refresh %v", c.Roles)
	}
}

// A grant sealed before the claims were kept (the IdP tokens alone) still redeems and refreshes;
// its first access token carries no claims, and every refresh after it does.
func TestAGrantSealedWithoutClaimsStillWorks(t *testing.T) {
	e := newEnv(t, withAssert(Asserted{Roles: true}))
	e.fake.Set(fakeidp.WithUser(fakeidp.User{Roles: []string{"byward.user"}}))
	e.resealBlob(t, func(plain []byte) []byte {
		s, err := unmarshalSecrets(plain)
		if err != nil {
			t.Fatal(err)
		}
		legacy, _ := json.Marshal(s.Tokens) //nolint:gosec // G117: re-sealed, as the broker sealed it before
		return legacy
	})
	body := e.offline(t)
	if c := e.opened(t, body); c.Roles != nil || c.ClientID != clientID {
		t.Fatalf("first token of a legacy grant %+v", c)
	}
	res, body := e.refresh(t, body["refresh_token"].(string), "")
	if res.StatusCode != http.StatusOK || !reflect.DeepEqual(e.opened(t, body).Roles, []string{"byward.user"}) {
		t.Fatalf("refresh of a legacy grant: %d %v", res.StatusCode, body)
	}
}

// Too many groups for a token: the sign-in still works and the assertion carries no groups, as
// with Entra's groups overage; the operator sees why.
func TestGroupsThatDoNotFitAreLeftOutWithAWarning(t *testing.T) {
	e := newEnv(t, withAssert(Asserted{Roles: true, Groups: true}))
	var groups []string // within Entra's 200-group limit, but too long for a token
	for i := range 200 {
		groups = append(groups, fmt.Sprintf("%03d-%s", i, strings.Repeat("g", 96)))
	}
	e.fake.Set(fakeidp.WithUser(fakeidp.User{Roles: []string{"byward.user"}, Groups: groups}))
	c := e.opened(t, e.offline(t))
	if c.Groups != nil || !reflect.DeepEqual(c.Roles, []string{"byward.user"}) {
		t.Fatalf("claims %+v", c)
	}
	if !strings.Contains(e.logs.String(), "the user's groups do not fit in an access token") {
		t.Fatalf("no warning in %s", e.logs.String())
	}
}

// Groups the IdP left out (Entra overage) are never asserted as an incomplete list, even when it
// still sent some.
func TestGroupsOverageAssertsNoGroups(t *testing.T) {
	c := Asserted{Roles: true, Groups: true}.claimsOf(idp.Identity{Roles: []string{"r"}, Groups: []string{"g"}, GroupsUnavailable: true})
	if c.Groups != nil || !reflect.DeepEqual(c.Roles, []string{"r"}) {
		t.Fatalf("claims %+v", c)
	}
}

// resealBlob makes every new grant's sealed IdP-token blob hold rewrite(plain) instead, as an
// older or newer proxy, or a damaged store, would have left it.
func (e *env) resealBlob(t *testing.T, rewrite func(plain []byte) []byte) {
	e.st.rewriteBlob = func(blob []byte) []byte {
		plain, err := e.idpBox.Open(string(blob))
		if err != nil {
			t.Fatal(err)
		}
		sealed, err := e.idpBox.Seal(rewrite(plain), e.now.Add(GrantLifetime))
		if err != nil {
			t.Fatal(err)
		}
		return []byte(sealed)
	}
}

// A grant whose IdP-token blob this proxy cannot read (written by a newer version before a
// rollback, or damaged) issues no token: the client gets a server error, never a token without
// the user's claims.
func TestAGrantWithAnUnreadableBlobIssuesNoToken(t *testing.T) {
	for name, plain := range map[string]string{"a newer layout": `{"v":2,"t":{}}`, "not JSON": "x"} {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t, withAssert(Asserted{Roles: true}))
			e.resealBlob(t, func([]byte) []byte { return []byte(plain) })
			code := e.signIn(t, url.Values{"scope": {"mcp offline_access"}}).Query().Get("code")
			res, body := e.redeem(t, code, nil)
			if res.StatusCode != http.StatusInternalServerError || body["error"] != "server_error" || body["access_token"] != nil {
				t.Fatalf("redeem: %d %v", res.StatusCode, body)
			}
		})
	}
}
