package broker

import (
	"encoding/json"
	"fmt"
	"net/http"
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
		name   string
		assert Asserted
		want   func(u fakeidp.User) (roles, groups []string, email, name string)
	}{
		{"nothing opted in", Asserted{}, func(fakeidp.User) ([]string, []string, string, string) { return nil, nil, "", "" }},
		{"roles (the default)", Asserted{Roles: true}, func(u fakeidp.User) ([]string, []string, string, string) { return u.Roles, nil, "", "" }},
		{"everything", Asserted{Roles: true, Groups: true, Email: true, Name: true}, func(u fakeidp.User) ([]string, []string, string, string) {
			return u.Roles, u.Groups, u.Email, u.Name
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := newEnv(t, withAssert(tc.assert))
			e.fake.Set(fakeidp.WithUser(user))
			c := e.opened(t, e.offline(t))
			roles, groups, email, name := tc.want(user)
			if c.ClientID != clientID || !reflect.DeepEqual(c.Roles, roles) || !reflect.DeepEqual(c.Groups, groups) || c.Email != email || c.Name != name {
				t.Fatalf("claims %+v", c)
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
	e.st.rewriteBlob = func(blob []byte) []byte {
		plain, err := e.idpBox.Open(string(blob))
		if err != nil {
			t.Fatal(err)
		}
		s, err := unmarshalSecrets(plain)
		if err != nil {
			t.Fatal(err)
		}
		legacy, _ := json.Marshal(s.Tokens) //nolint:gosec // G117: re-sealed below, as the broker sealed it before
		sealed, err := e.idpBox.Seal(legacy, e.now.Add(GrantLifetime))
		if err != nil {
			t.Fatal(err)
		}
		return []byte(sealed)
	}
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

// Groups the IdP left out (Entra overage) are never asserted as an incomplete list.
func TestGroupsOverageAssertsNoGroups(t *testing.T) {
	e := newEnv(t, withAssert(Asserted{Groups: true}))
	e.fake.Set(fakeidp.WithUser(fakeidp.User{GroupsOverage: true}))
	if c := e.opened(t, e.offline(t)); c.Groups != nil {
		t.Fatalf("groups %v", c.Groups)
	}
}

func TestGrantSecretsReadBothLayouts(t *testing.T) {
	toks := idp.Tokens{IDToken: "a.b.c", RefreshToken: "rt"}
	legacy, _ := json.Marshal(toks) //nolint:gosec // G117: test data
	for name, tc := range map[string]struct {
		plain []byte
		want  grantSecrets
		ok    bool
	}{
		"current":        {marshalSecrets(toks, assertedClaims{Roles: []string{"r"}}), grantSecrets{Version: 1, Tokens: toks, Claims: assertedClaims{Roles: []string{"r"}}}, true},
		"legacy":         {legacy, grantSecrets{Tokens: toks}, true},
		"future version": {[]byte(`{"v":2,"t":{}}`), grantSecrets{}, false},
		"not JSON":       {[]byte("x"), grantSecrets{}, false},
	} {
		t.Run(name, func(t *testing.T) {
			got, err := unmarshalSecrets(tc.plain)
			if (err == nil) != tc.ok || !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("got %+v, %v", got, err)
			}
		})
	}
}
