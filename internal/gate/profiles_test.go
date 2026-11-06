package gate

import (
	"context"
	"testing"
	"time"

	"github.com/byward-dev/byward/internal/idp"
	"github.com/byward-dev/byward/internal/idp/entra"
	"github.com/byward-dev/byward/internal/idp/oidc"
	"github.com/byward-dev/byward/internal/testutil/fakeidp"
)

const (
	redirect = "https://proxy.example/callback/x"
	secret   = "test-secret-value"
)

var login = idp.Login{State: "s", Nonce: "n", CodeVerifier: "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"}

func now() time.Time { return time.Unix(1_800_000_000, 0) }

// signIn logs u in at a fake IdP through the real adapter and returns the Identity the broker
// would hand to the gate.
func signIn(t *testing.T, profile fakeidp.Profile, preset string, u fakeidp.User) (idp.Identity, string) {
	t.Helper()
	c := fakeidp.Client{ID: fakeidp.NewGUID(), Secrets: []string{secret}, RedirectURIs: []string{redirect}}
	fake := fakeidp.New(t, profile, fakeidp.WithClient(c), fakeidp.WithClock(now), fakeidp.WithUser(u))
	var a idp.Authenticator
	if profile == fakeidp.Entra {
		p, err := entra.New(entra.Config{Tenant: fake.TenantID(), ClientID: c.ID, ClientAuth: idp.ClientSecret(secret),
			RedirectURL: redirect, HTTPClient: fake.HTTPClient(), Now: now})
		if err != nil {
			t.Fatal(err)
		}
		a = p
	} else {
		p, err := oidc.New(oidc.Config{Preset: preset, Issuer: fake.Issuer(), ClientID: c.ID, ClientAuth: idp.ClientSecret(secret), RedirectURL: redirect, Now: now})
		if err != nil {
			t.Fatal(err)
		}
		a = p
	}
	loginURL, err := a.AuthCodeURL(context.Background(), login)
	if err != nil {
		t.Fatal(err)
	}
	id, _, err := a.Callback(context.Background(), fake.Authorize(t, loginURL), login)
	if err != nil {
		t.Fatal(err)
	}
	return id, fake.TenantID()
}

func TestGateDecidesOnIdentitiesFromARealEntraSignIn(t *testing.T) {
	g1, g2 := fakeidp.NewGUID(), fakeidp.NewGUID()
	many := make([]string, 201)
	for i := range many {
		many[i] = fakeidp.NewGUID()
	}
	for name, tc := range map[string]struct {
		user  fakeidp.User
		rules func(tid string) Rules
		deny  string
	}{
		"no roles, empty gate":    {user: fakeidp.User{}, rules: func(string) Rules { return Rules{} }},
		"no roles, role required": {user: fakeidp.User{}, rules: func(string) Rules { return Rules{Roles: []string{"MCP.User"}} }, deny: RuleRole},
		"with role":               {user: fakeidp.User{Roles: []string{"MCP.User"}}, rules: func(string) Rules { return Rules{Roles: []string{"MCP.User"}} }},
		"with group":              {user: fakeidp.User{Groups: []string{g1}}, rules: func(string) Rules { return Rules{Groups: []string{g1}} }},
		"other group":             {user: fakeidp.User{Groups: []string{g2}}, rules: func(string) Rules { return Rules{Groups: []string{g1}} }, deny: RuleGroup},
		"group overage denies even a member of the required group": {user: fakeidp.User{Groups: []string{g1}, GroupsOverage: true}, rules: func(string) Rules { return Rules{Groups: []string{g1}} }, deny: RuleGroupsUnavailable},
		"over 200 groups is an overage":                            {user: fakeidp.User{Groups: many}, rules: func(string) Rules { return Rules{Groups: []string{many[0]}} }, deny: RuleGroupsUnavailable},
		"overage is ignored by a roles-only gate":                  {user: fakeidp.User{Roles: []string{"R"}, GroupsOverage: true, Groups: []string{g1}}, rules: func(string) Rules { return Rules{Roles: []string{"R"}} }},
		"tenant allowlist":                                         {user: fakeidp.User{}, rules: func(tid string) Rules { return Rules{Tenants: []string{tid}} }},
	} {
		t.Run(name, func(t *testing.T) {
			id, tid := signIn(t, fakeidp.Entra, "", tc.user)
			g := mustGate(t, tc.rules(tid), Options{IdP: Entra, Tenant: tid})
			checkDecision(t, g.Allow(context.Background(), id), tc.deny)
		})
	}
}

func TestGateDecidesOnEmailVerificationAndHostedDomainFromARealOIDCSignIn(t *testing.T) {
	for name, tc := range map[string]struct {
		user fakeidp.User
		deny string
	}{
		"verified domain":   {user: fakeidp.User{Email: "a@contoso.example", EmailVerified: true}},
		"unverified domain": {user: fakeidp.User{Email: "a@contoso.example"}, deny: RuleEmailDomain},
	} {
		t.Run(name, func(t *testing.T) {
			id, _ := signIn(t, fakeidp.Generic, "", tc.user)
			err := mustGate(t, Rules{EmailDomains: []string{"contoso.example"}}, Options{IdP: Generic}).Allow(context.Background(), id)
			checkDecision(t, err, tc.deny)
		})
	}
	t.Run("google hd reaches the gate", func(t *testing.T) {
		id, _ := signIn(t, fakeidp.Generic, "google", fakeidp.User{HostedDomain: "contoso.example"})
		checkDecision(t, mustGate(t, Rules{HostedDomains: []string{"contoso.example"}}, Options{IdP: Google}).Allow(context.Background(), id), "")
	})
}
