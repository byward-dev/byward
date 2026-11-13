package gate

import (
	"context"
	"slices"
	"strings"
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

// issuerPaths are what each preset's issuer check needs after the fake's URL.
var issuerPaths = map[string]string{"okta": "/oauth2/default", "auth0": "/", "keycloak": "/realms/acme"}

// signIn logs u in at a fake IdP through the real adapter, with opts applied to a generic
// adapter's Config, and returns the Identity the broker would hand to the gate.
func signIn(t *testing.T, profile fakeidp.Profile, preset string, u fakeidp.User, opts ...func(*oidc.Config)) (idp.Identity, string) {
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
		if path := issuerPaths[preset]; path != "" {
			fake.Set(fakeidp.WithIssuer(strings.TrimSuffix(fake.Issuer(), "/") + path))
		}
		cfg := oidc.Config{Preset: preset, Issuer: fake.Issuer(), ClientID: c.ID, ClientAuth: idp.ClientSecret(secret), RedirectURL: redirect, Now: now, AllowLoopbackHTTP: true} // the fake serves http on loopback
		for _, o := range opts {
			o(&cfg)
		}
		p, err := oidc.New(cfg)
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

// namespacedRoles and namespacedGroups are an Auth0 Action's roles and groups claims, which no preset
// reads by default.
const namespacedRoles, namespacedGroups = "https://byward.dev/roles", "https://byward.dev/groups"

// With BYWARD_OIDC_ROLES_CLAIM and BYWARD_OIDC_GROUPS_CLAIM unset, every IdP's gate reads the
// top-level roles and groups claims, as on v0.2.0-rc.1, and ignores namespaced ones (#286).
func TestEveryIdPGatesOnTheTopLevelRolesAndGroupsByDefault(t *testing.T) {
	group, other := fakeidp.NewGUID(), fakeidp.NewGUID()
	for _, tc := range []struct {
		idp     string
		profile fakeidp.Profile
		preset  string
		kind    string
	}{
		{"entra", fakeidp.Entra, "", Entra},
		{"keycloak", fakeidp.Generic, "keycloak", Generic},
		{"google", fakeidp.Generic, "google", Google},
		{"okta", fakeidp.Generic, "okta", Generic},
		{"auth0", fakeidp.Generic, "auth0", Generic},
		{"oidc", fakeidp.Generic, "", Generic},
	} {
		t.Run(tc.idp, func(t *testing.T) {
			u := fakeidp.User{Claims: map[string]any{namespacedRoles: []string{"Namespaced.Role"}, namespacedGroups: []string{other}}}
			if tc.profile == fakeidp.Entra {
				u.Roles, u.Groups = []string{"MCP.User"}, []string{group}
			} else {
				u.Claims["roles"], u.Claims["groups"] = []string{"MCP.User"}, []string{group}
			}
			id, tid := signIn(t, tc.profile, tc.preset, u)
			if !slices.Equal(id.Roles, []string{"MCP.User"}) || !slices.Equal(id.Groups, []string{group}) {
				t.Fatalf("roles %q, groups %q; want the top-level roles and groups claims only", id.Roles, id.Groups)
			}
			o := Options{IdP: tc.kind, Tenant: tid}
			checkDecision(t, mustGate(t, Rules{Roles: []string{"MCP.User"}, Groups: []string{group}}, o).Allow(context.Background(), id), "")
			checkDecision(t, mustGate(t, Rules{Roles: []string{"Namespaced.Role"}}, o).Allow(context.Background(), id), RuleRole)
			checkDecision(t, mustGate(t, Rules{Groups: []string{other}}, o).Allow(context.Background(), id), RuleGroup)
		})
	}
}

// The gate follows the claims the adapter is told to read: an Auth0 user whose role is in the named
// namespaced claim is admitted, one whose role is only in the top-level claim is not. The adapter's
// own tests cover the claim choice in full.
func TestTheGateFollowsTheNamedRolesClaim(t *testing.T) {
	named := func(c *oidc.Config) { c.RolesClaim = namespacedRoles }
	for name, tc := range map[string]struct {
		claims map[string]any
		deny   string
	}{
		"the role in the named claim":     {map[string]any{namespacedRoles: []string{"mcp-user"}}, ""},
		"the role in the top-level claim": {map[string]any{"roles": []string{"mcp-user"}}, RuleRole},
	} {
		t.Run(name, func(t *testing.T) {
			id, _ := signIn(t, fakeidp.Generic, "auth0", fakeidp.User{Claims: tc.claims}, named)
			checkDecision(t, mustGate(t, Rules{Roles: []string{"mcp-user"}}, Options{IdP: Generic}).Allow(context.Background(), id), tc.deny)
		})
	}
}
