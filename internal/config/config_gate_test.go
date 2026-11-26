package config

import (
	"slices"
	"strings"
	"testing"

	"github.com/byward-dev/byward/internal/gate"
)

// Each gate and app list entry is refused by its own rule, named by its place and length, never
// shown (#495). A role is an Entra app role value with Entra, as Microsoft Graph's appRole resource
// defines one (appRoleValues quotes it), and a name of up to 256 bytes with another IdP.
func TestEachGateAndAppListEntryIsRefusedByItsOwnRule(t *testing.T) {
	type idpContext struct {
		env   []string
		files readFileFunc
	}
	type entryCase struct {
		name string
		ctx  idpContext
		kv   string
		want string // "" when it loads
	}
	entra := idpContext{base, baseFiles}
	appOn := idpContext{append(slices.Clone(base), "BYWARD_APP_TOKENS=entra"), baseFiles}
	appWithRole := idpContext{append(slices.Clone(appOn.env), "BYWARD_APP_ROLES=r"), baseFiles}
	oidc := idpContext{oidcBase, oidcFiles}
	google := idpContext{with("BYWARD_IDP=google")(without("BYWARD_IDP", "BYWARD_OIDC_ISSUER")(slices.Clone(oidcBase))), oidcFiles}
	role := "app role values, each at most 120 letters, digits or ASCII punctuation (no space, \" or \\), not starting with ."
	cases := []entryCase{
		{"an Entra gate role of 120 characters", entra, "BYWARD_GATE_ROLES=" + strings.Repeat("r", 120), ""},
		{"an Entra gate role of 121 characters", entra, "BYWARD_GATE_ROLES=" + strings.Repeat("r", 121),
			"BYWARD_GATE_ROLES: want " + role + "; got entry 1 of 1 (121 characters, not shown): it is longer than 120 characters"},
		{"an Entra gate role with a space", entra, "BYWARD_GATE_ROLES=MCP User",
			"BYWARD_GATE_ROLES: want " + role + "; got entry 1 of 1 (8 characters, not shown): it has a character an app role value cannot hold"},
		{"an Entra gate role with a quote", entra, `BYWARD_GATE_ROLES=MCP"User`,
			"BYWARD_GATE_ROLES: want " + role + "; got entry 1 of 1 (8 characters, not shown): it has a character an app role value cannot hold"},
		{"an Entra gate role of 61 letters that are not ASCII", entra, "BYWARD_GATE_ROLES=" + strings.Repeat("é", 61),
			"BYWARD_GATE_ROLES: want " + role + "; got entry 1 of 1 (61 characters, not shown): it has a character an app role value cannot hold"},
		{"an Entra gate role with a letter that is not ASCII", entra, "BYWARD_GATE_ROLES=" + strings.Repeat("é", 60),
			"BYWARD_GATE_ROLES: want " + role + "; got entry 1 of 1 (60 characters, not shown): it has a character an app role value cannot hold"},
		{"an Entra gate role with a control character", entra, "BYWARD_GATE_ROLES=a\x01b",
			"BYWARD_GATE_ROLES: want " + role + "; got entry 1 of 1 (3 characters, not shown): it has a character an app role value cannot hold"},
		{"an Entra gate role with DEL", entra, "BYWARD_GATE_ROLES=a\x7fb",
			"BYWARD_GATE_ROLES: want " + role + "; got entry 1 of 1 (3 characters, not shown): it has a character an app role value cannot hold"},
		{"an Entra gate role starting with a dot", entra, "BYWARD_GATE_ROLES=.User",
			"BYWARD_GATE_ROLES: want " + role + "; got entry 1 of 1 (5 characters, not shown): it starts with ."},
		{"an Entra gate role of Graph's punctuation", entra, "BYWARD_GATE_ROLES=MCP.User:read/all_v2~x", ""},
		{"an app role of 120 characters", appOn, "BYWARD_APP_ROLES=" + strings.Repeat("r", 120), ""},
		{"an app role of 121 characters", appOn, "BYWARD_APP_ROLES=" + strings.Repeat("r", 121),
			"BYWARD_APP_ROLES: want " + role + "; got entry 1 of 1 (121 characters, not shown): it is longer than 120 characters"},
		{"an oidc gate role of 256 bytes", oidc, "BYWARD_GATE_ROLES=" + strings.Repeat("r", 256), ""},
		{"an Entra gate role with a backslash", entra, `BYWARD_GATE_ROLES=MCP\User`,
			"BYWARD_GATE_ROLES: want " + role + "; got entry 1 of 1 (8 characters, not shown): it has a character an app role value cannot hold"},
		{"two gate tenants that are not GUIDs", entra, "BYWARD_GATE_TENANTS=bad1,bad2",
			"BYWARD_GATE_TENANTS: want tenant IDs, each a GUID such as 00000000-0000-0000-0000-000000000000; got entry 1 of 2 (4 characters, not shown): it is not a GUID; " +
				"BYWARD_GATE_TENANTS: want tenant IDs, each a GUID such as 00000000-0000-0000-0000-000000000000; got entry 2 of 2 (4 characters, not shown): it is not a GUID"},
		{"an oidc gate role of 121 characters", oidc, "BYWARD_GATE_ROLES=" + strings.Repeat("r", 121), ""},
		{"an oidc gate role with a space", oidc, "BYWARD_GATE_ROLES=MCP User", ""},
		{"an oidc gate role of 257 bytes", oidc, "BYWARD_GATE_ROLES=" + strings.Repeat("r", 257),
			"BYWARD_GATE_ROLES: want role names, each at most 256 bytes without control characters; got entry 1 of 1 (257 characters, not shown): it is longer than 256 bytes"},
		{"an oidc gate role with a control character", oidc, "BYWARD_GATE_ROLES=a\x01b",
			"BYWARD_GATE_ROLES: want role names, each at most 256 bytes without control characters; got entry 1 of 1 (3 characters, not shown): it has a control character"},
		{"an oidc gate role with the last control character", oidc, "BYWARD_GATE_ROLES=a\x1fb",
			"BYWARD_GATE_ROLES: want role names, each at most 256 bytes without control characters; got entry 1 of 1 (3 characters, not shown): it has a control character"},
		{"an oidc gate role with DEL", oidc, "BYWARD_GATE_ROLES=a\x7fb",
			"BYWARD_GATE_ROLES: want role names, each at most 256 bytes without control characters; got entry 1 of 1 (3 characters, not shown): it has a control character"},
		{"an Entra gate group that is a name", entra, "BYWARD_GATE_GROUPS=mcp-users",
			"BYWARD_GATE_GROUPS: want group object IDs, each a GUID such as 00000000-0000-0000-0000-000000000000; got entry 1 of 1 (9 characters, not shown): it is not a GUID"},
		{"an oidc gate group that is a name", oidc, "BYWARD_GATE_GROUPS=mcp-users", ""},
		{"a gate tenant that is not a GUID", entra, "BYWARD_GATE_TENANTS=0a1b2c3d-4e5f-6a7b-8c9d-0e1f2a3b4c5",
			"BYWARD_GATE_TENANTS: want tenant IDs, each a GUID such as 00000000-0000-0000-0000-000000000000; got entry 1 of 1 (35 characters, not shown): it is not a GUID"},
		{"an email domain with an @", oidc, "BYWARD_GATE_EMAIL_DOMAINS=@contoso.example",
			"BYWARD_GATE_EMAIL_DOMAINS: want domain names such as example.com, without @ or wildcards; got entry 1 of 1 (16 characters, not shown): it is not a domain name"},
		{"an email domain in capitals", oidc, "BYWARD_GATE_EMAIL_DOMAINS=Contoso.Example", ""},
		{"a wildcard hosted domain", google, "BYWARD_GATE_HOSTED_DOMAINS=*.contoso.example",
			"BYWARD_GATE_HOSTED_DOMAINS: want domain names such as example.com, without @ or wildcards; got entry 1 of 1 (17 characters, not shown): it is not a domain name"},
		{"an app client ID that is not a GUID", appWithRole, "BYWARD_APP_CLIENT_IDS=my-app",
			"BYWARD_APP_CLIENT_IDS: want application (client) IDs, each a GUID such as 00000000-0000-0000-0000-000000000000; got entry 1 of 1 (6 characters, not shown): it is not a GUID"},
	}
	// Each punctuation character Graph's appRole value allows, as Graph lists it, loads with Entra.
	for _, c := range ":!#$%&'()*+,-./;<=>?@[]^_`{|}~" {
		if c == ',' { // the list separator: two roles, each of which loads
			continue
		}
		cases = append(cases, entryCase{"an Entra gate role with " + string(c), entra, "BYWARD_GATE_ROLES=a" + string(c) + "b", ""})
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, _, err := Load(nil, append(slices.Clone(tc.ctx.env), tc.kv), tc.ctx.files)
			switch {
			case tc.want == "" && err != nil:
				t.Errorf("%v, want it to load", err)
			case tc.want != "" && (!isConfigError(err) || err.Error() != tc.want):
				t.Errorf("%v\nwant %s", err, tc.want)
			}
		})
	}
}

// Where a GUID list entry belongs, a domain name, in any case, is named as one: the likely mistake is
// the tenant's domain (walkthrough 09). The Entra tenant and client ID settings are pinned in
// TestTheEntraIDsTakeAGUIDInEitherCaseAndRefuseAnythingElse.
func TestADomainGivenWhereAGUIDListEntryBelongsIsNamedAsADomain(t *testing.T) {
	for name, what := range map[string]string{"gate-tenants": "tenant IDs", "gate-groups": "group object IDs", "app-client-ids": "application (client) IDs"} {
		s := lookup(name)
		c := readContextOf(s)
		for _, domain := range []string{"contoso.onmicrosoft.com", "CONTOSO.onmicrosoft.com"} {
			_, _, err := Load(c.args, append(slices.Clone(c.env), s.Env()+"="+domain), c.files)
			want := s.Env() + ": want " + what + ", each a GUID such as 00000000-0000-0000-0000-000000000000; got entry 1 of 1 (23 characters, not shown): it looks like a domain name, not a GUID"
			if !isConfigError(err) || err.Error() != want {
				t.Errorf("%s=%s: %v\nwant %s", s.Env(), domain, err, want)
			}
		}
	}
}

// Config's copies of gate's rules for names, GUIDs and domain names are gate's: an entry config
// accepts, gate accepts, and one config refuses, gate refuses for that rule, so the backstop never
// refuses what config let through, and a change on either side fails here, not in review.
func TestConfigsGateRulesAreGates(t *testing.T) {
	const tenant = "11111111-1111-4111-8111-111111111111"
	for _, rule := range []struct {
		name    string
		entries []string
		config  func(string) bool
		gate    func(string) (gate.Rules, gate.Options)
		refusal string
	}{
		{"names", []string{"r", strings.Repeat("r", 256), strings.Repeat("r", 257), "a\x00b", "a\x1fb", "a\x7fb", "a\tb", "MCP User", "é"},
			func(s string) bool { return names("").reason(s) == "" },
			func(s string) (gate.Rules, gate.Options) {
				return gate.Rules{Roles: []string{s}}, gate.Options{IdP: gate.Generic}
			}, "not a valid name"},
		{"GUIDs", []string{tenant, strings.ToUpper(tenant), "11111111111141118111111111111111", tenant[:35], tenant + "1", "{" + tenant[1:35] + "}", "g1111111-1111-4111-8111-111111111111", "AAAAAAAA-BBBB-4CCC-8DDD-EEEEEEEEEEEF"},
			isGUID,
			func(s string) (gate.Rules, gate.Options) {
				return gate.Rules{Groups: []string{s}}, gate.Options{IdP: gate.Entra, Tenant: tenant}
			}, "not a GUID"},
		{"domain names", []string{"example.com", "a.b.c.example", "xn--bcher-kva.example", "EXAMPLE.com", "a-b.example",
			"example", ".example.com", "example.com.", "a..b", "-a.example", "a-.example", "*.example.com", "a_b.example",
			"user@example.com", strings.Repeat("a", 63) + ".example", strings.Repeat("a", 64) + ".example", strings.Repeat("a.", 126) + "a", strings.Repeat("a.", 126) + "ab"},
			func(s string) bool { return validDomain(strings.ToLower(s)) },
			func(s string) (gate.Rules, gate.Options) {
				return gate.Rules{EmailDomains: []string{s}}, gate.Options{IdP: gate.Generic}
			}, "not a domain name"},
	} {
		for _, e := range rule.entries {
			_, _, err := gate.New(rule.gate(e))
			if err != nil && !strings.Contains(err.Error(), rule.refusal) {
				t.Fatalf("%s %q: gate refused it for another reason: %v", rule.name, e, err)
			}
			if config, gateOK := rule.config(e), err == nil; config != gateOK {
				t.Errorf("%s %q: config takes it %v, gate %v (%v)", rule.name, e, config, gateOK, err)
			}
		}
	}
}
