package gate

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/byward-dev/byward/internal/idp"
)

const (
	tenant = "aaaaaaaa-1111-4111-8111-111111111111"
	other  = "bbbbbbbb-2222-4222-8222-222222222222"
	group  = "cccccccc-3333-4333-8333-333333333333"
)

func entraOpts() Options { return Options{IdP: Entra, Tenant: tenant} }

func mustGate(t *testing.T, r Rules, o Options) *Gate {
	t.Helper()
	g, _, err := New(r, o)
	if err != nil {
		t.Fatal(err)
	}
	return g
}

func entraUser(mod func(*idp.Identity)) idp.Identity {
	id := idp.Identity{Subject: tenant + ":x", Claims: map[string]any{"tid": tenant}}
	if mod != nil {
		mod(&id)
	}
	return id
}

func TestGateAdmitsOnlyUsersMeetingEveryRuleAndNamesTheFailingRule(t *testing.T) {
	for name, tc := range map[string]struct {
		rules Rules
		opts  Options
		id    idp.Identity
		deny  string // "" = allowed
	}{
		"empty single-tenant gate":           {opts: entraOpts(), id: entraUser(nil)},
		"tenant allowed":                     {rules: Rules{Tenants: []string{tenant}}, opts: entraOpts(), id: entraUser(nil)},
		"configured tenant upper case":       {rules: Rules{Tenants: []string{tenant}}, opts: Options{IdP: Entra, Tenant: strings.ToUpper(tenant)}, id: entraUser(nil)},
		"hd upper case":                      {rules: Rules{HostedDomains: []string{"contoso.example"}}, opts: Options{IdP: Google}, id: idp.Identity{Claims: map[string]any{"hd": "Contoso.Example"}}},
		"tenant rule upper case":             {rules: Rules{Tenants: []string{strings.ToUpper(tenant)}}, opts: entraOpts(), id: entraUser(nil)},
		"group rule upper case":              {rules: Rules{Groups: []string{strings.ToUpper(group)}}, opts: entraOpts(), id: entraUser(func(i *idp.Identity) { i.Groups = []string{group} })},
		"email domain with hyphen and digit": {rules: Rules{EmailDomains: []string{"my-corp365.example"}}, opts: Options{IdP: Generic}, id: idp.Identity{Email: "a@my-corp365.example", EmailVerified: true}},
		"tenant upper case claim":            {rules: Rules{Tenants: []string{tenant}}, opts: entraOpts(), id: entraUser(func(i *idp.Identity) { i.Claims["tid"] = strings.ToUpper(tenant) })},
		"tenant not allowed":                 {rules: Rules{Tenants: []string{other}}, opts: Options{IdP: Entra, Tenant: "organizations"}, id: entraUser(nil), deny: RuleTenant},
		"tenant claim missing":               {rules: Rules{Tenants: []string{tenant}}, opts: entraOpts(), id: idp.Identity{}, deny: RuleTenant},
		"role present":                       {rules: Rules{Roles: []string{"MCP.User", "MCP.Admin"}}, opts: entraOpts(), id: entraUser(func(i *idp.Identity) { i.Roles = []string{"MCP.Admin"} })},
		"role missing":                       {rules: Rules{Roles: []string{"MCP.User"}}, opts: entraOpts(), id: entraUser(nil), deny: RuleRole},
		"role is case-sensitive":             {rules: Rules{Roles: []string{"MCP.User"}}, opts: entraOpts(), id: entraUser(func(i *idp.Identity) { i.Roles = []string{"mcp.user"} }), deny: RuleRole},
		"group present":                      {rules: Rules{Groups: []string{group}}, opts: entraOpts(), id: entraUser(func(i *idp.Identity) { i.Groups = []string{strings.ToUpper(group)} })},
		"group missing":                      {rules: Rules{Groups: []string{group}}, opts: entraOpts(), id: entraUser(func(i *idp.Identity) { i.Groups = []string{other} }), deny: RuleGroup},
		"groups overage denies":              {rules: Rules{Groups: []string{group}}, opts: entraOpts(), id: entraUser(func(i *idp.Identity) { i.Groups = []string{group}; i.GroupsUnavailable = true }), deny: RuleGroupsUnavailable},
		"overage ignored w/o groups":         {rules: Rules{Roles: []string{"R"}}, opts: entraOpts(), id: entraUser(func(i *idp.Identity) { i.Roles = []string{"R"}; i.GroupsUnavailable = true })},
		"role and group both needed":         {rules: Rules{Roles: []string{"R"}, Groups: []string{group}}, opts: entraOpts(), id: entraUser(func(i *idp.Identity) { i.Roles = []string{"R"} }), deny: RuleGroup},
		"email domain verified":              {rules: Rules{EmailDomains: []string{"Contoso.example"}}, opts: Options{IdP: Generic}, id: idp.Identity{Email: "a@CONTOSO.example", EmailVerified: true}},
		"email domain unverified":            {rules: Rules{EmailDomains: []string{"contoso.example"}}, opts: Options{IdP: Generic}, id: idp.Identity{Email: "a@contoso.example"}, deny: RuleEmailDomain},
		"email subdomain":                    {rules: Rules{EmailDomains: []string{"contoso.example"}}, opts: Options{IdP: Generic}, id: idp.Identity{Email: "a@evil.contoso.example", EmailVerified: true}, deny: RuleEmailDomain},
		"email suffix trick":                 {rules: Rules{EmailDomains: []string{"contoso.example"}}, opts: Options{IdP: Generic}, id: idp.Identity{Email: "a@evilcontoso.example", EmailVerified: true}, deny: RuleEmailDomain},
		"email two at signs":                 {rules: Rules{EmailDomains: []string{"contoso.example"}}, opts: Options{IdP: Generic}, id: idp.Identity{Email: "a@contoso.example@evil.example", EmailVerified: true}, deny: RuleEmailDomain},
		"no email":                           {rules: Rules{EmailDomains: []string{"contoso.example"}}, opts: Options{IdP: Generic}, id: idp.Identity{EmailVerified: true}, deny: RuleEmailDomain},
		"hd matches":                         {rules: Rules{HostedDomains: []string{"contoso.example"}}, opts: Options{IdP: Google}, id: idp.Identity{Claims: map[string]any{"hd": "contoso.example"}}},
		"hd missing":                         {rules: Rules{HostedDomains: []string{"contoso.example"}}, opts: Options{IdP: Google}, id: idp.Identity{Claims: map[string]any{}}, deny: RuleHostedDomain},
		"hd other":                           {rules: Rules{HostedDomains: []string{"contoso.example"}}, opts: Options{IdP: Google}, id: idp.Identity{Claims: map[string]any{"hd": "evil.example"}}, deny: RuleHostedDomain},
		"generic group by name":              {rules: Rules{Groups: []string{"mcp-users"}}, opts: Options{IdP: Generic}, id: idp.Identity{Groups: []string{"mcp-users"}}},
		"generic group name exact":           {rules: Rules{Groups: []string{"mcp-users"}}, opts: Options{IdP: Generic}, id: idp.Identity{Groups: []string{"MCP-users"}}, deny: RuleGroup},
	} {
		t.Run(name, func(t *testing.T) {
			checkDecision(t, mustGate(t, tc.rules, tc.opts).Allow(context.Background(), tc.id), tc.deny)
		})
	}
}

func TestDenialNeverRevealsTheIdentity(t *testing.T) {
	g := mustGate(t, Rules{EmailDomains: []string{"contoso.example"}}, Options{IdP: Generic})
	err := g.Allow(context.Background(), idp.Identity{Email: "secret.person@evil.example", EmailVerified: true})
	if err == nil || strings.Contains(err.Error(), "secret.person") || strings.Contains(err.Error(), "evil") {
		t.Fatalf("err = %v", err)
	}
}

func TestInvalidGateIsRefusedWithTheReason(t *testing.T) {
	for name, tc := range map[string]struct {
		rules Rules
		opts  Options
		want  string
	}{
		"tenant not a GUID":            {Rules{Tenants: []string{"contoso"}}, entraOpts(), "not a GUID"},
		"entra group not a GUID":       {Rules{Groups: []string{"mcp-users"}}, entraOpts(), "not a GUID"},
		"group with a non-hex letter":  {Rules{Groups: []string{"gggggggg-3333-4333-8333-333333333333"}}, entraOpts(), "not a GUID"},
		"tenant with a dash missing":   {Rules{Tenants: []string{"aaaaaaaa11111-4111-8111-111111111111"}}, entraOpts(), "not a GUID"},
		"entra email domains":          {Rules{EmailDomains: []string{"contoso.example"}}, entraOpts(), "not with Entra"},
		"entra hosted domains":         {Rules{HostedDomains: []string{"contoso.example"}}, entraOpts(), "only with Google"},
		"configured tenant excluded":   {Rules{Tenants: []string{other}}, entraOpts(), "nobody could sign in"},
		"tenants without entra":        {Rules{Tenants: []string{tenant}}, Options{IdP: Generic}, "only with Entra"},
		"multi-tenant without tenants": {Rules{Roles: []string{"R"}}, Options{IdP: Entra, Tenant: "organizations"}, "required with a multi-tenant"},
		"hd for generic":               {Rules{HostedDomains: []string{"contoso.example"}}, Options{IdP: Generic}, "only with Google"},
		"domain with @":                {Rules{EmailDomains: []string{"@contoso.example"}}, Options{IdP: Generic}, "not a domain"},
		"wildcard domain":              {Rules{EmailDomains: []string{"*.contoso.example"}}, Options{IdP: Generic}, "not a domain"},
		"leading hyphen":               {Rules{EmailDomains: []string{"-contoso.example"}}, Options{IdP: Generic}, "not a domain"},
		"empty label":                  {Rules{EmailDomains: []string{"a..example"}}, Options{IdP: Generic}, "not a domain"},
		"trailing dot":                 {Rules{EmailDomains: []string{"contoso.example."}}, Options{IdP: Generic}, "not a domain"},
		"trailing hyphen label":        {Rules{EmailDomains: []string{"contoso-.example"}}, Options{IdP: Generic}, "not a domain"},
		"domain over 253":              {Rules{EmailDomains: []string{strings.Repeat(strings.Repeat("a", 63)+".", 4) + "example"}}, Options{IdP: Generic}, "not a domain"},
		"role over 256":                {Rules{Roles: []string{strings.Repeat("a", 257)}}, entraOpts(), "not a valid name"},
		"label over 63":                {Rules{EmailDomains: []string{strings.Repeat("a", 64) + ".example"}}, Options{IdP: Generic}, "not a domain"},
		"google wildcard hd":           {Rules{HostedDomains: []string{"*.contoso.example"}}, Options{IdP: Google}, "not a domain"},
		"bare TLD":                     {Rules{EmailDomains: []string{"example"}}, Options{IdP: Generic}, "not a domain"},
		"empty role":                   {Rules{Roles: []string{""}}, entraOpts(), "not a valid name"},
		"control char role":            {Rules{Roles: []string{"a\nb"}}, entraOpts(), "not a valid name"},
		"unknown IdP":                  {Rules{Roles: []string{"r"}}, Options{IdP: "okta"}, "unknown IdP"},
		"empty multi-tenant":           {Rules{}, Options{IdP: Entra, Tenant: "organizations"}, "required with a multi-tenant"},
		"empty google":                 {Rules{}, Options{IdP: Google}, FieldAllowEmpty + ": the gate is empty"},
		"empty generic":                {Rules{}, Options{IdP: Generic}, FieldAllowEmpty + ": the gate is empty"},
	} {
		t.Run(name, func(t *testing.T) {
			_, _, err := New(tc.rules, tc.opts)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want %q", err, tc.want)
			}
		})
	}
}

func TestOnlyAnEmptyGateWarnsWhoCanSignIn(t *testing.T) {
	for name, tc := range map[string]struct {
		rules Rules
		opts  Options
		want  string // "" = no warning
	}{
		"single-tenant Entra":            {opts: entraOpts(), want: "all users of tenant " + tenant + " can sign in, guests too"},
		"google with allow-empty":        {opts: Options{IdP: Google, AllowEmpty: true}, want: "allowed explicitly"},
		"single-tenant with allow-empty": {opts: Options{IdP: Entra, Tenant: tenant, AllowEmpty: true}, want: "all users of tenant " + tenant},
		"non-empty gate":                 {rules: Rules{Roles: []string{"R"}}, opts: entraOpts()},
	} {
		t.Run(name, func(t *testing.T) {
			_, warnings, err := New(tc.rules, tc.opts)
			if err != nil {
				t.Fatal(err)
			}
			if tc.want == "" {
				if len(warnings) != 0 {
					t.Fatalf("warnings %v", warnings)
				}
				return
			}
			if len(warnings) != 1 || !strings.Contains(warnings[0], tc.want) {
				t.Fatalf("warnings %v, want %q", warnings, tc.want)
			}
		})
	}
}

// checkDecision asserts that err allows (deny == "") or is a denial by the rule deny.
func checkDecision(t *testing.T, err error, deny string) {
	t.Helper()
	if deny == "" {
		if err != nil {
			t.Fatalf("denied: %v", err)
		}
		return
	}
	var d *Denied
	if !errors.As(err, &d) || d.Rule != deny || d.DeniedRule() != deny {
		t.Fatalf("err = %v, want denial by %s", err, deny)
	}
}

func TestInvalidRulesNameTheirList(t *testing.T) {
	_, _, err := New(Rules{Tenants: []string{"x"}, Groups: []string{"y"}, EmailDomains: []string{"contoso.example"}}, entraOpts())
	joined, ok := err.(interface{ Unwrap() []error })
	if !ok {
		t.Fatalf("err = %v, want joined field errors", err)
	}
	var fields []string
	for _, e := range joined.Unwrap() {
		var fe *FieldError
		if errors.As(e, &fe) {
			fields = append(fields, fe.Field)
		}
	}
	if strings.Join(fields, ",") != FieldTenants+","+FieldGroups+","+FieldEmailDomains {
		t.Fatalf("fields = %v (err %v)", fields, err)
	}
}
