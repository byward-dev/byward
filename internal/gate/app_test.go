package gate

import (
	"errors"
	"strings"
	"testing"

	"github.com/byward-dev/byward/internal/idp"
)

const caller = "dddddddd-4444-4444-8444-444444444444"

func TestTheAppGateAdmitsOnlyCallersMeetingEveryRuleAndNamesTheFailingRule(t *testing.T) {
	app := func(mod func(*idp.App)) idp.App {
		a := idp.App{Tenant: tenant, ObjectID: other, ClientID: caller, Roles: []string{"MCP.Invoke"}}
		if mod != nil {
			mod(&a)
		}
		return a
	}
	all := AppRules{Roles: []string{"MCP.Invoke", "MCP.Admin"}, ClientIDs: []string{strings.ToUpper(caller)}, Tenants: []string{tenant}}
	for name, tc := range map[string]struct {
		rules AppRules
		app   idp.App
		rule  string // "" admits
	}{
		"every rule met":                {all, app(nil), ""},
		"GUIDs in upper case":           {all, app(func(a *idp.App) { a.ClientID, a.Tenant = strings.ToUpper(caller), strings.ToUpper(tenant) }), ""},
		"one of the roles is enough":    {all, app(func(a *idp.App) { a.Roles = []string{"Other", "MCP.Admin"} }), ""},
		"roles only":                    {AppRules{Roles: []string{"MCP.Invoke"}}, app(func(a *idp.App) { a.ClientID, a.Tenant = other, other }), ""},
		"no role at all":                {all, app(func(a *idp.App) { a.Roles = nil }), RuleRole},
		"another role":                  {all, app(func(a *idp.App) { a.Roles = []string{"Other"} }), RuleRole},
		"roles compare exactly":         {all, app(func(a *idp.App) { a.Roles = []string{"mcp.invoke"} }), RuleRole},
		"a client not in the allowlist": {all, app(func(a *idp.App) { a.ClientID = other }), RuleClient},
		"a tenant not in the allowlist": {all, app(func(a *idp.App) { a.Tenant = other }), RuleTenant},
	} {
		t.Run(name, func(t *testing.T) {
			g, err := NewApp(tc.rules)
			if err != nil {
				t.Fatal(err)
			}
			err = g.Allow(tc.app)
			var d *Denied
			switch {
			case tc.rule == "" && err != nil:
				t.Fatalf("denied: %v", err)
			case tc.rule != "" && (!errors.As(err, &d) || d.Rule != tc.rule):
				t.Fatalf("err = %v, want denied by the %s rule", err, tc.rule)
			}
		})
	}
}

// Startup refuses an app gate without roles, which would admit every service principal of the
// tenant, and malformed lists, naming each list.
func TestAnAppGateWithoutRolesOrWithBadListsRefusesToStart(t *testing.T) {
	for name, tc := range map[string]struct {
		rules AppRules
		field string
	}{
		"no roles":               {AppRules{ClientIDs: []string{caller}}, FieldAppRoles},
		"a blank role":           {AppRules{Roles: []string{""}}, FieldAppRoles},
		"a client ID not a GUID": {AppRules{Roles: []string{"r"}, ClientIDs: []string{"my-app"}}, FieldAppClientIDs},
		"a tenant not a GUID":    {AppRules{Roles: []string{"r"}, Tenants: []string{"contoso.com"}}, FieldTenants},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := NewApp(tc.rules)
			var fe *FieldError
			if !errors.As(err, &fe) || fe.Field != tc.field {
				t.Fatalf("err = %v, want a %s field error", err, tc.field)
			}
		})
	}
}
