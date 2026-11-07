package gate

import (
	"errors"
	"strings"

	"github.com/byward-dev/byward/internal/idp"
)

// AppRules are the operator's allowlists for app-only callers (ADR-0022 §4). Roles is required: an
// app-only token says only that a service principal of the tenant got it, so tid and oid alone
// would admit every service principal there.
type AppRules struct {
	// Roles are app roles on our app; the caller needs at least one.
	Roles []string
	// ClientIDs, when set, are the callers' application (client) IDs allowed (azp).
	ClientIDs []string
	// Tenants, when set, are the tenants allowed, as for users.
	Tenants []string
}

// RuleClient is an app-only caller whose client ID is not in the allowlist.
const RuleClient = "client"

// Fields naming the app rule lists in configuration errors.
const (
	FieldAppRoles     = "app roles"
	FieldAppClientIDs = "app client IDs"
)

// AppGate admits app-only callers. Unlike the user gate it runs on every MCP request, since an
// app-only caller has no grant to check it once for.
type AppGate struct {
	roles, clients, tenants map[string]bool
}

// NewApp validates r; an empty role list is an error, so the proxy does not start.
func NewApp(r AppRules) (*AppGate, error) {
	g := &AppGate{}
	var errs []error
	var err error
	if len(r.Roles) == 0 {
		errs = append(errs, fieldErr(FieldAppRoles, "at least one is required for app-only callers, or every service principal in the tenant could call (ADR-0022 §4)"))
	} else if g.roles, err = names(FieldAppRoles, r.Roles); err != nil {
		errs = append(errs, err)
	}
	if g.clients, err = guids(FieldAppClientIDs, r.ClientIDs); err != nil {
		errs = append(errs, err)
	}
	if g.tenants, err = guids(FieldTenants, r.Tenants); err != nil {
		errs = append(errs, err)
	}
	if len(errs) > 0 {
		return nil, errors.Join(errs...)
	}
	return g, nil
}

// Allow checks one app-only caller. A refusal is a *Denied naming the rule only.
func (g *AppGate) Allow(a idp.App) error {
	if len(g.tenants) > 0 && !g.tenants[strings.ToLower(a.Tenant)] {
		return &Denied{Rule: RuleTenant}
	}
	if len(g.clients) > 0 && !g.clients[strings.ToLower(a.ClientID)] {
		return &Denied{Rule: RuleClient}
	}
	if !anyIn(g.roles, a.Roles) {
		return &Denied{Rule: RuleRole}
	}
	return nil
}
