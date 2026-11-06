// Package gate is the access gate (CONTEXT.md "Access gate", ADR-0015): the operator's allowlists
// for which users may use the proxy at all, checked when a grant is created and at every refresh —
// never per MCP request.
package gate

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/byward-dev/byward/internal/idp"
)

// organizations is the Entra tenant value of a multi-tenant app.
const organizations = "organizations"

// IdP kinds the gate validates its rules against.
const (
	Entra   = "entra"
	Google  = "google"
	Generic = "generic"
)

// Rules are the operator's allowlists (ADR-0015 §1). Every non-empty list must be satisfied (AND);
// within a list any one entry is enough (OR).
type Rules struct {
	// Tenants are Entra tenant IDs (`tid`).
	Tenants []string
	// Roles are app roles; the user needs at least one (`roles`).
	Roles []string
	// Groups are group IDs (Entra object IDs); opt-in, and groups overage denies (ADR-0012 §8).
	Groups []string
	// EmailDomains match the domain of a verified email (generic IdPs only, never Entra).
	EmailDomains []string
	// HostedDomains match Google's `hd` claim.
	HostedDomains []string
}

func (r Rules) empty() bool {
	return len(r.Tenants)+len(r.Roles)+len(r.Groups)+len(r.EmailDomains)+len(r.HostedDomains) == 0
}

// Options describe the IdP the gate guards.
type Options struct {
	// IdP is Entra, Google or Generic.
	IdP string
	// Tenant is the configured Entra tenant ("organizations" for multi-tenant).
	Tenant string
	// AllowEmpty accepts an empty gate where ADR-0015 §3 otherwise refuses to start.
	AllowEmpty bool
}

// Denied rules, for the audit log and metrics.
const (
	RuleTenant            = "tenant"
	RuleRole              = "role"
	RuleGroup             = "group"
	RuleGroupsUnavailable = "groups_unavailable"
	RuleEmailDomain       = "email_domain"
	RuleHostedDomain      = "hosted_domain"
)

// Fields name the rule lists in configuration errors, so callers can point at the setting.
const (
	FieldTenants       = "tenants"
	FieldRoles         = "roles"
	FieldGroups        = "groups"
	FieldEmailDomains  = "email domains"
	FieldHostedDomains = "hosted domains"
	// FieldAllowEmpty is the explicit opt-in for an empty gate (Options.AllowEmpty).
	FieldAllowEmpty = "allow empty"
)

// FieldError is an invalid rule list; Field is one of the Field* names.
type FieldError struct{ Field, Msg string }

func (e *FieldError) Error() string { return e.Field + ": " + e.Msg }

func fieldErr(field, format string, a ...any) error {
	return &FieldError{Field: field, Msg: fmt.Sprintf(format, a...)}
}

// Denied is the gate's refusal. Its message names the rule only, never the user's claims.
type Denied struct{ Rule string }

func (d *Denied) Error() string { return "access gate: denied by the " + d.Rule + " rule" }

// DeniedRule names the rule that refused the user (the broker's Denial contract).
func (d *Denied) DeniedRule() string { return d.Rule }

// Gate implements the broker's Gate interface.
type Gate struct {
	tenants, roles, groups, emailDomains, hostedDomains map[string]bool
	// groupGUIDs: Entra group IDs compare case-insensitively.
	groupGUIDs bool
}

// New validates rules for the IdP and returns the gate plus startup warnings, which the caller
// logs at every start (ADR-0015 §3). An invalid or (where refused) empty gate is an error, so the
// proxy does not start (ADR-0015 §5).
func New(r Rules, o Options) (*Gate, []string, error) {
	var errs []error
	g := &Gate{groupGUIDs: o.IdP == Entra}
	var err error
	if g.tenants, err = guids(FieldTenants, r.Tenants); err != nil {
		errs = append(errs, err)
	}
	if g.roles, err = names(FieldRoles, r.Roles); err != nil {
		errs = append(errs, err)
	}
	if o.IdP == Entra {
		g.groups, err = guids(FieldGroups, r.Groups)
	} else {
		g.groups, err = names(FieldGroups, r.Groups)
	}
	if err != nil {
		errs = append(errs, err)
	}
	if g.emailDomains, err = domains(FieldEmailDomains, r.EmailDomains); err != nil {
		errs = append(errs, err)
	}
	if g.hostedDomains, err = domains(FieldHostedDomains, r.HostedDomains); err != nil {
		errs = append(errs, err)
	}
	switch o.IdP {
	case Entra:
		if len(r.EmailDomains) > 0 {
			errs = append(errs, fieldErr(FieldEmailDomains, "not with Entra, whose email claim is not verified (ADR-0012 §3); use tenants, roles or groups"))
		}
		if len(r.HostedDomains) > 0 {
			errs = append(errs, fieldErr(FieldHostedDomains, "only with Google"))
		}
		if o.Tenant == organizations && len(r.Tenants) == 0 {
			errs = append(errs, fieldErr(FieldTenants, "required with a multi-tenant (organizations) Entra app (ADR-0012 §2)"))
		}
		if o.Tenant != organizations && len(g.tenants) > 0 && !g.tenants[strings.ToLower(o.Tenant)] {
			errs = append(errs, fieldErr(FieldTenants, "the configured tenant %s is not in the list, so nobody could sign in", o.Tenant))
		}
	case Google, Generic:
		if len(r.Tenants) > 0 {
			errs = append(errs, fieldErr(FieldTenants, "only with Entra"))
		}
		if o.IdP == Generic && len(r.HostedDomains) > 0 {
			errs = append(errs, fieldErr(FieldHostedDomains, "only with Google"))
		}
	default:
		errs = append(errs, fmt.Errorf("unknown IdP %q", o.IdP))
	}
	if len(errs) > 0 {
		return nil, nil, errors.Join(errs...)
	}

	var warnings []string
	if r.empty() {
		single := o.IdP == Entra && o.Tenant != organizations
		switch {
		case single:
			warnings = append(warnings, fmt.Sprintf("access gate is empty: all users of tenant %s can sign in, guests too unless restricted (set roles or groups, or Entra \"Assignment required\")", o.Tenant))
		case o.AllowEmpty:
			warnings = append(warnings, "access gate is empty and allowed explicitly: anyone who can sign in at the IdP can use the proxy")
		default:
			return nil, nil, fieldErr(FieldAllowEmpty, "the gate is empty for a Google or generic OIDC IdP, so anyone with an account could sign in; set an allowlist, or set this to true to allow it")
		}
	}
	return g, warnings, nil
}

// Allow checks one user (ADR-0015 §1). A refusal is a *Denied.
func (g *Gate) Allow(_ context.Context, id idp.Identity) error {
	if len(g.tenants) > 0 && !g.tenants[strings.ToLower(idp.StringClaim(id.Claims, "tid"))] {
		return &Denied{Rule: RuleTenant}
	}
	if len(g.roles) > 0 && !anyIn(g.roles, id.Roles) {
		return &Denied{Rule: RuleRole}
	}
	if len(g.groups) > 0 {
		if id.GroupsUnavailable {
			return &Denied{Rule: RuleGroupsUnavailable}
		}
		if !anyIn(g.groups, lower(id.Groups, g.groupGUIDs)) {
			return &Denied{Rule: RuleGroup}
		}
	}
	if len(g.emailDomains) > 0 {
		_, domain, ok := strings.Cut(id.Email, "@")
		if !id.EmailVerified || !ok || !g.emailDomains[strings.ToLower(domain)] {
			return &Denied{Rule: RuleEmailDomain}
		}
	}
	if len(g.hostedDomains) > 0 && !g.hostedDomains[strings.ToLower(idp.StringClaim(id.Claims, "hd"))] {
		return &Denied{Rule: RuleHostedDomain}
	}
	return nil
}

func anyIn(set map[string]bool, have []string) bool {
	return slices.ContainsFunc(have, func(s string) bool { return set[s] })
}

func lower(in []string, yes bool) []string {
	if !yes {
		return in
	}
	out := make([]string, len(in))
	for i, s := range in {
		out[i] = strings.ToLower(s)
	}
	return out
}

func guids(what string, in []string) (map[string]bool, error) {
	out := map[string]bool{}
	for _, s := range in {
		if !isGUID(s) {
			return nil, fieldErr(what, "%q is not a GUID", s)
		}
		out[strings.ToLower(s)] = true
	}
	return out, nil
}

func names(what string, in []string) (map[string]bool, error) {
	out := map[string]bool{}
	for _, s := range in {
		if s == "" || len(s) > 256 || strings.ContainsFunc(s, func(r rune) bool { return r < 0x20 || r == 0x7f }) {
			return nil, fieldErr(what, "%q is not a valid name", s)
		}
		out[s] = true
	}
	return out, nil
}

func domains(what string, in []string) (map[string]bool, error) {
	out := map[string]bool{}
	for _, s := range in {
		d := strings.ToLower(s)
		if !validDomain(d) {
			return nil, fieldErr(what, "%q is not a domain name (no @, no wildcards)", s)
		}
		out[d] = true
	}
	return out, nil
}

func validDomain(d string) bool {
	if len(d) == 0 || len(d) > 253 || !strings.Contains(d, ".") || strings.HasPrefix(d, ".") || strings.HasSuffix(d, ".") {
		return false
	}
	for _, label := range strings.Split(d, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, r := range label {
			if (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '-' {
				return false
			}
		}
	}
	return true
}

func isGUID(s string) bool {
	if len(s) != 36 {
		return false
	}
	for i, r := range s {
		switch {
		case i == 8 || i == 13 || i == 18 || i == 23:
			if r != '-' {
				return false
			}
		case !strings.ContainsRune("0123456789abcdefABCDEF", r):
			return false
		}
	}
	return true
}
