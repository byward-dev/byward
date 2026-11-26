package config

import "strings"

// appTokens reads the app-only path (ADR-0022): off by default, Entra only, and never without an
// app role to require (§4).
func (c *Config) appTokens(v *Values) []error {
	named := v.NameAsGiven
	var err error
	if c.AppTokens, err = parseWord(v.value("app-tokens"), "off", "entra"); err != nil {
		return []error{err}
	}
	switch c.AppTokens {
	case "off":
		var set []string
		for _, n := range v.familyOf("app-tokens") { // EnabledBy "app-tokens": a new one is refused with no edit (#658)
			if v.isSet(n) {
				set = append(set, named(n))
			}
		}
		if len(set) > 0 {
			return []error{errorf("%s set while %s=off: they configure app-only callers; set %s=entra, or remove them", strings.Join(set, ", "), named("app-tokens"), named("app-tokens"))}
		}
		return nil
	case "entra":
	}
	var errs []error
	if c.IdP != "" && c.IdP != "entra" { // a refused IdP has its own error
		errs = append(errs, errorf("%s=entra cannot be used with %s=%s: app-only tokens are Entra's (ADR-0022 §1); remove it, or set %s=entra", named("app-tokens"), named("idp"), c.IdP, named("idp")))
	}
	var listErrs []error
	if c.AppRoles, listErrs = parseChecked(v.value("app-roles"), appRoleValues); len(listErrs) > 0 {
		errs = append(errs, listErrs...)
	} else if len(c.AppRoles) == 0 {
		errs = append(errs, errorf("%s is required with %s=entra: at least one app role, or every service principal in the tenant could call (ADR-0022 §4)", named("app-roles"), named("app-tokens")))
	}
	c.AppClientIDs, listErrs = parseChecked(v.value("app-client-ids"), guidsOf("application (client) IDs"))
	errs = append(errs, listErrs...)
	return errs
}
