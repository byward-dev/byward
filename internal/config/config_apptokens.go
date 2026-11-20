package config

import "strings"

// appTokens reads the app-only path (ADR-0022): off by default, Entra only, and never without an
// app role to require (§4).
func (c *Config) appTokens(v *Values) []error {
	env := func(n string) string { return Setting{Name: n}.Env() }
	var err error
	if c.AppTokens, err = parseWord(v.value("app-tokens"), "off", "entra"); err != nil {
		return []error{err}
	}
	switch c.AppTokens {
	case "off":
		var set []string
		for _, n := range []string{"app-roles", "app-client-ids"} {
			if v.byKey[n].Source != SourceDefault {
				set = append(set, env(n))
			}
		}
		if len(set) > 0 {
			return []error{errorf("%s set while %s=off: they configure app-only callers; set %s=entra, or remove them", strings.Join(set, ", "), env("app-tokens"), env("app-tokens"))}
		}
		return nil
	}
	var errs []error
	if c.IdP != "entra" {
		errs = append(errs, errorf("%s=entra cannot be used with %s=%s: app-only tokens are Entra's (ADR-0022 §1); remove it, or set %s=entra", env("app-tokens"), env("idp"), c.IdP, env("idp")))
	}
	if c.AppRoles, err = parseList(v.value("app-roles")); err != nil {
		errs = append(errs, err)
	} else if len(c.AppRoles) == 0 {
		errs = append(errs, errorf("%s is required with %s=entra: at least one app role, or every service principal in the tenant could call (ADR-0022 §4)", env("app-roles"), env("app-tokens")))
	}
	if c.AppClientIDs, err = parseList(v.value("app-client-ids")); err != nil {
		errs = append(errs, err)
	}
	return errs
}
