package config

import "strconv"

// gate reads the access gate's lists (ADR-0015); gate.New validates them when the broker is wired.
func (c *Config) gate(v *Values) []error {
	var errs []error
	var err error
	c.GateTenants, c.GateRoles, c.GateGroups = splitList(v.get("gate-tenants")), splitList(v.get("gate-roles")), splitList(v.get("gate-groups"))
	c.GateEmailDomains, c.GateHostedDomains = splitList(v.get("gate-email-domains")), splitList(v.get("gate-hosted-domains"))
	// A gate list that is set but names nothing would silently open the gate.
	for _, s := range []string{"gate-tenants", "gate-roles", "gate-groups", "gate-email-domains", "gate-hosted-domains"} {
		if raw := v.get(s); raw != "" && len(splitList(raw)) == 0 {
			errs = append(errs, errorf("%s is set but lists nothing; remove it or give at least one entry", Setting{Name: s}.Env()))
		}
	}
	if c.GateAllowEmpty, err = strconv.ParseBool(v.get("gate-allow-empty")); err != nil {
		errs = append(errs, errorf("%s: want true or false, got %q", Setting{Name: "gate-allow-empty"}.Env(), v.get("gate-allow-empty")))
	}
	return errs
}
