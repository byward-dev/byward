package config

// gate reads the access gate's lists (ADR-0015) and checks each entry for the IdP, so a refused
// entry is refused here, by its place and length, never shown (#495); gate.New checks them again
// when the broker is wired, as a backstop that names no entry.
func (c *Config) gate(v *Values) []error {
	entra := c.IdP == "entra"
	roles, groups := names("role names"), names("group names")
	if entra {
		roles, groups = appRoleValues, guidsOf("group object IDs")
	}
	var errs []error
	for _, l := range []struct {
		name  string
		dst   *[]string
		check entryCheck
	}{
		{"gate-tenants", &c.GateTenants, guidsOf("tenant IDs")},
		{"gate-roles", &c.GateRoles, roles},
		{"gate-groups", &c.GateGroups, groups},
		{"gate-email-domains", &c.GateEmailDomains, domainNames},
		{"gate-hosted-domains", &c.GateHostedDomains, domainNames},
	} {
		list, listErrs := parseChecked(v.value(l.name), l.check)
		*l.dst = list
		errs = append(errs, listErrs...)
	}
	var err error
	if c.GateAllowEmpty, err = v.boolean("gate-allow-empty"); err != nil {
		errs = append(errs, err)
	}
	return errs
}
