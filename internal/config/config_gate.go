package config

// gate reads the access gate's lists (ADR-0015); gate.New validates them when the broker is wired.
func (c *Config) gate(v *Values) []error {
	var errs []error
	for _, l := range []struct {
		name string
		dst  *[]string
	}{{"gate-tenants", &c.GateTenants}, {"gate-roles", &c.GateRoles}, {"gate-groups", &c.GateGroups},
		{"gate-email-domains", &c.GateEmailDomains}, {"gate-hosted-domains", &c.GateHostedDomains}} {
		list, err := parseList(v.value(l.name))
		if err != nil {
			errs = append(errs, err)
		}
		*l.dst = list
	}
	var err error
	if c.GateAllowEmpty, err = v.boolean("gate-allow-empty"); err != nil {
		errs = append(errs, err)
	}
	return errs
}
