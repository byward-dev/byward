package config

// consent reads the consent page's wording (ADR-0010 §4).
func (c *Config) consent(v *Values) []error {
	var errs []error
	var err error
	if c.OperatorName, err = parseWording(v.value("operator-name"), 80); err != nil {
		errs = append(errs, err)
	}
	if c.ScopeDescription, err = parseWording(v.value("scope-description"), 200); err != nil {
		errs = append(errs, err)
	}
	return errs
}
