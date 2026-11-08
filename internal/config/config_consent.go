package config

// consent reads the consent page's wording (ADR-0010 §4).
func (c *Config) consent(v *Values) []error {
	c.OperatorName, c.ScopeDescription = v.get("operator-name"), v.get("scope-description")
	return append(checkText("operator-name", c.OperatorName, 80), checkText("scope-description", c.ScopeDescription, 200)...)
}
