package config

import "time"

// maxRefreshGrace is the upper bound of ADR-0006 §4 (range 0–60 s).
const maxRefreshGrace = 60 * time.Second

// refreshGrace parses the refresh-token grace window (ADR-0006 §4: 0 to 60 s).
func (c *Config) refreshGrace(v *Values) []error {
	grace, err := time.ParseDuration(v.get("refresh-grace"))
	switch {
	case err != nil:
		return []error{errorf("BYWARD_REFRESH_GRACE: want a duration such as 30s, got %q", v.get("refresh-grace"))}
	case grace < 0 || grace > maxRefreshGrace:
		return []error{errorf("BYWARD_REFRESH_GRACE: want 0s to 60s, got %s", grace)}
	}
	c.RefreshGrace = grace
	return nil
}
