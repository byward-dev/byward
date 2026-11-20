package config

import "time"

// maxRefreshGrace is the upper bound of ADR-0006 §4 (range 0–60 s).
const maxRefreshGrace = 60 * time.Second

// refreshGrace parses the refresh-token grace window (ADR-0006 §4: 0 to 60 s).
func (c *Config) refreshGrace(v *Values) []error {
	grace, err := parseDuration(v.value("refresh-grace"), "a duration from 0s to 60s, such as 30s",
		func(d time.Duration) bool { return d >= 0 && d <= maxRefreshGrace })
	if err != nil {
		return []error{err}
	}
	c.RefreshGrace = grace
	return nil
}
