package config

import (
	"path/filepath"
	"strings"
	"time"
)

// within reports whether path is dir or inside it.
func within(dir, path string) bool {
	rel, err := filepath.Rel(dir, path)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

// maxRefreshGrace is the upper bound of ADR-0006 §4 (range 0–60 s).
const maxRefreshGrace = 60 * time.Second

// paths resolves the data directory and the paths that default into it: keys, static clients,
// the store and its restore counter (ADR-0007 §6, §9). No path is relative to the working directory.
func (c *Config) paths(v *Values) []error {
	var errs []error
	c.DataDir = v.get("data-dir")
	if !filepath.IsAbs(c.DataDir) {
		return []error{errorf("BYWARD_DATA_DIR: want an absolute path (no paths relative to the working directory, ADR-0007 §6), got %q", c.DataDir)}
	}
	or := func(name, def string) string {
		if p := v.get(name); p != "" {
			return p
		}
		return filepath.Join(c.DataDir, def)
	}
	c.KeysDir, c.StaticClientsFile, c.StoreDir = or("keys-dir", "keys"), or("static-clients-file", "clients.json"), or("store-dir", "state")
	c.StaticClientsFileNamed = v.get("static-clients-file") != ""
	c.AssertionKeysDir = or("assertion-keys-dir", "assertion-keys")
	if !filepath.IsAbs(c.AssertionKeysDir) {
		errs = append(errs, errorf("BYWARD_ASSERTION_KEYS_DIR: want an absolute path, got %q", c.AssertionKeysDir))
	}
	if !filepath.IsAbs(c.StoreDir) {
		errs = append(errs, errorf("BYWARD_STORE_DIR: want an absolute path (no paths relative to the working directory, ADR-0007 §6), got %q", c.StoreDir))
	}
	c.StoreCounterFile = v.get("store-counter-file")
	if c.StoreCounterFile == "" {
		// Next to the keys: outside the state directory, so a restored backup of it is detected.
		c.StoreCounterFile = filepath.Join(filepath.Dir(filepath.Clean(c.KeysDir)), "store-writes")
	}
	switch {
	case !filepath.IsAbs(c.StoreCounterFile):
		errs = append(errs, errorf("BYWARD_STORE_COUNTER_FILE: want an absolute path, got %q (the default is derived from BYWARD_KEYS_DIR, so set an absolute keys directory or this setting)", c.StoreCounterFile))
	case filepath.IsAbs(c.StoreDir) && within(c.StoreDir, c.StoreCounterFile):
		errs = append(errs, errorf("BYWARD_STORE_COUNTER_FILE: %s is inside BYWARD_STORE_DIR %s, so a restored backup of the state directory would restore it too and go undetected; keep the keys directory outside the state directory, or set this to a path outside it", c.StoreCounterFile, c.StoreDir))
	}
	return errs
}

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
