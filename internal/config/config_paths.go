package config

import (
	"path/filepath"
	"strings"
)

// absolute refuses a path setting that is relative to the working directory (ADR-0007 §6): every
// path setting goes through it.
func absolute(setting, path string) error {
	if filepath.IsAbs(path) {
		return nil
	}
	// The path is not shown: a secret pasted where its file's path belongs would be (#461).
	return refusedMeaning(lookup(setting), whole, "a relative one", "an absolute path", "no path is relative to the working directory (ADR-0007 §6)")
}

// within reports whether path is dir or inside it.
func within(dir, path string) bool {
	rel, err := filepath.Rel(dir, path)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

// paths resolves the data directory and the paths that default into it: keys, static clients,
// assertion keys, the store and its restore counter (ADR-0007 §6, §9). No path is relative to the working directory.
func (c *Config) paths(v *Values) []error {
	var errs []error
	c.DataDir = parseText(v.value("data-dir"))
	if err := absolute("data-dir", c.DataDir); err != nil {
		return []error{err} // every default below is derived from it
	}
	or := func(name, def string) string {
		if p := parseText(v.value(name)); p != "" {
			return p
		}
		return filepath.Join(c.DataDir, def)
	}
	c.KeysDir, c.StaticClientsFile, c.StoreDir = or("keys-dir", "keys"), or("static-clients-file", "clients.json"), or("store-dir", "state")
	c.StaticClientsFileNamed = !v.empty("static-clients-file")
	c.AssertionKeysDir = or("assertion-keys-dir", "assertion-keys")
	for _, p := range []struct{ setting, path string }{{"keys-dir", c.KeysDir}, {"static-clients-file", c.StaticClientsFile},
		{"assertion-keys-dir", c.AssertionKeysDir}, {"store-dir", c.StoreDir}} {
		if err := absolute(p.setting, p.path); err != nil {
			errs = append(errs, err)
		}
	}
	c.StoreCounterFile = parseText(v.value("store-counter-file"))
	if c.StoreCounterFile == "" {
		// Next to the keys: outside the state directory, so a restored backup of it is detected.
		c.StoreCounterFile = filepath.Join(filepath.Dir(filepath.Clean(c.KeysDir)), "store-writes")
	}
	switch err := absolute("store-counter-file", c.StoreCounterFile); {
	case err != nil:
		if v.empty("store-counter-file") {
			break // derived from the keys directory, refused above as relative
		}
		errs = append(errs, err)
	case filepath.IsAbs(c.StoreDir) && within(c.StoreDir, c.StoreCounterFile):
		errs = append(errs, refusedMeaning(lookup("store-counter-file"), whole, "one inside it", "a path outside BYWARD_STORE_DIR",
			"a restored backup of the state directory would restore it too and go undetected; keep the keys directory outside the state directory, or set this to a path outside it"))
	}
	return errs
}
