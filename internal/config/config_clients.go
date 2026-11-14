package config

import (
	"strconv"
	"strings"
)

// clientSources reads the client sources besides the static file: Dynamic Client Registration with
// its denylist (ADR-0008 §2-3, §9), and Client ID Metadata Documents with their host lists (§4, §8).
func (c *Config) clientSources(v *Values) []error {
	var errs []error
	var err error
	if c.DCR, err = strconv.ParseBool(v.get("dcr")); err != nil {
		errs = append(errs, errorf("%s: want true or false, got %q", Setting{Name: "dcr"}.Env(), v.get("dcr")))
	}
	if raw := v.get("client-denylist"); raw != "" {
		if c.ClientDenylist = splitList(raw); len(c.ClientDenylist) == 0 {
			errs = append(errs, errorf("%s is set but lists nothing; remove it or give at least one entry", Setting{Name: "client-denylist"}.Env()))
		}
	}
	if c.CIMD, err = strconv.ParseBool(v.get("cimd")); err != nil {
		errs = append(errs, errorf("%s: want true or false, got %q", Setting{Name: "cimd"}.Env(), v.get("cimd")))
	}
	for _, s := range []struct {
		name string
		dst  *[]string
	}{{"cimd-trusted-hosts", &c.CIMDTrustedHosts}, {"cimd-allowed-hosts", &c.CIMDAllowedHosts}} {
		env, raw := Setting{Name: s.name}.Env(), v.get(s.name)
		*s.dst = splitList(raw)
		switch {
		case raw != "" && len(*s.dst) == 0:
			errs = append(errs, errorf("%s is set but lists nothing; remove it or give at least one host", env))
		case raw != "" && !c.CIMD:
			errs = append(errs, errorf("%s has no effect while BYWARD_CIMD is false; remove one of them", env))
		}
		for i, h := range *s.dst {
			if err := asciiHost(h); err != nil {
				errs = append(errs, errorf("%s: %v", env, err))
			} else if !validHostName(h) { // #344
				errs = append(errs, errorf("%s: %q is not a host name such as claude.ai: %s", env, h, hostNameRule))
			} else if !strings.Contains(h, ".") {
				errs = append(errs, errorf("%s: %q is not a host name such as claude.ai: give a name with at least one dot", env, h))
			}
			(*s.dst)[i] = strings.ToLower(h)
		}
	}
	return errs
}
