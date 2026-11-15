package config

import (
	"strings"
)

// clientSources reads the client sources besides the static file: Dynamic Client Registration with
// its denylist (ADR-0008 §2-3, §9), and Client ID Metadata Documents with their host lists (§4, §8).
func (c *Config) clientSources(v *Values) []error {
	var errs []error
	var err error
	if c.DCR, err = v.boolean("dcr"); err != nil {
		errs = append(errs, err)
	}
	if raw := v.get("client-denylist"); raw != "" {
		env := Setting{Name: "client-denylist"}.Env()
		if c.ClientDenylist = splitList(raw); len(c.ClientDenylist) == 0 {
			errs = append(errs, errorf("%s is set but lists nothing; remove it or give at least one entry", env))
		}
		for _, e := range c.ClientDenylist {
			if strings.HasPrefix(e, "https://") {
				continue // a CIMD client ID, which registration.NewDenylist checks
			}
			// A trailing dot names the same host; the denylist folds it away (ADR-0008 §9).
			if err := asciiHost(e); err != nil {
				errs = append(errs, errorf("%s: %v", env, err))
			} else if reason := hostNameReason(strings.TrimSuffix(e, ".")); reason != "" {
				errs = append(errs, errorf("%s: %q is neither a CIMD client ID (an https URL) nor a host name such as app.example: %s", env, e, reason))
			}
		}
	}
	if c.CIMD, err = v.boolean("cimd"); err != nil {
		errs = append(errs, err)
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
			} else if reason := hostNameReason(h); reason != "" {
				errs = append(errs, errorf("%s: %q is not a host name such as claude.ai: %s", env, h, reason))
			}
			(*s.dst)[i] = strings.ToLower(h)
		}
	}
	return errs
}

// hostNameReason says why h is not a host name an operator's host list can match on (#344), or ""
// when it is: validHostName's characters and labels, and at least one dot, since a single label is
// not a host any client uses. The caller checks asciiHost first, for its own message.
func hostNameReason(h string) string {
	switch {
	case !validHostName(h):
		return hostNameRule
	case !strings.Contains(h, "."):
		return "give a name with at least one dot"
	}
	return ""
}
