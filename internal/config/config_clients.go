package config

import (
	"net/url"
	"strconv"
	"strings"

	"github.com/byward-dev/byward/internal/logging"
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
				// A CIMD client ID, which registration.NewDenylist checks in full. Config refuses here,
				// before the startup log lists the settings, only the forms that can carry a credential:
				// a user name or password, a query or fragment, or no URL at all with an @ in it
				// (security invariant 2). The rest stays registration's rule.
				switch u, err := url.Parse(e); {
				case err == nil && u.User != nil:
					errs = append(errs, errorf("%s: %s is not a CIMD client ID: it has a user name or password", env, logging.Quote(e)))
				case strings.ContainsAny(e, "?#"):
					errs = append(errs, errorf("%s: %s is not a CIMD client ID: it has a query or a fragment", env, logging.Quote(e)))
				case err != nil && strings.Contains(e, "@"):
					errs = append(errs, errorf("%s: %s is not a CIMD client ID: it is not an absolute URL", env, logging.Quote(e)))
				}
				continue
			}
			// A trailing dot names the same host; registration.BrowserHost folds it away.
			host := strings.TrimSuffix(e, ".")
			// A refused entry is quoted as logging.Quote does; one that is a URL in all but its scheme's
			// case (HTTPS://…) as MarkedURL shows it, so the message marks with ;… ?… #… what it leaves out.
			shown := logging.Quote(e)
			if strings.Contains(e, "://") {
				if shown = logging.MarkedURL(e); shown != logging.Hidden {
					shown = strconv.Quote(shown)
				}
			}
			if err := asciiHost(e); err != nil && strings.Contains(e, "://") {
				// asciiHost's message, with the entry shown as MarkedURL shows it (#458).
				errs = append(errs, errorf("%s: %s has a host that is not ASCII; give its ASCII (xn--) form, which is what browsers and MCP clients send", env, shown))
			} else if err != nil {
				errs = append(errs, errorf("%s: %v", env, err))
			} else if reason := hostNameReason(host); reason != "" {
				errs = append(errs, errorf("%s: %s is neither a CIMD client ID (an https URL) nor a host name such as app.example: %s", env, shown, reason))
			} else if endsInANumber(host) {
				errs = append(errs, errorf("%s: %s ends in a number, so a browser reads it as an IPv4 address: one it also reaches by other spellings (127.1, 0x7f000001) that no entry can match (127.1 and 0x7f000001 are 127.0.0.1), or none at all; deny the app by its CIMD client ID or its redirect host's name", env, shown))
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
				errs = append(errs, errorf("%s: %s is not a host name such as claude.ai: %s", env, logging.Quote(h), reason))
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
