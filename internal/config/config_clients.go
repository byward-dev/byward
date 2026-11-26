package config

import (
	"net/url"
	"strings"

	"github.com/byward-dev/byward/internal/host"
)

// clientSources reads the client sources besides the static file: Dynamic Client Registration with
// its denylist (ADR-0008 §2-3, §9), and Client ID Metadata Documents with their host lists (§4, §8).
func (c *Config) clientSources(v *Values) []error {
	var errs []error
	var err error
	if c.DCR, err = v.boolean("dcr"); err != nil {
		errs = append(errs, err)
	}
	var denyErrs []error
	c.ClientDenylist, denyErrs = parseClientDenylist(v.value("client-denylist"))
	errs = append(errs, denyErrs...)
	if c.CIMD, err = v.boolean("cimd"); err != nil {
		errs = append(errs, err)
	}
	for _, s := range []struct {
		name string
		dst  *[]string
	}{{"cimd-trusted-hosts", &c.CIMDTrustedHosts}, {"cimd-allowed-hosts", &c.CIMDAllowedHosts}} {
		var hostErrs []error
		*s.dst, hostErrs = parseCIMDHosts(v.value(s.name))
		errs = append(errs, hostErrs...)
		if len(*s.dst) > 0 && !c.CIMD {
			errs = append(errs, errorf("%s has no effect while %s is false; remove one of them", v.NameAsGiven(s.name), v.NameAsGiven("cimd")))
		}
	}
	return errs
}

// wantDenylistEntry is what a BYWARD_CLIENT_DENYLIST entry must be, for its refusals.
const wantDenylistEntry = "a CIMD client ID (an https URL) or a host name such as app.example"

// parseClientDenylist reads BYWARD_CLIENT_DENYLIST: CIMD client IDs (https URLs) and host names. A
// refused entry is never shown (ADR-0031 §1).
func parseClientDenylist(val Value) ([]string, []error) {
	list, at, err := parseEntries(val)
	if err != nil {
		return nil, []error{err}
	}
	var errs []error
	for i, e := range list {
		if reason := denylistReason(e); reason != "" {
			errs = append(errs, refusedForm(val, at(i), e, wantDenylistEntry, "it "+reason))
		}
	}
	return list, errs
}

// RefusedDenylistEntry is the refusal of entry i of BYWARD_CLIENT_DENYLIST, which client
// registration refused at wiring for reason, a fixed clause (registration.EntryError): by its place and
// length, never shown (ADR-0031 §1), in the format of every refusal config makes. i is an index into
// c.ClientDenylist, the list registration was given.
func (c *Config) RefusedDenylistEntry(i int, reason string) error {
	return refusedForm(c.Values.valueOf("client-denylist"), entry{i, len(c.ClientDenylist)}, c.ClientDenylist[i], wantDenylistEntry, reason)
}

// denylistReason says why config refuses e as a client denylist entry, completing "it …", or "" when
// it does not.
func denylistReason(e string) string {
	if strings.HasPrefix(e, "https://") {
		// A CIMD client ID, which registration.NewDenylist checks in full. Config refuses here,
		// before the startup log lists the settings, only the forms that can carry a credential:
		// a user name or password, a query or fragment, or no URL at all with an @ in it
		// (security invariant 2). The rest stays registration's rule.
		switch u, err := url.Parse(e); {
		case err == nil && u.User != nil:
			return "is a CIMD client ID with a user name or password"
		case strings.ContainsAny(e, "?#"):
			return "is a CIMD client ID with a query or a fragment"
		case err != nil && strings.Contains(e, "@"):
			return "is not an absolute URL"
		}
		return ""
	}
	// A trailing dot names the same host; host.BrowserName folds it away.
	name := strings.TrimSuffix(e, ".")
	if reason := hostNameReason(name); reason != "" { // neither a CIMD client ID nor a host name
		return reason
	}
	if host.EndsInANumber(name) {
		return "ends in a number, so a browser reads it as an IPv4 address: one it also reaches by other spellings (127.1, 0x7f000001) that no entry can match (127.1 and 0x7f000001 are 127.0.0.1), or none at all; deny the app by its CIMD client ID or its redirect host's name"
	}
	return ""
}

// parseCIMDHosts reads a CIMD host list (cimd-trusted-hosts, cimd-allowed-hosts): host names, in
// lower case. A refused entry is never shown (ADR-0031 §1).
func parseCIMDHosts(val Value) ([]string, []error) {
	list, at, err := parseEntries(val)
	if err != nil {
		return nil, []error{err}
	}
	var errs []error
	for i, h := range list {
		if reason := hostNameReason(h); reason != "" {
			errs = append(errs, refusedForm(val, at(i), h, "a host name such as claude.ai", "it "+reason))
		}
		list[i] = strings.ToLower(h)
	}
	return list, errs
}

// hostNameReason says why h is not a host name an operator's host list can match on (#344), or ""
// when it is: ASCII (an internationalized name in its xn-- form), validHostName's characters and
// labels, and at least one dot, since a single label is not a host any client uses. It completes
// "it …".
func hostNameReason(h string) string {
	switch {
	case notASCII(h):
		return reasonNotASCII
	case !validHostName(h):
		return "breaks the host name rule: " + hostNameRule
	case !strings.Contains(h, "."):
		return "has no dot; give a name with at least one dot"
	}
	return ""
}
