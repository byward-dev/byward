package config

import (
	"fmt"
	"net/netip"
	"net/url"

	"github.com/byward-dev/byward/internal/host"
)

// Hosts as browsers write them (WHATWG URL host parser and serializer), for the public listener's
// Host check and the settings that must match what a browser sends.

// browserIPv4 says why a browser would not send host as written, when it reads host as an IPv4
// address (host.EndsInANumber) that is not one in dotted decimal: the browser rewrites it (127.1 and
// 0x7f.0.0.1 are 127.0.0.1, 010.0.0.1 is 8.0.0.1, octal) or refuses the URL (mcp.10, 10.0.0.999). It
// is "" for any other host. Settings a browser must send back exactly, the public URL and allowed
// origins, use it. The reason completes "its host …"; it names the address a browser reads the host
// as, as the parser read it, never the host as given, and not as a form to write: an operator who
// wrote 010.0.0.1 for 10.0.0.1 would be misled by "write it as 8.0.0.1" (#480).
func browserIPv4(h string) string {
	if !host.EndsInANumber(h) {
		return ""
	}
	if _, err := netip.ParseAddr(h); err == nil {
		return "" // dotted decimal (netip refuses leading zeros, which browsers read as octal), or IPv6
	}
	a, ok := host.ParseIPv4(h)
	if !ok {
		return host.ErrEndsInANumber.Error()
	}
	reason := "is not an IPv4 address in dotted decimal, the only form browsers send; browsers read it as " + a.String()
	if host.ReadsOctal(h) {
		reason += ", reading a part with a leading 0 as octal"
	}
	return reason
}

// nameCharReason says why name, a host, is refused for a character no host name holds (ADR-0032 §3:
// only ASCII letters, digits, "-", "." and "_"; an internationalized name in its xn-- form), completing
// "its host …"; "" when it holds none, or is an IP address (host.BadNameChar), whose IPv6 zone may hold
// any character. It names the character's place, or says the name is not ASCII; never the character
// or the host, which a secret may be.
func nameCharReason(name string) string {
	place := host.BadNameChar(name)
	switch {
	case place == 0:
		return ""
	case notASCII(name): // a name that is not ASCII is told its xn-- form, wherever its first bad character is
		return reasonNotASCII
	}
	return fmt.Sprintf("has a character no host name holds at position %d; a host name has only letters, digits, - . and _", place)
}

// browserOrigin is u's origin as browsers serialize it (RFC 6454 §6.2): host.Origin, the form the
// Origin check compares.
func browserOrigin(u *url.URL) string { return host.Origin(u.Scheme, u.Host) }

// ListWarning is a warning about entries of a list setting, named by their places in the list,
// never their values (ADR-0031 §1): its Setting is named as the operator gave it.
type ListWarning struct{ Setting, Message, Fix string }

// browserListWarnings are the R7 warnings of the browser-matched lists (ADR-0032 §2, class B): their
// entries keyed as the Host and Origin checks compare them.
func (c *Config) browserListWarnings() []ListWarning {
	const folds = "case, an IP address's spelling, a default port"
	hostKeys := make([]string, len(c.AllowedHosts))
	for i, h := range c.AllowedHosts {
		hostKeys[i] = host.MatchKey(h)
	}
	return append(c.foldedDuplicates("allowed-hosts", "host", folds, hostKeys, host.MatchKey(c.PublicURL.Host)),
		c.foldedDuplicates("allowed-origins", "origin", folds, c.AllowedOrigins, c.Origin())...)
}

// foldedDuplicates are the warnings for the list setting name, whose entries are keyed as keys: each
// later entry with an earlier one's key, and each entry whose key is self, the key of an entry always
// allowed anyway (the public URL's own). what names the kind of entry ("host", "origin") and folds
// what the keys fold, in the message.
func (c *Config) foldedDuplicates(name, what, folds string, keys []string, self string) []ListWarning {
	var out []ListWarning
	setting, of := c.Values.NameAsGiven(name), len(keys)
	first := map[string]int{}
	for i, k := range keys {
		switch j, seen := first[k]; {
		case k == self:
			out = append(out, ListWarning{setting, fmt.Sprintf("%s is the public URL's %s, which is always allowed", entry{i, of}, what), "remove it"})
		case seen:
			out = append(out, ListWarning{setting, fmt.Sprintf("%s name the same %s once folded (%s)", entry{j, of}.and(entry{i, of}), what, folds), "remove one of them"})
		default:
			first[k] = i
		}
	}
	return out
}
