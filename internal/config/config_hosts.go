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
// any character. It names the character's place, never the character or the host, which a secret may
// be.
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

// browserOrigin is u's origin as browsers serialize it (RFC 6454 §6.2): scheme://host[:port], the
// host as host.Serialize writes it, and no port when it is the scheme's default.
func browserOrigin(u *url.URL) string {
	hp := host.Serialize(u.Hostname())
	if p := u.Port(); p != "" && p != host.DefaultPort(u.Scheme) {
		hp += ":" + p
	}
	return u.Scheme + "://" + hp
}
