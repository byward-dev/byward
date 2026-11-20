package config

import (
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
// origins, use it. The reason completes "its host …"; it names the address a browser rewrites the
// host to, as the parser read it, never the host as given.
func browserIPv4(h string) string {
	if !host.EndsInANumber(h) {
		return ""
	}
	if _, err := netip.ParseAddr(h); err == nil {
		return "" // dotted decimal (netip refuses leading zeros, which browsers read as octal), or IPv6
	}
	a, ok := host.ParseIPv4(h)
	if !ok {
		return "is not an IPv4 address but ends in a number, so browsers refuse it"
	}
	return "is not an IPv4 address in dotted decimal, the only form browsers send; write it as " + a.String()
}

// browserOrigin is u's origin as browsers serialize it (RFC 6454 §6.2): scheme://host[:port], the
// host as browserHost writes it, and no port when it is the scheme's default.
func browserOrigin(u *url.URL) string {
	hp := host.Serialize(u.Hostname())
	defaultPort := map[string]string{"http": "80", "https": "443"}[u.Scheme]
	if p := u.Port(); p != "" && p != defaultPort {
		hp += ":" + p
	}
	return u.Scheme + "://" + hp
}
