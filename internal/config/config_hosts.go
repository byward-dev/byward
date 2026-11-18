package config

import (
	"fmt"
	"math"
	"net/netip"
	"net/url"
	"strconv"
	"strings"

	"github.com/byward-dev/byward/internal/logging"
)

// Hosts as browsers write them (WHATWG URL host parser and serializer), for the public listener's
// Host check and the settings that must match what a browser sends.

// browserIPv4 refuses a host that a browser reads as an IPv4 address (endsInANumber) but that is not
// one in dotted decimal: the browser rewrites it (127.1 and 0x7f.0.0.1 are 127.0.0.1, 010.0.0.1 is
// 8.0.0.1, octal) or refuses the URL (mcp.10, 10.0.0.999), so it never sends the host as written.
// Settings a browser must send back exactly, the public URL and allowed origins, use it.
func browserIPv4(host string) error {
	if !endsInANumber(host) {
		return nil
	}
	if _, err := netip.ParseAddr(host); err == nil {
		return nil // dotted decimal (netip refuses leading zeros, which browsers read as octal), or IPv6
	}
	if _, ok := parseIPv4(host); !ok {
		return fmt.Errorf("%s is not an IPv4 address but ends in a number, so browsers refuse it", logging.Quote(host))
	}
	return fmt.Errorf("%s is not an IPv4 address in dotted decimal, the only form browsers send", logging.Quote(host))
}

// endsInANumber reports whether a browser reads host as an IPv4 address (WHATWG URL "ends in a
// number"): its last label, after one trailing dot, is decimal digits, or a number ipv4Number
// parses (0x and hex digits). The parse may then fail (a.0x7f, 1.2.3.4.5), and the browser refuses
// the URL.
func endsInANumber(host string) bool {
	parts := strings.Split(host, ".")
	if parts[len(parts)-1] == "" {
		if len(parts) == 1 {
			return false
		}
		parts = parts[:len(parts)-1]
	}
	last := parts[len(parts)-1]
	if last != "" && strings.Trim(last, "0123456789") == "" {
		return true
	}
	_, ok := ipv4Number(last)
	return ok
}

// ipv4Number is the WHATWG URL IPv4 number parser: decimal, 0x hex, or octal with a leading 0; an
// empty number after its prefix is 0.
func ipv4Number(s string) (uint64, bool) {
	if s == "" {
		return 0, false
	}
	base := 10
	switch {
	case len(s) >= 2 && (s[:2] == "0x" || s[:2] == "0X"):
		s, base = s[2:], 16
	case len(s) >= 2 && s[0] == '0':
		s, base = s[1:], 8
	}
	if s == "" {
		return 0, true
	}
	digits := "0123456789abcdefABCDEF"[:base]
	if base == 16 {
		digits = "0123456789abcdefABCDEF"
	}
	if strings.Trim(s, digits) != "" {
		return 0, false
	}
	n, err := strconv.ParseUint(s, base, 64)
	if err != nil { // only too large: the parser takes any length, and such a number fails parseIPv4
		return math.MaxUint64, true
	}
	return n, true
}

// parseIPv4 is the WHATWG URL IPv4 parser, for a host that endsInANumber: one to four numbers,
// every one but the last at most 255, the last filling the bytes left (127.1 is 127.0.0.1).
func parseIPv4(host string) (netip.Addr, bool) {
	parts := strings.Split(host, ".")
	if parts[len(parts)-1] == "" && len(parts) > 1 {
		parts = parts[:len(parts)-1]
	}
	if len(parts) > 4 {
		return netip.Addr{}, false
	}
	var v uint64
	for i, p := range parts {
		n, ok := ipv4Number(p)
		if !ok {
			return netip.Addr{}, false
		}
		if i < len(parts)-1 {
			if n > 255 {
				return netip.Addr{}, false
			}
			v |= n << (8 * (3 - i))
			continue
		}
		if n >= 1<<(8*(5-len(parts))) {
			return netip.Addr{}, false
		}
		v |= n
	}
	return netip.AddrFrom4([4]byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)}), true
}

// browserHost is a host name (no port, no brackets) as browsers serialize it (WHATWG URL host
// serializer): in lower case; an IPv4 address in dotted decimal, whatever spelling the parser took
// (127.1, 0x7f.0.0.1, 2130706433); an IPv6 address in brackets, in its shortest form and all hex
// (::ffff:7f00:1, where netip writes ::ffff:127.0.0.1). Anything else, including a zoned IPv6
// address, which no URL carries, is only lower-cased: this is the IP-address half of the browser's
// host serializer. Names are folded (IDNA, a trailing dot) by registration.BrowserHost, for the
// consent page and the client denylist; config refuses a non-ASCII host instead (asciiHost).
func browserHost(host string) string {
	host = strings.ToLower(host)
	switch a, err := netip.ParseAddr(host); {
	case err == nil && a.Zone() != "":
	case err == nil && a.Is4In6():
		b := a.As16()
		return fmt.Sprintf("[::ffff:%x:%x]", uint16(b[12])<<8|uint16(b[13]), uint16(b[14])<<8|uint16(b[15]))
	case err == nil && a.Is6():
		return "[" + a.String() + "]"
	case endsInANumber(host):
		if a, ok := parseIPv4(host); ok {
			return a.String()
		}
	}
	return host
}

// CanonicalHost is a host[:port] (as a Host header carries it, or as BYWARD_ALLOWED_HOSTS and the
// public URL give it: host, host:port, [IPv6], [IPv6]:port or a bare IPv6 address) with its host as
// browsers serialize it (browserHost) and its port kept. The public listener compares Host headers in
// this form (origin.Hosts), so a client that sends the host as written (Go, Python) and one that
// sends it as a browser does (fetch; curl rewrites most spellings) both match an entry however it is spelled.
func CanonicalHost(hostport string) string {
	host, port := hostport, ""
	switch {
	case strings.HasPrefix(hostport, "["):
		inner, rest, ok := strings.Cut(hostport[1:], "]")
		if !ok || (rest != "" && !strings.HasPrefix(rest, ":")) {
			return strings.ToLower(hostport)
		}
		host, port = inner, rest
		if a, err := netip.ParseAddr(inner); err != nil || !a.Is6() || a.Zone() != "" {
			return strings.ToLower(hostport) // no address a browser writes, so only lower-cased
		}
	case strings.Count(hostport, ":") > 1: // a bare IPv6 address, taken whole
	default:
		if h, p, ok := strings.Cut(hostport, ":"); ok {
			host, port = h, ":"+p
		}
	}
	return browserHost(host) + port
}

// browserOrigin is u's origin as browsers serialize it (RFC 6454 §6.2): scheme://host[:port], the
// host as browserHost writes it, and no port when it is the scheme's default.
func browserOrigin(u *url.URL) string {
	host := browserHost(u.Hostname())
	defaultPort := map[string]string{"http": "80", "https": "443"}[u.Scheme]
	if p := u.Port(); p != "" && p != defaultPort {
		host += ":" + p
	}
	return u.Scheme + "://" + host
}
