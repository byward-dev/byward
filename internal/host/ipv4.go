package host

import (
	"math"
	"net/netip"
	"strconv"
	"strings"
)

// EndsInANumber reports whether a browser reads host as an IPv4 address (WHATWG URL "ends in a
// number"): its last label, after one trailing dot, is decimal digits, or a number ipv4Number
// parses (0x and hex digits). The parse may then fail (a.0x7f, 1.2.3.4.5), and the browser refuses
// the URL.
func EndsInANumber(host string) bool {
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

// ReadsOctal reports whether a browser reads a number of host, a host that EndsInANumber, as octal:
// a part with a leading 0 that is not a 0x or 0X prefix (010 is 8), as ipv4Number reads it.
func ReadsOctal(host string) bool {
	for p := range strings.SplitSeq(host, ".") {
		if len(p) > 1 && p[0] == '0' && p[1] != 'x' && p[1] != 'X' {
			return true
		}
	}
	return false
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
	if err != nil { // only too large: the parser takes any length, and such a number fails ParseIPv4
		return math.MaxUint64, true
	}
	return n, true
}

// ParseIPv4 is the WHATWG URL IPv4 parser, for a host that EndsInANumber: one to four numbers,
// every one but the last at most 255, the last filling the bytes left (127.1 is 127.0.0.1).
func ParseIPv4(host string) (netip.Addr, bool) {
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
