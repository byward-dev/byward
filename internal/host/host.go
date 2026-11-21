// Package host is the one parser of a host as byward reads one in a setting or a request header
// (ADR-0032): the WHATWG URL host parser for a special scheme, and loopback. It parses only: it
// knows nothing about settings, imports nothing from byward, and its errors are fixed reasons that
// never quote their input (ADR-0031 §1).
package host

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
)

// Kind is what a parsed host is: a name, an IPv4 address or an IPv6 address.
type Kind int

const (
	Name Kind = iota
	IPv4
	IPv6
)

// Host is a host[:port] as a browser reads it (WHATWG URL host parser and serializer).
type Host struct {
	Kind Kind
	// Canonical is the host as browsers serialize it: a name in lower case, internationalized
	// labels in xn-- form; an IPv4 address in dotted decimal, whatever spelling it was read from;
	// an IPv6 address in brackets, in its shortest form.
	Canonical string
	// Addr is the address of an IPv4 or IPv6 host, and the zero Addr for a name.
	Addr netip.Addr
	// Port is the port in decimal, without leading zeros; empty when absent or the scheme's default.
	Port string
}

// The reasons Parse refuses a host[:port]. None quotes the input. They are exported for the setting
// classes of ADR-0032 §2, which refuse through them (slices 2 to 4).
var (
	ErrEmpty         = errors.New("has no host")
	ErrBrackets      = errors.New("has brackets that do not enclose an IPv6 address alone")
	ErrIPv6          = errors.New("is not an IPv6 address without a zone")
	ErrPort          = errors.New("has a port that is not a number from 0 to 65535")
	ErrName          = errors.New("is a name browsers refuse")
	ErrEndsInANumber = errors.New("is not an IPv4 address but ends in a number, so browsers refuse it")
)

// defaultPorts are the special schemes' default ports, which a URL does not carry (WHATWG URL §4.4).
var defaultPorts = map[string]string{"ftp": "21", "http": "80", "https": "443", "ws": "80", "wss": "443"}

// Parse reads hostport (host, host:port, [IPv6], [IPv6]:port, or a bare IPv6 address taken whole)
// as the WHATWG URL host parser does for scheme: a name is folded to its ASCII lower case (IDNA,
// as browsers map it), a host that ends in a number is read as an IPv4 address (127.1 is 127.0.0.1)
// or refused, and an IPv6 address is written in its shortest form. A port that is scheme's default
// is dropped. A trailing dot is kept: example.com. is not example.com (WHATWG URL §3.1).
func Parse(hostport, scheme string) (Host, error) {
	h, port, err := split(hostport)
	if err != nil {
		return Host{}, err
	}
	if port, err = parsePort(port); err != nil {
		return Host{}, err
	}
	if port == defaultPorts[scheme] {
		port = ""
	}
	if strings.Contains(h, ":") {
		a, err := netip.ParseAddr(h)
		if err != nil || !a.Is6() || a.Zone() != "" {
			return Host{}, ErrIPv6
		}
		return Host{Kind: IPv6, Canonical: Serialize(h), Addr: a, Port: port}, nil
	}
	if h == "" {
		return Host{}, ErrEmpty
	}
	// An ASCII domain is only lower-cased, even with xn-- labels; IDNA maps and checks the rest
	// (WHATWG URL §3.3).
	name := strings.ToLower(h)
	if strings.ContainsFunc(h, func(r rune) bool { return r >= 0x80 }) {
		ascii, err := browserIDNA.ToASCII(h)
		if err != nil || ascii == "" {
			return Host{}, ErrName
		}
		name = ascii
	}
	if strings.ContainsFunc(name, forbiddenDomainCodePoint) {
		return Host{}, ErrName
	}
	if EndsInANumber(name) {
		a, ok := ParseIPv4(name)
		if !ok {
			return Host{}, ErrEndsInANumber
		}
		return Host{Kind: IPv4, Canonical: a.String(), Addr: a, Port: port}, nil
	}
	return Host{Kind: Name, Canonical: name, Port: port}, nil
}

// split cuts hostport into its host (without brackets) and port.
func split(hostport string) (h, port string, err error) {
	switch {
	case strings.HasPrefix(hostport, "["):
		inner, rest, ok := strings.Cut(hostport[1:], "]")
		if !ok || (rest != "" && !strings.HasPrefix(rest, ":")) || !strings.Contains(inner, ":") {
			return "", "", ErrBrackets
		}
		return inner, strings.TrimPrefix(rest, ":"), nil
	case strings.ContainsAny(hostport, "[]"):
		return "", "", ErrBrackets
	case strings.Count(hostport, ":") > 1:
		return hostport, "", nil
	}
	h, port, _ = strings.Cut(hostport, ":")
	return h, port, nil
}

// parsePort is port in decimal without leading zeros, or "" for none.
func parsePort(port string) (string, error) {
	if port == "" {
		return "", nil
	}
	if strings.Trim(port, "0123456789") != "" {
		return "", ErrPort
	}
	n, err := strconv.ParseUint(port, 10, 16)
	if err != nil {
		return "", ErrPort
	}
	return strconv.FormatUint(n, 10), nil
}

// String is the host and its port as a browser writes them: Canonical, then :Port if any.
func (h Host) String() string {
	if h.Port == "" {
		return h.Canonical
	}
	return h.Canonical + ":" + h.Port
}

// Loopback reports whether h is on this machine: localhost, in any case, or an address in
// 127.0.0.0/8 or ::1 (ADR-0032 §1). It answers whether an operator's address is local; a redirect
// URI's loopback hosts are an exact set instead (ADR-0009 §2, ADR-0032 §5).
func (h Host) Loopback() bool {
	if h.Kind == Name {
		return h.Canonical == "localhost"
	}
	return h.Addr.Unmap().IsLoopback()
}

// LoopbackAsWritten reports whether h is loopback as an operator wrote it: ASCII only, and a name or
// an IPv4 address only as Parse writes it, case aside. So localhost counts in any case (A1), but
// neither 127.1 nor a full-width or IDNA-mapped spelling of localhost does, though Parse reads them
// as 127.0.0.1 and localhost and Host.Loopback says they are. Resolvers do not agree on those
// spellings (Go's own refuses them; the system's may reach loopback), so only the form they all read
// alike counts. h has no port, and an IPv6 address no brackets: a host with either is not loopback.
func LoopbackAsWritten(h string) bool {
	if strings.HasPrefix(h, "[") || strings.ContainsFunc(h, func(r rune) bool { return r >= 0x80 }) {
		return false
	}
	p, err := Parse(h, "")
	if err != nil || p.Port != "" || p.Kind != IPv6 && !strings.EqualFold(p.Canonical, h) {
		return false
	}
	return p.Loopback()
}

// Hostname is hostport (host, host:port, [IPv6], [IPv6]:port or a bare IPv6 address) reduced to its
// host name: no port, no brackets, in lower case.
func Hostname(hostport string) string {
	h := hostport
	if name, _, err := net.SplitHostPort(h); err == nil {
		h = name
	}
	return strings.ToLower(strings.TrimSuffix(strings.TrimPrefix(h, "["), "]"))
}

// Serialize is a host name (no port, no brackets) as browsers serialize it (WHATWG URL host
// serializer): in lower case; an IPv4 address in dotted decimal, whatever spelling the parser took
// (127.1, 0x7f.0.0.1, 2130706433); an IPv6 address in brackets, in its shortest form and all hex
// (::ffff:7f00:1, where netip writes ::ffff:127.0.0.1). Anything else, including a zoned IPv6
// address, which no URL carries, is only lower-cased: this is the IP-address half of the browser's
// host serializer. Names are folded (IDNA, a trailing dot) by BrowserName.
func Serialize(host string) string {
	host = strings.ToLower(host)
	switch a, err := netip.ParseAddr(host); {
	case err == nil && a.Zone() != "":
	case err == nil && a.Is4In6():
		b := a.As16()
		return fmt.Sprintf("[::ffff:%x:%x]", uint16(b[12])<<8|uint16(b[13]), uint16(b[14])<<8|uint16(b[15]))
	case err == nil && a.Is6():
		return "[" + a.String() + "]"
	case EndsInANumber(host):
		if a, ok := ParseIPv4(host); ok {
			return a.String()
		}
	}
	return host
}

// Canonical is a host[:port] (host, host:port, [IPv6], [IPv6]:port or a bare IPv6 address) with its
// host as browsers serialize it (Serialize) and its port kept as written, so a host sent as written
// (Go, Python) and one sent as a browser writes it (fetch; curl rewrites most spellings) compare
// equal however it is spelled.
func Canonical(hostport string) string {
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
	return Serialize(host) + port
}
