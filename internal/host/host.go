// Package host is the one parser of a host as byward reads one in a setting or a request header
// (ADR-0032): the WHATWG URL host parser for a special scheme, and loopback. It parses only: it
// knows nothing about settings, imports nothing from byward, and its errors are fixed reasons that
// never quote their input (ADR-0031 §1).
package host

import (
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
	"unicode/utf8"
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

// DefaultPort is scheme's default port, which browsers drop when they write a URL (WHATWG URL §4.4),
// or "" for a scheme without one.
func DefaultPort(scheme string) string { return defaultPorts[scheme] }

// NameChars are the characters of a host name byward accepts (ADR-0032 §3): ASCII letters, digits,
// "-", "." and "_". RFC 3986 allows more in a host (~ ! $ & ' ( ) * + , ; =, and browsers all of
// them), but no DNS name holds one, and a host with one is often a pasted secret.
const NameChars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._"

// BadNameChar is the place of the first character of name that is not in NameChars, counted from
// 1, or 0 when there is none, or when name is an IP address, whose ":" (and an IPv6 zone's "%") are
// the address's, not a name's. Every character before it is ASCII, since a non-ASCII one is not in
// NameChars, so the place is the same in bytes and in characters. It never returns the character,
// which a secret may be.
func BadNameChar(name string) int {
	if _, err := netip.ParseAddr(name); err == nil {
		return 0
	}
	for i := 0; i < len(name); i++ {
		if strings.IndexByte(NameChars, name[i]) < 0 {
			return i + 1
		}
	}
	return 0
}

// NameCharReason says why name, a host, is refused for a character no host name holds (ADR-0032 §3:
// only ASCII letters, digits, "-", "." and "_"; an internationalized name in its xn-- form), completing
// "its host …"; "" when it holds none, or is an IP address (BadNameChar), whose ":" is an IPv6
// address's, not a name's. It names the character's place, or says the name is not ASCII; never the character
// or the host, which a secret may be. The URL settings that take a host name (config) and a registered
// redirect URI (registration, #707) take it.
func NameCharReason(name string) string {
	place := BadNameChar(name)
	switch {
	case place == 0:
		return ""
	case strings.ContainsFunc(name, func(r rune) bool { return r >= utf8.RuneSelf }): // told its xn-- form, wherever its first bad character is
		return ReasonNotASCII
	}
	return fmt.Sprintf("has a character no host name holds at position %d; a host name has only letters, digits, - . and _", place)
}

// ReasonNotASCII is why a host with a non-ASCII character is refused. Browsers and MCP clients send
// an internationalized host in its ASCII (xn--) form in Host, Origin and every URL they compare
// (WHATWG URL "domain to ASCII", RFC 6454 §7.3), so a Unicode host could never match them. A byte
// that is not UTF-8 reads as U+FFFD, so it is refused as not ASCII too.
const ReasonNotASCII = "holds a character that is not ASCII; give an internationalized host in its ASCII (xn--) form, which browsers and MCP clients send"

// HasEmptyLabel reports whether name has an empty label: it starts or ends with a dot, or holds two
// in a row. A trailing dot names the root, so example.com. is not example.com (WHATWG URL §3.1).
func HasEmptyLabel(name string) bool {
	return strings.HasPrefix(name, ".") || strings.HasSuffix(name, ".") || strings.Contains(name, "..")
}

// HasEdgeHyphen reports whether any dot-separated label of name starts or ends with a hyphen.
// RFC 952 and RFC 1123 §2.1 require each label to start and end with an alphanumeric character.
func HasEdgeHyphen(name string) bool {
	for label := range strings.SplitSeq(name, ".") {
		if strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return true
		}
	}
	return false
}

// Parse reads hostport (host, host:port, [IPv6], [IPv6]:port, or a bare IPv6 address taken whole)
// as the WHATWG URL host parser does for scheme: a name is folded to its ASCII lower case (IDNA,
// as browsers map it), a host that ends in a number is read as an IPv4 address (127.1 is 127.0.0.1)
// or refused, and an IPv6 address is written in its shortest form. A port that is scheme's default
// is dropped. A trailing dot is kept: example.com. is not example.com (WHATWG URL §3.1).
func Parse(hostport, scheme string) (Host, error) {
	h, port, err := Split(hostport)
	if err != nil {
		return Host{}, err
	}
	if port, err = parsePort(strings.TrimPrefix(port, ":")); err != nil {
		return Host{}, err
	}
	if port == defaultPorts[scheme] {
		port = ""
	}
	if strings.Contains(h, ":") {
		a, ok := ParseIPv6(h)
		if !ok {
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

// ParseIPv6 reads h, a host without brackets, as an IPv6 address without a zone: the one IPv6 form a URL
// or a Host header carries (WHATWG URL §3.1 omits zones).
func ParseIPv6(h string) (netip.Addr, bool) {
	a, err := netip.ParseAddr(h)
	return a, err == nil && a.Is6() && a.Zone() == ""
}

// HasZone reports whether h, a host without brackets, is an IPv6 address with a zone, which no URL
// carries (#644).
func HasZone(h string) bool {
	a, err := netip.ParseAddr(h)
	return err == nil && a.Zone() != ""
}

// Split cuts hostport (host, host:port, [IPv6], [IPv6]:port, or a bare IPv6 address taken whole)
// into its host, without brackets, and its port as written with its colon: ":443", ":" for a colon
// with no port after it, or "" for none. It is the one bracket rule (#644): a hostport that starts
// with "[" must close it around a host with a ":", followed by nothing or by a ":"; a "[" or "]" in a
// hostport that does not start with "[" is ErrBrackets, and one with more than one ":" and no brackets
// is a bare IPv6 address, taken whole with no port. What the brackets enclose and what follows the ":"
// are not read: [not an address:] and [::1]:80] split, and the caller judges the host and the port.
func Split(hostport string) (h, port string, err error) {
	switch {
	case strings.HasPrefix(hostport, "["):
		inner, rest, ok := strings.Cut(hostport[1:], "]")
		if !ok || (rest != "" && !strings.HasPrefix(rest, ":")) || !strings.Contains(inner, ":") {
			return "", "", ErrBrackets
		}
		return inner, rest, nil
	case strings.ContainsAny(hostport, "[]"):
		return "", "", ErrBrackets
	case strings.Count(hostport, ":") > 1:
		return hostport, "", nil
	}
	if i := strings.IndexByte(hostport, ':'); i >= 0 {
		return hostport[:i], hostport[i:], nil
	}
	return hostport, "", nil
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
// spellings (Go's own does not read them as addresses and may send them to DNS; the system's may
// reach loopback), so only the form they all read alike counts. h has no port, and an IPv6 address
// no brackets: a host with either is not loopback.
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

// MatchKey is a host[:port] as a Host header is compared with an allowed host (ADR-0032 §2, class
// B): Canonical (so 127.1 matches 127.0.0.1, and any spelling of an IPv6 address its shortest form),
// without one default port (:443 or :80), trimmed once, so [::1]:80:443 is not [::1]. Two entries
// with one MatchKey name the same host.
func MatchKey(hostport string) string {
	h := Canonical(hostport)
	for _, p := range []string{":443", ":80"} {
		if t, ok := strings.CutSuffix(h, p); ok {
			return t
		}
	}
	return h
}

// Origin is scheme://hostport as an Origin header is compared with an allowed origin (ADR-0032 A3):
// the host and port as Canonical writes them, without the scheme's own default port, so
// https://127.1:443 is https://127.0.0.1 while http://h:443 keeps its port. It folds only what
// MatchKey folds for a Host header, nothing a browser never sends. Two origins with one Origin are
// the same origin.
func Origin(scheme, hostport string) string {
	h := Canonical(hostport)
	if p := DefaultPort(scheme); p != "" {
		h = strings.TrimSuffix(h, ":"+p)
	}
	return scheme + "://" + h
}

// CutHostname cuts hostport (host, host:port, [IPv6], [IPv6]:port or a bare IPv6 address) to its host
// name, without port or brackets, in lower case, and reports whether hostport has one of those shapes
// (#644): ok is false when Split refuses it or its port after the ":" is not up to 5 digits, as for
// [::1]:80] and [mcp.example.com]:443. The name itself is not judged: "", ":80" and [not an address:]
// give ok, and the caller decides whether the name is one it takes. The port is only shaped, not read:
// parsePort and the URL settings' port rule judge a port's value; a Host header's port is the
// listener's own, and RFC 3986 allows an empty one.
func CutHostname(hostport string) (name string, ok bool) {
	h, port, err := Split(hostport)
	if digits := strings.TrimPrefix(port, ":"); err != nil || len(digits) > 5 || strings.Trim(digits, "0123456789") != "" {
		return "", false
	}
	return strings.ToLower(h), true
}

// Hostname is hostport reduced to its host name (CutHostname), or, when hostport is in no shape
// CutHostname takes, hostport lower-cased whole, as Canonical does a malformed one: for values config has checked already.
func Hostname(hostport string) string {
	if name, ok := CutHostname(hostport); ok {
		return name
	}
	return strings.ToLower(hostport)
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
	case HasZone(host):
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
	host, port, err := Split(hostport)
	if err != nil {
		return strings.ToLower(hostport) // brackets no browser writes, so only lower-cased
	}
	if strings.HasPrefix(hostport, "[") {
		if _, ok := ParseIPv6(host); !ok {
			return strings.ToLower(hostport) // no address a browser writes, so only lower-cased
		}
	}
	return Serialize(host) + port
}
