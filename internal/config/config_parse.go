package config

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"strconv"
	"strings"

	"github.com/byward-dev/byward/internal/host"
	"github.com/byward-dev/byward/internal/ratelimit"
)

// checkInlineSecrets rejects secrets given directly in env; development mode accepts them and
// reports the relaxation instead.
func checkInlineSecrets(v *Values, dev bool) (relaxation string, err error) {
	secrets := v.inlineSecrets()
	envs := make([]string, len(secrets))
	for i, s := range secrets {
		envs[i] = s.Env()
	}
	switch {
	case len(secrets) == 0:
		return "", nil
	case !dev:
		return "", errorf("%s: secrets must come from a file (%s)", strings.Join(envs, ", "), secrets[0].FileEnv())
	default:
		return "inline secrets accepted: " + strings.Join(envs, ", "), nil
	}
}

// ParsePublicURL validates the public URL of the MCP endpoint, as `byward init entra` also needs it:
// absolute, an ASCII host[:port] that BYWARD_ALLOWED_HOSTS would accept (hostPort: an IP address or a
// name of letters, digits, - . and _ only, no empty label and no label that starts or ends with a
// hyphen, a port from 1 to 65535 without a leading zero, no IPv6 zone: ADR-0032 §3), no host ending
// in a number unless it is an IPv4 address in dotted decimal (browserIPv4), an IPv6 address or a host
// name only in the form browsers write it (host.Serialize: a name in lower case), no port that is the
// scheme's default (browsers drop it, ADR-0032 R2), a path without a trailing slash, no query or
// fragment, and https unless the host is loopback (which the proxy itself accepts only with --dev).
// It is never rewritten into that form: it is also the IdP redirect URI, registered as written
// (ADR-0032 §2, class P). A refusal never shows the value as given (ADR-0031 §1),
// nor its host: a token is a valid host name. It shows an IP address only as browsers would write it.
// It names the setting by its variable: its caller (`byward init`) passes only the text.
func ParsePublicURL(raw string) (*url.URL, error) {
	return parsePublicURL(Value{Setting: lookup("public-url"), Given: NewOpaque(raw)})
}

// parsePublicURL reads BYWARD_PUBLIC_URL by ParsePublicURL's rules, naming it as the operator gave it.
func parsePublicURL(val Value) (*url.URL, error) {
	raw := val.Given.raw()
	u, err := parseURL("public-url", exampleMCPURL, raw, val.Source)
	if err != nil {
		return nil, err
	}
	const want = "the MCP endpoint's URL such as " + exampleMCPURL
	if _, reason := hostPort(u.Host); reason != "" {
		// host:port joins the public listener's Host allow-list, so it follows BYWARD_ALLOWED_HOSTS'
		// rules (#344, #353). The rest is not checked: the host is not shown, so the URL is not either.
		return nil, refusedForm(val, whole, raw, want, "its host:port "+reason)
	}
	// The host as browsers write it: the public URL is also the issuer, the resource and the IdP
	// redirect URI, which browser clients compare with the URL they hold, in the form they write.
	const wantBrowserHost = "the MCP endpoint's URL with its host as browsers write it, such as " + exampleMCPURL
	var errs []error
	h := u.Hostname()
	if reason := browserIPv4(h); reason != "" {
		// A browser never sends such a host back, so its sign-in could never finish.
		errs = append(errs, refusedForm(val, whole, raw, want, "its host "+reason))
	} else if bh := host.Serialize(h); strings.Contains(h, ":") && "["+h+"]" != bh {
		// The public URL is also the issuer, the resource and the IdP redirect URI, which browser
		// clients compare with the URL they hold, in the form they write (#447).
		errs = append(errs, refusedForm(val, whole, raw, wantBrowserHost, "its IPv6 address is not in the form browsers write it; write it as "+bh))
	} else if !strings.Contains(h, ":") && h != bh {
		// The same for a host name: a browser lower-cases it, and byward does not rewrite it, since the
		// IdP's redirect URI is registered as written (#472).
		// The host is not shown, not even in lower case: a token is a valid host name.
		errs = append(errs, refusedForm(val, whole, raw, wantBrowserHost, "its host name has upper-case letters; write it in lower case, as browsers do"))
	}
	if p := u.Port(); p != "" && p == host.DefaultPort(u.Scheme) {
		// Browsers drop a scheme's default port when they write a URL (WHATWG URL §4.4), so a browser
		// client would hold the issuer and resource without it (#484).
		errs = append(errs, refusedForm(val, whole, raw, "the MCP endpoint's URL with its port as browsers write it, such as "+exampleMCPURL,
			"its port "+p+" is "+u.Scheme+"'s default, which browsers drop; write the URL without :"+p))
	}
	if u.Path == "" || strings.HasSuffix(u.Path, "/") {
		errs = append(errs, refusedMeaning(val, whole, "a path that is empty or ends in /", "the MCP endpoint's path without a trailing slash, such as "+exampleMCPURL,
			"give the endpoint's path, without the trailing slash"))
	}
	if u.RawQuery != "" || u.Fragment != "" {
		errs = append(errs, refusedMeaning(val, whole, "a query or fragment, not shown", "a URL without a query or fragment, such as "+exampleMCPURL, "remove it"))
	}
	// LOCALHOST is loopback too; the host name rule above already refuses its spelling.
	if u.Scheme == "http" && !host.LoopbackAsWritten(h) {
		errs = append(errs, refusedMeaning(val, whole, "http", "https (http only on a loopback host, with --dev), such as "+exampleMCPURL, "give https, or a loopback host"))
	}
	if len(errs) > 0 {
		return nil, joinErrors(errs)
	}
	return u, nil
}

// RedirectURL is the IdP callback the proxy registers for idpName under publicURL.
func RedirectURL(publicURL *url.URL, idpName string) string {
	return (&Config{PublicURL: publicURL}).Issuer() + "/callback/" + idpName
}

// parseResourceDocumentation reads BYWARD_RESOURCE_DOCUMENTATION: empty, or an absolute http(s) URL.
func parseResourceDocumentation(val Value) (string, error) {
	if val.Given.empty() {
		return "", nil
	}
	if _, err := parseURL("resource-documentation", "https://docs.example.com/mcp", val.Given.raw(), val.Source); err != nil {
		return "", err
	}
	return val.Given.raw(), nil
}

// ParseUpstreamURL validates the HTTP upstream's URL as the proxy reads BYWARD_UPSTREAM_URL, as
// `byward init entra` also needs it: an absolute http(s) URL whose host name has letters, digits, - .
// and _ only (nameCharReason, ADR-0032 §3), and no IPv6 address with a zone (urlZoneReason); the rest
// of the host is left to Go's dialer.
// It names the setting by its variable: its caller (`byward init`) passes only the text.
func ParseUpstreamURL(raw string) (*url.URL, error) {
	return parseUpstreamURL(Value{Setting: lookup("upstream-url"), Given: NewOpaque(raw)})
}

// parseUpstreamURL reads BYWARD_UPSTREAM_URL by ParseUpstreamURL's rules, naming it as given.
func parseUpstreamURL(val Value) (*url.URL, error) {
	raw := val.Given.raw()
	const example = "http://127.0.0.1:9000/mcp"
	u, err := parseURL("upstream-url", example, raw, val.Source)
	if err != nil {
		return nil, err
	}
	if reason := nameCharReason(u.Hostname()); reason != "" {
		return nil, refusedForm(val, whole, raw, "an absolute http(s) URL such as "+example, "its host "+reason)
	}
	return u, nil
}

// parseURL validates an absolute http(s) URL setting, name, which has urlShape
// (TestEverySettingReadAsAURLHasAURLShape). Its refusal goes through the registry entry's shape: name
// is a literal at each call (that test follows it), and the exported parsers byward init uses have no
// Values to take a Value from. A URL refused for its form is never shown (ADR-0031 §1), nor is
// url.Parse's error, which holds the whole value: the refusal gives a fixed reason and example, a URL
// of the kind of page the setting names.
// The refusal names the setting as given from source: no source names its variable.
func parseURL(name, example, raw string, source Source) (*url.URL, error) {
	val := Value{Setting: lookup(name), Source: source}
	if raw == "" {
		return nil, errorf("%s is required", val.nameAsGiven())
	}
	u, reason := parseHTTPURL(raw)
	if reason != "" {
		return nil, refusedForm(val, whole, raw, "an absolute http(s) URL such as "+example, reason)
	}
	return u, nil
}

// exampleMCPURL is the example of an MCP endpoint's URL that refusals give.
const exampleMCPURL = "https://mcp.example.com/mcp"

// isDigits reports whether s is ASCII digits only, at least one: a port or a prefix length as written.
func isDigits(s string) bool { return s != "" && strings.Trim(s, "0123456789") == "" }

// parseHTTPURL parses raw as an absolute http(s) URL by the one URL rule (host.URLReason), or says why
// it is not one: fixed text completing "it …", never url.Parse's error, which quotes the value.
func parseHTTPURL(raw string) (*url.URL, string) {
	u, reason := host.URLReason(raw)
	if reason != "" {
		return nil, "it " + reason
	}
	return u, ""
}

// urlZoneReason and portReason are host's URL refusals (host.URLReason), named here as config's
// other reasons are.
const (
	urlZoneReason = host.URLZoneReason
	portReason    = host.PortReason
)

// Bounds of a configured OAuth rate limit (ADR-0018 Consequences: configurable within bounds). There
// is no off switch.
const (
	minRateLimit = 1
	maxRateLimit = 10000
)

func parseRateLimits(val Value) (map[string]int, []error) {
	want := fmt.Sprintf("endpoint=per-minute entries such as %s=%d, the endpoint %s and the limit a whole number from %d to %d",
		ratelimit.Token, ratelimit.Defaults()[ratelimit.Token], oneOf(ratelimit.Endpoints), minRateLimit, maxRateLimit)
	out := ratelimit.Defaults()
	var errs []error
	list, at, err := parseEntries(val)
	if err != nil {
		return nil, []error{err}
	}
	for i, item := range list {
		name, per, ok := strings.Cut(item, "=")
		name = strings.TrimSpace(name)
		n, err := strconv.Atoi(strings.TrimSpace(per))
		switch _, known := out[name]; {
		case !ok || !known:
			errs = append(errs, refusedForm(val, at(i), item, want, "it is not endpoint=per-minute for one of the endpoints"))
		case errors.Is(err, strconv.ErrRange):
			errs = append(errs, refusedForm(val, at(i), item, want, "its limit is out of range"))
		case err != nil:
			errs = append(errs, refusedForm(val, at(i), item, want, "its limit is not a whole number"))
		case n < minRateLimit || n > maxRateLimit:
			errs = append(errs, refusedMeaning(val, at(i), name+"="+strconv.Itoa(n), want, "the limit is out of range"))
		default:
			out[name] = n
		}
	}
	if len(errs) > 0 {
		return nil, errs
	}
	return out, nil
}

// parseProxies reads BYWARD_TRUSTED_PROXIES. An entry that is not a CIDR or an IP address is
// never shown (ADR-0031 §1); one refused for what it names is shown as netip read it, without a zone.
func parseProxies(val Value) ([]netip.Prefix, error) {
	const want = "a CIDR or an IP address such as 10.0.0.0/8 or 192.0.2.1"
	var out []netip.Prefix
	list, at, err := parseEntries(val)
	if err != nil {
		return nil, err
	}
	for i, item := range list {
		zoned := false
		p, err := netip.ParsePrefix(item)
		switch {
		case err != nil:
			a, aerr := netip.ParseAddr(item)
			if aerr != nil {
				return nil, refusedForm(val, at(i), item, want, cidrReason(item))
			}
			// A zone runs to the end of the entry: "fe80::1%eth0/64" is fe80::1 in zone "eth0/64".
			zoned, a = a.Zone() != "", a.WithZone("").Unmap()
			p = netip.PrefixFrom(a, a.BitLen())
		case p.Addr().Is4In6() && p.Bits() < 96: // masked, ::ffff:10.0.0.0/8 is ::/8: it would trust IPv6 peers
			return nil, refusedMeaning(val, at(i), p.String(), want, "it is an IPv4-mapped prefix shorter than /96: it maps no IPv4 prefix and would trust IPv6 addresses; give the IPv4 prefix instead (::ffff:10.0.0.0/104 is 10.0.0.0/8)")
		case p.Addr().Is4In6(): // peers are compared unmapped (logging.ClientAddress), as a bare mapped address is here
			p = netip.PrefixFrom(p.Addr().Unmap(), p.Bits()-96)
		}
		// Link-local first: removing the zone from "fe80::1%eth0" would only meet this refusal.
		switch p = p.Masked(); {
		case linkLocal.Contains(p.Addr()) && p.Bits() >= linkLocal.Bits():
			return nil, refusedMeaning(val, at(i), p.String(), want, "it is link-local: a link-local proxy cannot be trusted, as its address names a host only together with an interface; give the proxy's routable address or CIDR")
		case zoned:
			return nil, refusedMeaning(val, at(i), p.Addr().String(), want, "it has an IPv6 zone, not shown: give the proxy's routable address or CIDR, without a zone")
		}
		out = append(out, p)
	}
	return out, nil
}

// cidrReason says why item, neither a CIDR nor an IP address, is not one, as a clause that never
// quotes it: by the part that fails, the address or the prefix length after its "/".
func cidrReason(item string) string {
	addr, bits, ok := strings.Cut(item, "/")
	a, err := netip.ParseAddr(addr)
	switch {
	case !ok:
		return "it is neither a CIDR nor an IP address"
	case err != nil:
		return `its address, before the "/", is not an IP address`
	case !isDigits(bits):
		return `its prefix length, after the "/", is not a whole number`
	case len(bits) > 1 && bits[0] == '0':
		return "its prefix length has a leading zero"
	case a.Is4(): // what ParsePrefix leaves to refuse: a length longer than the address
		return "its prefix length is longer than /32, the length of an IPv4 address"
	}
	return "its prefix length is longer than /128, the length of an IPv6 address"
}

// linkLocal is IPv6's link-local unicast prefix. A peer in it carries a zone, and a zoned address is
// never a trusted proxy (logging.ClientAddress), so an entry inside it would trust no peer. A wider
// entry (::/0, fe80::/9) is accepted: it cannot trust a link-local peer either.
var linkLocal = netip.MustParsePrefix("fe80::/10")

// parseOrigins reads BYWARD_ALLOWED_ORIGINS: each origin as browsers send it (browserOrigin),
// with its host[:port] checked as BYWARD_ALLOWED_HOSTS checks one (hostPort), and refused when no
// browser could send it (browserIPv4). A refused entry is never shown (ADR-0031 §1).
func parseOrigins(val Value) ([]string, []error) {
	const want = "an origin (scheme://host[:port]) such as https://app.example"
	var out []string
	var errs []error
	list, at, err := parseEntries(val)
	if err != nil {
		return nil, []error{err}
	}
	for i, o := range list {
		u, reason := parseOrigin(o)
		if reason != "" {
			errs = append(errs, refusedForm(val, at(i), o, want, reason))
			continue
		}
		out = append(out, browserOrigin(u))
	}
	return out, errs
}

// parseOrigin is o parsed as an origin a browser sends, or why it is not one, as a clause ("it has
// a path").
func parseOrigin(o string) (*url.URL, string) {
	u, reason := parseHTTPURL(o)
	if reason != "" {
		return nil, reason
	}
	switch {
	case strings.ContainsAny(o, "?#"):
		return nil, "it has a query or a fragment"
	case u.Path != "":
		return nil, "it has a path"
	}
	if _, reason := hostPort(u.Host); reason != "" {
		return nil, "its host:port " + reason
	}
	if reason := browserIPv4(u.Hostname()); reason != "" {
		return nil, "its host " + reason
	}
	return u, ""
}

// reasonNotASCII is why a host with a non-ASCII character is refused. Browsers and MCP clients send
// an internationalized host in its ASCII (xn--) form in Host, Origin and every URL they compare
// (WHATWG URL "domain to ASCII", RFC 6454 §7.3), so a Unicode host here could never match them.
const reasonNotASCII = "holds a character that is not ASCII; give an internationalized host in its ASCII (xn--) form, which browsers and MCP clients send"

// notASCII reports whether s holds a character that is not ASCII.
func notASCII(s string) bool { return strings.ContainsFunc(s, func(r rune) bool { return r >= 0x80 }) }

// reasonEmptyLabel is why a host name with an empty label is refused, completing "it …" or "its
// host:port …": a trailing dot names the root, a different host to a browser (WHATWG URL §3.1).
const reasonEmptyLabel = "has an empty label (a leading, double or trailing dot); drop the extra dot"

// nameReason says why name, a host, breaks the host name rule (ADR-0032 §3): a character no host name
// holds (nameCharReason), an empty label, or a label that starts or ends with a hyphen (#630),
// completing "it …" or "its host:port …"; "" when it keeps the rule, or is an IP address. Every host
// setting but the upstream URL takes it: the browser-matched ones (hostPort), the server-matched ones
// (hostNameReason) and the listen addresses (validHostName).
func nameReason(name string) string {
	switch reason := nameCharReason(name); {
	case reason != "":
		return reason
	case host.HasEmptyLabel(name):
		return reasonEmptyLabel
	case host.HasEdgeHyphen(name):
		return reasonEdgeHyphen
	}
	return ""
}

// reasonEdgeHyphen is why a host name with a label that starts or ends with a hyphen is refused,
// completing "it …" or "its host:port …" (RFC 952, RFC 1123 §2.1; #630).
const reasonEdgeHyphen = "has a label that starts or ends with a hyphen; a label starts and ends with a letter or a digit"

// hostPortForms are the forms a host[:port] may take, for its refusals.
const hostPortForms = "give host, host:port, an IPv6 address, [IPv6] or [IPv6]:port, with a port from 1 to 65535 and no IPv6 zone"

// hostPort is a BYWARD_ALLOWED_HOSTS entry, or BYWARD_PUBLIC_URL's host:port, which joins the same
// list, as the public listener compares it with a Host header (host.Canonical): in lower case, an IPv4
// address in dotted decimal (127.1 is 127.0.0.1), and an IPv6 address in brackets in its shortest
// form. It refuses any form a Host header cannot carry, since such an entry could never match there,
// with a fixed reason that completes "it …" and never repeats the entry.
// Accepted: host or host:port (a host may be an IPv4 address), [IPv6], [IPv6]:port, or a bare IPv6
// address taken whole (never as IPv6:port); a port from 1 to 65535 without a sign or leading zero,
// and no IPv6 zone.
func hostPort(h string) (stored, reason string) {
	if notASCII(h) {
		return "", reasonNotASCII
	}
	if strings.ContainsAny(h, "/ ") {
		return "", `holds a "/" or a space; ` + hostPortForms
	}
	name, p, err := host.Split(h) // the one bracket rule (#644)
	if err != nil {
		return "", bracketsReason + "; " + hostPortForms
	}
	switch {
	case strings.Contains(name, ":"): // an IPv6 address, in brackets or bare
		if _, ok := host.ParseIPv6(name); !ok {
			return "", ipv6Reason + "; " + hostPortForms
		}
	default:
		if name == "" {
			return "", `has no host before its ":"; ` + hostPortForms
		}
		if reason := nameReason(name); reason != "" {
			return "", reason
		}
	}
	if p != "" && !host.IsPortNumber(strings.TrimPrefix(p, ":")) {
		return "", portReason
	}
	return host.Serialize(name) + p, ""
}

// parseAllowedHosts reads BYWARD_ALLOWED_HOSTS (#323, #325): each entry as hostPort stores it,
// folded as a browser writes it, and refused when a browser reads its host as an IPv4 address it
// is not written as (127.1, 010.0.0.1: ADR-0032 R3) or refuses it (mcp.10: R4), naming what the
// browser reads, never rewritten. A refused entry is never shown (ADR-0031 §1).
func parseAllowedHosts(val Value) ([]string, []error) {
	var out []string
	var errs []error
	list, at, err := parseEntries(val)
	if err != nil {
		return nil, []error{err}
	}
	for i, h := range list {
		const want = "a host[:port] such as mcp.example.com or 127.0.0.1:8080"
		n, reason := hostPort(h)
		if reason != "" {
			errs = append(errs, refusedForm(val, at(i), h, want, "it "+reason))
			continue
		}
		if reason := browserIPv4(host.Hostname(h)); reason != "" {
			errs = append(errs, refusedForm(val, at(i), h, want, "its host "+reason))
			continue
		}
		out = append(out, n)
	}
	return out, errs
}

// zoneReason is why a listen address's IPv6 zone that no interface can be named is refused,
// completing "it …".
const zoneReason = "has an IPv6 zone that is not an interface name: 1 to 15 bytes, not . or .., without white space, a control character, a slash or a colon"

// validInterfaceName reports whether zone is a name a network interface can have, by Linux's own rule
// (dev_valid_name, net/core/dev.c): 1 to 15 bytes (IFNAMSIZ is 16, include/uapi/linux/if.h; macOS's
// IF_NAMESIZE is 16 too, xnu bsd/net/if.h), not "." or "..", and no "/", ":" or byte the kernel's
// isspace matches (9 to 13, 32 and 0xA0, lib/ctype.c). Bytes, not characters, as the kernel reads
// it. It refuses an ASCII control character too, which the kernel would take (#638). Go maps a
// zone to an interface index through its own interface list and, when no interface has the name,
// reads its leading digits as an index, 0 (an unscoped bind) when it starts with none
// (net/interface.go ipv6ZoneCache.index, Go 1.27.4 lines 244-261; dtoi, net/parse.go): a zone
// outside this rule can match no interface, so it would be dropped silently or misread. A numeric
// zone, an interface index, passes.
func validInterfaceName(zone string) bool {
	if zone == "" || len(zone) > 15 || zone == "." || zone == ".." {
		return false
	}
	for i := range len(zone) {
		if b := zone[i]; b == '/' || b == ':' || b == ' ' || b == 0xA0 || b < 0x20 || b == 0x7F {
			return false
		}
	}
	return true
}

// bracketsReason is why an address with brackets around anything but an IPv6 address is refused:
// host.Parse's own reason, shared by hostPort, host.URLReason and parseListen (whose host variable
// shadows the package).
var bracketsReason = host.ErrBrackets.Error()

// ipv6Reason is why a bracketed or bare IPv6 host that is not an IPv6 address without a zone is
// refused: host.Parse's own reason.
var ipv6Reason = host.ErrIPv6.Error()

// parseListen reads a listen address setting: host:port, the host empty, an IP address (an IPv6 one
// may have a zone, as for a link-local address) or a host name (validHostName, one trailing dot
// allowed, and letters, digits, - . and _ only: nameCharReason, ADR-0032 §3), the port a
// number from 0 to 65535, as net.Listen takes it. Brackets enclose an IPv6 address alone (RFC 3986
// §3.2.2), as host.Parse requires (#629): net.SplitHostPort strips them from a name, an IPv4
// address or nothing too, so such a value is almost certainly a typo, and []:80 would listen on
// every interface. An IPv6 zone is a name an interface can have (validInterfaceName, #638). A refused
// address is never shown (ADR-0031 §1): net.Listen's own error would quote it.
func parseListen(val Value, want string) (string, error) {
	raw := val.Given.raw()
	host, port, err := net.SplitHostPort(raw)
	_, ipErr := netip.ParseAddr(host) // an IPv6 address may have a zone, as a link-local one needs
	charReason, zone, zoned := "", "", false
	if !strings.Contains(host, ":") { // an IPv6 host is no name; a bad one is neither, below
		charReason = nameCharReason(host)
	} else if addr, z, ok := strings.Cut(host, "%"); ok {
		if a, err := netip.ParseAddr(addr); err == nil && a.Is6() { // a zone only on an IPv6 address
			zone, zoned = z, true
		}
	}
	var reason string
	switch {
	case err != nil:
		reason = "it is not host:port"
	case strings.HasPrefix(raw, "[") && !strings.Contains(host, ":"):
		reason = "it " + bracketsReason
	case zoned && !validInterfaceName(zone):
		reason = "it " + zoneReason
	case charReason != "":
		reason = "its host " + charReason
	case host != "" && !validHostName(strings.TrimSuffix(host, ".")) && ipErr != nil:
		reason = "it has a host that is neither an IP address nor a host name"
	case !isDigits(port):
		reason = "it has a port that is not a number"
	default:
		if n, err := strconv.Atoi(port); err != nil || n > 65535 { // too many digits for an int is above too
			reason = "it has a port that is not a number from 0 to 65535"
		}
	}
	if reason != "" {
		return "", refusedForm(val, whole, raw, want, reason)
	}
	return raw, nil
}

// validHostName reports whether name, a listen address's host (parseListen), is a host name: not
// empty, and keeping the host name rule (nameReason). An IP address keeps it too, so parseListen asks
// only of a host that is not one; it strips one trailing dot first, since net.Listen takes it, and
// refuses a bad character before, naming its place.
func validHostName(name string) bool { return name != "" && nameReason(name) == "" }
