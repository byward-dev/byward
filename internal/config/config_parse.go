package config

import (
	"net"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/byward-dev/byward/internal/ratelimit"
)

// checkText limits page wording: no control or format characters (bidi overrides), at most max
// characters.
func checkText(name, s string, max int) []error {
	env := Setting{Name: name}.Env()
	if strings.ContainsFunc(s, func(r rune) bool { return unicode.IsControl(r) || unicode.Is(unicode.Cf, r) }) {
		return []error{errorf("%s: must not contain control or formatting characters", env)}
	}
	if n := utf8.RuneCountInString(s); n > max {
		return []error{errorf("%s: at most %d characters, got %d", env, max, n)}
	}
	return nil
}

// checkInlineSecrets rejects secrets given directly in env; development mode accepts them and
// reports the relaxation instead.
func checkInlineSecrets(v *Values, dev bool) (relaxation string, err error) {
	secrets := v.inlineSecrets()
	switch {
	case len(secrets) == 0:
		return "", nil
	case !dev:
		return "", errorf("%s: secrets must come from a file (%s_FILE)", strings.Join(secrets, ", "), secrets[0])
	default:
		return "inline secrets accepted: " + strings.Join(secrets, ", "), nil
	}
}

// ParsePublicURL validates the public URL of the MCP endpoint, as `byward init entra` also needs it:
// absolute, an ASCII host[:port] that BYWARD_ALLOWED_HOSTS would accept (hostPort: an IP address or a
// name following validHostName's rule, a port from 1 to 65535 without a leading zero, no IPv6 zone),
// no host ending in a number unless it is an IPv4 address in dotted decimal (browserIPv4), an IPv6
// address or a host name only in the form browsers write it (browserHost: a name in lower case), a
// path without a trailing slash, no query or fragment, and https unless the host is loopback (which
// the proxy itself accepts only with --dev). A refusal never shows the value as given (ADR-0031 §1),
// nor its host: a token is a valid host name. It shows an IP address only as browsers would write it.
func ParsePublicURL(raw string) (*url.URL, error) {
	s := lookup("public-url")
	u, err := parseURLOf(s, raw)
	if err != nil {
		return nil, err
	}
	const want = "the MCP endpoint's URL such as https://mcp.example.com/mcp"
	if u.Hostname() == "" {
		return nil, refusedForm(s, whole, raw, want, "it has no host before its port")
	}
	if _, reason := hostPort(u.Host); reason != "" {
		// host:port joins the public listener's Host allow-list, so it follows BYWARD_ALLOWED_HOSTS'
		// rules (#344, #353). The rest is not checked: the host is not shown, so the URL is not either.
		return nil, refusedForm(s, whole, raw, want, "its host:port "+reason)
	}
	// The host as browsers write it: the public URL is also the issuer, the resource and the IdP
	// redirect URI, which browser clients compare with the URL they hold, in the form they write.
	const wantBrowserHost = "the MCP endpoint's URL with its host as browsers write it"
	var errs []string
	h := u.Hostname()
	if reason := browserIPv4(h); reason != "" {
		// A browser never sends such a host back, so its sign-in could never finish.
		errs = append(errs, refusedForm(s, whole, raw, want, "its host "+reason).Error())
	} else if bh := browserHost(h); strings.Contains(h, ":") && "["+h+"]" != bh {
		// The public URL is also the issuer, the resource and the IdP redirect URI, which browser
		// clients compare with the URL they hold, in the form they write (#447).
		errs = append(errs, refusedForm(s, whole, raw, wantBrowserHost, "its IPv6 address is not in the form browsers write it; write it as "+bh).Error())
	} else if !strings.Contains(h, ":") && h != bh {
		// The same for a host name: a browser lower-cases it, and byward does not rewrite it, since the
		// IdP's redirect URI is registered as written (#472).
		// The host is not shown, not even in lower case: a token is a valid host name.
		errs = append(errs, refusedForm(s, whole, raw, wantBrowserHost, "its host name has upper-case letters; write it in lower case, as browsers do").Error())
	}
	if u.Path == "" || strings.HasSuffix(u.Path, "/") {
		errs = append(errs, refusedMeaning(s, whole, "a path that is empty or ends in /", "the MCP endpoint's path without a trailing slash, e.g. https://mcp.example.com/mcp",
			"give the endpoint's path, without the trailing slash").Error())
	}
	if u.RawQuery != "" || u.Fragment != "" {
		errs = append(errs, refusedMeaning(s, whole, "a query or fragment, not shown", "a URL without a query or fragment", "remove it").Error())
	}
	// LOCALHOST is loopback too; the host name rule above already refuses its spelling.
	if u.Scheme == "http" && !isLoopback(strings.ToLower(h)) {
		errs = append(errs, refusedMeaning(s, whole, "http", "https (http only on a loopback host, with --dev)", "give https, or a loopback host").Error())
	}
	if len(errs) > 0 {
		return nil, &configError{msg: strings.Join(errs, "; ")}
	}
	return u, nil
}

// RedirectURL is the IdP callback the proxy registers for idpName under publicURL.
func RedirectURL(publicURL *url.URL, idpName string) string {
	return (&Config{PublicURL: publicURL}).Issuer() + "/callback/" + idpName
}

// parsePublicURL reads BYWARD_PUBLIC_URL (ParsePublicURL).
func parsePublicURL(val Value) (*url.URL, error) { return ParsePublicURL(val.Given.raw()) }

// parseResourceDocumentation reads BYWARD_RESOURCE_DOCUMENTATION: empty, or an absolute http(s) URL.
func parseResourceDocumentation(val Value) (string, error) {
	if val.Given.empty() {
		return "", nil
	}
	if _, err := parseURL("resource-documentation", val.Given.raw()); err != nil {
		return "", err
	}
	return val.Given.raw(), nil
}

// ParseUpstreamURL validates the HTTP upstream's URL as the proxy reads BYWARD_UPSTREAM_URL, as
// `byward init entra` also needs it.
func ParseUpstreamURL(raw string) (*url.URL, error) { return parseURL("upstream-url", raw) }

// parseUpstreamURL reads BYWARD_UPSTREAM_URL (ParseUpstreamURL).
func parseUpstreamURL(val Value) (*url.URL, error) { return ParseUpstreamURL(val.Given.raw()) }

// parseURL validates an absolute http(s) URL setting, name, which has urlShape
// (TestEverySettingReadAsAURLHasAURLShape). Its refusal goes through the registry entry's shape: name
// is a literal at each call (that test follows it), and the exported parsers byward init uses have no
// Values to take a Value from. A URL refused for its form is never shown (ADR-0031 §1), nor is
// url.Parse's error, which holds the whole value: the refusal gives a fixed reason.
func parseURL(name, raw string) (*url.URL, error) { return parseURLOf(lookup(name), raw) }

// parseURLOf is parseURL for the setting s.
func parseURLOf(s Setting, raw string) (*url.URL, error) {
	if raw == "" {
		return nil, errorf("%s is required", s.Env())
	}
	u, err := url.Parse(raw)
	if reason := urlReason(u, err); reason != "" {
		return nil, refusedForm(s, whole, raw, "an absolute http(s) URL", "it "+reason)
	}
	return u, nil
}

// urlReason says why url.Parse's result u (or its error err) is not an absolute http(s) URL with a
// host and no user name or password, or "" when it is: fixed text completing "it …", never
// url.Parse's error.
func urlReason(u *url.URL, err error) string {
	switch {
	case err != nil:
		return "does not parse as a URL"
	case u.Scheme == "":
		return "has no scheme such as https://"
	case u.Scheme != "https" && u.Scheme != "http":
		return "has a scheme other than http or https"
	case u.Opaque != "":
		return `has no "//" after its scheme`
	case u.Host == "":
		return "has no host"
	case u.User != nil:
		return "holds a user name or password"
	}
	return ""
}

// Bounds of a configured OAuth rate limit (ADR-0018 Consequences: configurable within bounds). There
// is no off switch.
const (
	minRateLimit = 1
	maxRateLimit = 10000
)

func parseRateLimits(raw string) (map[string]int, error) {
	out := ratelimit.Defaults()
	for _, item := range splitList(raw) {
		name, val, ok := strings.Cut(item, "=")
		name = strings.TrimSpace(name)
		if _, known := out[name]; !ok || !known {
			return nil, errorf("BYWARD_OAUTH_RATE_LIMITS: %q is not endpoint=per-minute for one of %s", item, strings.Join(ratelimit.Endpoints, ", "))
		}
		n, err := strconv.Atoi(strings.TrimSpace(val))
		if err != nil || n < minRateLimit || n > maxRateLimit {
			return nil, errorf("BYWARD_OAUTH_RATE_LIMITS: %s must be a whole number from %d to %d per minute, got %q", name, minRateLimit, maxRateLimit, val)
		}
		out[name] = n
	}
	return out, nil
}

// parseProxies reads BYWARD_TRUSTED_PROXIES. An entry that is not a CIDR or an IP address is
// never shown (ADR-0031 §1); one refused for what it names is shown as netip read it, without a zone.
func parseProxies(val Value) ([]netip.Prefix, error) {
	s, raw := val.Setting, val.Given.raw()
	const want = "a CIDR or an IP address such as 10.0.0.0/8 or 192.0.2.1"
	var out []netip.Prefix
	list, at := entries(raw)
	for i, item := range list {
		zoned := false
		p, err := netip.ParsePrefix(item)
		switch {
		case err != nil:
			a, aerr := netip.ParseAddr(item)
			if aerr != nil {
				return nil, refusedForm(s, at(i), item, want, "it is neither a CIDR nor an IP address")
			}
			// A zone runs to the end of the entry: "fe80::1%eth0/64" is fe80::1 in zone "eth0/64".
			zoned, a = a.Zone() != "", a.WithZone("").Unmap()
			p = netip.PrefixFrom(a, a.BitLen())
		case p.Addr().Is4In6() && p.Bits() < 96: // masked, ::ffff:10.0.0.0/8 is ::/8: it would trust IPv6 peers
			return nil, refusedMeaning(s, at(i), p.String(), want, "it is an IPv4-mapped prefix shorter than /96: it maps no IPv4 prefix and would trust IPv6 addresses; give the IPv4 prefix instead (::ffff:10.0.0.0/104 is 10.0.0.0/8)")
		case p.Addr().Is4In6(): // peers are compared unmapped (logging.ClientAddress), as a bare mapped address is here
			p = netip.PrefixFrom(p.Addr().Unmap(), p.Bits()-96)
		}
		// Link-local first: removing the zone from "fe80::1%eth0" would only meet this refusal.
		switch p = p.Masked(); {
		case linkLocal.Contains(p.Addr()) && p.Bits() >= linkLocal.Bits():
			return nil, refusedMeaning(s, at(i), p.String(), want, "it is link-local: a link-local proxy cannot be trusted, as its address names a host only together with an interface; give the proxy's routable address or CIDR")
		case zoned:
			return nil, refusedMeaning(s, at(i), p.Addr().String(), want, "it has an IPv6 zone, not shown: give the proxy's routable address or CIDR, without a zone")
		}
		out = append(out, p)
	}
	return out, nil
}

// linkLocal is IPv6's link-local unicast prefix. A peer in it carries a zone, and a zoned address is
// never a trusted proxy (logging.ClientAddress), so an entry inside it would trust no peer. A wider
// entry (::/0, fe80::/9) is accepted: it cannot trust a link-local peer either.
var linkLocal = netip.MustParsePrefix("fe80::/10")

func splitList(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// parseOrigins reads BYWARD_ALLOWED_ORIGINS: each origin as browsers send it (browserOrigin),
// with its host[:port] checked as BYWARD_ALLOWED_HOSTS checks one (hostPort), and refused when no
// browser could send it (browserIPv4). A refused entry is never shown (ADR-0031 §1).
func parseOrigins(val Value) ([]string, []error) {
	s, raw := val.Setting, val.Given.raw()
	const want = "an origin (scheme://host[:port]) such as https://app.example"
	var out []string
	var errs []error
	list, at := entries(raw)
	for i, o := range list {
		u, reason := parseOrigin(o)
		if reason != "" {
			errs = append(errs, refusedForm(s, at(i), o, want, reason))
			continue
		}
		out = append(out, browserOrigin(u))
	}
	return out, errs
}

// parseOrigin is o parsed as an origin a browser sends, or why it is not one, as a clause ("it has
// a path").
func parseOrigin(o string) (*url.URL, string) {
	u, err := url.Parse(o)
	if reason := urlReason(u, err); reason != "" {
		return nil, "it " + reason
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

// hostPortForms are the forms a host[:port] may take, for its refusals.
const hostPortForms = "give host, host:port, an IPv6 address, [IPv6] or [IPv6]:port, with a port from 1 to 65535 and no IPv6 zone"

// hostPort is a BYWARD_ALLOWED_HOSTS entry, or BYWARD_PUBLIC_URL's host:port, which joins the same
// list, as the public listener compares it with a Host header (CanonicalHost): in lower case, an IPv4
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
	stored, v6, port, isV6, hasPort := h, "", "", false, false
	switch {
	case strings.HasPrefix(h, "["):
		inner, rest, ok := strings.Cut(h[1:], "]")
		if !ok || (rest != "" && !strings.HasPrefix(rest, ":")) {
			return "", "has brackets that do not enclose an IPv6 address alone; " + hostPortForms
		}
		v6, isV6, port, hasPort = inner, true, strings.TrimPrefix(rest, ":"), rest != ""
	case strings.ContainsAny(h, "[]"):
		return "", "has brackets that do not enclose an IPv6 address alone; " + hostPortForms
	case strings.Count(h, ":") > 1:
		v6, isV6, stored = h, true, "["+h+"]"
	default:
		host, p, ok := strings.Cut(h, ":")
		if host == "" {
			return "", `has no host before its ":"; ` + hostPortForms
		}
		if !validHostName(host) {
			return "", "breaks the host name rule: " + hostNameRule
		}
		port, hasPort = p, ok
	}
	if isV6 {
		ip, err := netip.ParseAddr(v6)
		if err != nil || !ip.Is6() || ip.Zone() != "" {
			return "", "is not an IPv6 address without a zone; " + hostPortForms
		}
	}
	if hasPort {
		// No sign, no leading zero: "+80", "-1", "0" and "080" all sort below '1'.
		if n, err := strconv.Atoi(port); err != nil || port[0] < '1' || n > 65535 {
			return "", "has a port that is not a number from 1 to 65535 without a sign or leading zero"
		}
	}
	return CanonicalHost(stored), ""
}

// parseAllowedHosts reads BYWARD_ALLOWED_HOSTS (#323, #325): each entry as hostPort stores it.
// A refused entry is never shown (ADR-0031 §1).
func parseAllowedHosts(val Value) ([]string, []error) {
	s, raw := val.Setting, val.Given.raw()
	var out []string
	var errs []error
	list, at := entries(raw)
	for i, h := range list {
		n, reason := hostPort(h)
		if reason != "" {
			errs = append(errs, refusedForm(s, at(i), h, "a host[:port] such as mcp.example.com or 127.0.0.1:8080", "it "+reason))
			continue
		}
		out = append(out, n)
	}
	return out, errs
}

// parseListen reads a listen address setting: host:port, the host empty, an IP address (an IPv6 one
// may have a zone, as for a link-local address) or a host name (validHostName, one trailing dot
// allowed), the port a number from 0 to 65535, as net.Listen takes it. A refused address is
// never shown (ADR-0031 §1): net.Listen's own error would quote it.
func parseListen(val Value, want string) (string, error) {
	s, raw := val.Setting, val.Given.raw()
	host, port, err := net.SplitHostPort(raw)
	_, ipErr := netip.ParseAddr(host) // an IPv6 address may have a zone, as a link-local one needs
	var reason string
	switch {
	case err != nil:
		reason = "is not host:port"
	case host != "" && !validHostName(strings.TrimSuffix(host, ".")) && ipErr != nil:
		reason = "has a host that is neither an IP address nor a host name"
	case port == "" || strings.Trim(port, "0123456789") != "":
		reason = "has a port that is not a number"
	default:
		if n, err := strconv.Atoi(port); err != nil || n > 65535 { // too many digits for an int is above too
			reason = "has a port that is not a number from 0 to 65535"
		}
	}
	if reason != "" {
		return "", refusedForm(s, whole, raw, want, "it "+reason)
	}
	return raw, nil
}

// hostNameRule is what validHostName requires, for the errors of the settings that use it.
const hostNameRule = "a host name has only letters, digits and - . _ ~, and no empty label (no leading or double dot; drop a trailing one)"

// validHostName reports whether host is a name a host setting can match on: BYWARD_ALLOWED_HOSTS
// (#334), BYWARD_PUBLIC_URL's host, BYWARD_CIMD_TRUSTED_HOSTS, BYWARD_CIMD_ALLOWED_HOSTS (#344) and
// BYWARD_CLIENT_DENYLIST's host entries (through hostNameReason). Not empty, only RFC 3986's
// unreserved characters (a DNS name never uses reg-name's sub-delims or %-escapes, which a Host
// header or a URL could carry), and no empty label. A trailing dot is refused, not stripped: the
// setting would match only a client given the absolute name, never the usual one, so it is almost
// always copied from a DNS zone by mistake. The client denylist is the exception: clientSources
// strips one trailing dot first, since the denylist's matching folds it away.
func validHostName(host string) bool {
	return host != "" && strings.Trim(host, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~") == "" &&
		!strings.HasPrefix(host, ".") && !strings.HasSuffix(host, ".") && !strings.Contains(host, "..")
}

// Hostname is a host as BYWARD_ALLOWED_HOSTS lists it or a Host header carries it (host,
// host:port, [v6], [v6]:port or a bare v6 address) reduced to its host name: no port, no
// brackets, in lower case. The internal listener's Host check, the no-auth loopback check and
// doctor's TLS certificate names use it, so they agree; the public listener's Host check compares
// host:port instead (origin.Hosts).
func Hostname(hostport string) string {
	h := hostport
	if name, _, err := net.SplitHostPort(h); err == nil {
		h = name
	}
	return strings.ToLower(strings.TrimSuffix(strings.TrimPrefix(h, "["), "]"))
}

func isLoopback(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
