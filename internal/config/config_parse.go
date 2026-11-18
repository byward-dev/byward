package config

import (
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/byward-dev/byward/internal/logging"
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
// absolute, an ASCII host[:port] that BYWARD_ALLOWED_HOSTS would accept (normalizeAllowedHost: an IP
// address or a name following validHostName's rule, a port from 1 to 65535 without a leading zero,
// no IPv6 zone), no host ending in a number unless it is an IPv4 address in dotted decimal
// (browserIPv4), an IPv6 address or a host name only in the form browsers write it (browserHost: a
// name in lower case), a path without a trailing slash, no query or fragment, and https unless the
// host is loopback (which the proxy itself accepts only with --dev).
func ParsePublicURL(raw string) (*url.URL, error) {
	u, err := parseURL("public-url", raw)
	if err != nil {
		return nil, err
	}
	var errs []string
	if u.Hostname() == "" {
		errs = append(errs, "BYWARD_PUBLIC_URL: give a host, e.g. https://mcp.example.com/mcp")
	} else if _, err := normalizeAllowedHost(u.Host); err != nil {
		// host:port joins the public listener's Host allow-list, so it follows BYWARD_ALLOWED_HOSTS'
		// rules (#344, #353).
		errs = append(errs, fmt.Sprintf("BYWARD_PUBLIC_URL: %v", err))
	} else if err := browserIPv4(u.Hostname()); err != nil {
		// A browser never sends such a host back, so its sign-in could never finish.
		errs = append(errs, fmt.Sprintf("BYWARD_PUBLIC_URL: %v", err))
	} else if h := u.Hostname(); strings.Contains(h, ":") && "["+h+"]" != browserHost(h) {
		// The public URL is also the issuer, the resource and the IdP redirect URI, which browser
		// clients compare with the URL they hold, in the form they write (#447).
		errs = append(errs, fmt.Sprintf("BYWARD_PUBLIC_URL: the IPv6 address [%s] is not in the form browsers write it; write it as %s", h, browserHost(h)))
	} else if !strings.Contains(h, ":") && h != browserHost(h) {
		// The same for a host name: a browser lower-cases it, and byward does not rewrite it, since the
		// IdP's redirect URI is registered as written (#472).
		errs = append(errs, fmt.Sprintf("BYWARD_PUBLIC_URL: the host name %s is not in the form browsers write it; write it as %s", h, browserHost(h)))
	}
	if u.Path == "" || strings.HasSuffix(u.Path, "/") {
		// The example names the host as browsers write it, as the host rules above ask.
		errs = append(errs, fmt.Sprintf("BYWARD_PUBLIC_URL: give the MCP endpoint path without a trailing slash, e.g. https://%s/mcp", CanonicalHost(u.Host)))
	}
	if u.RawQuery != "" || u.Fragment != "" {
		errs = append(errs, "BYWARD_PUBLIC_URL: must not have a query or fragment")
	}
	// LOCALHOST is loopback too; the host name rule above already refuses its spelling.
	if u.Scheme == "http" && !isLoopback(strings.ToLower(u.Hostname())) {
		errs = append(errs, "BYWARD_PUBLIC_URL: must use https (http is allowed only for loopback hosts with --dev)")
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

// ParseUpstreamURL validates the HTTP upstream's URL as the proxy reads BYWARD_UPSTREAM_URL, as
// `byward init entra` also needs it.
func ParseUpstreamURL(raw string) (*url.URL, error) { return parseURL("upstream-url", raw) }

// parseURL validates an absolute http(s) URL setting. Its errors quote the value only as
// logging.Quote does: never a user name, password, query or fragment (security invariant 2).
func parseURL(name, raw string) (*url.URL, error) {
	env := Setting{Name: name}.Env()
	if raw == "" {
		return nil, errorf("%s is required", env)
	}
	u, err := url.Parse(raw)
	switch {
	case err == nil && u.User != nil:
		return nil, errorf("%s: want an absolute http(s) URL without a user name or password, got %s", env, logging.Quote(raw))
	case err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "":
		return nil, errorf("%s: want an absolute http(s) URL, got %s", env, logging.Quote(raw))
	}
	return u, nil
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

func parseProxies(raw string) ([]netip.Prefix, error) {
	var out []netip.Prefix
	for _, item := range splitList(raw) {
		zoned := false
		p, err := netip.ParsePrefix(item)
		switch {
		case err != nil:
			a, aerr := netip.ParseAddr(item)
			if aerr != nil {
				return nil, errorf("BYWARD_TRUSTED_PROXIES: %s is not a CIDR or an IP address", logging.Quote(item))
			}
			// A zone runs to the end of the entry: "fe80::1%eth0/64" is fe80::1 in zone "eth0/64".
			zoned, a = a.Zone() != "", a.WithZone("").Unmap()
			p = netip.PrefixFrom(a, a.BitLen())
		case p.Addr().Is4In6() && p.Bits() < 96: // masked, ::ffff:10.0.0.0/8 is ::/8: it would trust IPv6 peers
			return nil, errorf("BYWARD_TRUSTED_PROXIES: %q is an IPv4-mapped prefix shorter than /96: it maps no IPv4 prefix and would trust IPv6 addresses; give the IPv4 prefix instead (::ffff:10.0.0.0/104 is 10.0.0.0/8)", item)
		case p.Addr().Is4In6(): // peers are compared unmapped (logging.ClientAddress), as a bare mapped address is here
			p = netip.PrefixFrom(p.Addr().Unmap(), p.Bits()-96)
		}
		// Link-local first: removing the zone from "fe80::1%eth0" would only meet this refusal.
		switch p = p.Masked(); {
		case linkLocal.Contains(p.Addr()) && p.Bits() >= linkLocal.Bits():
			return nil, errorf("BYWARD_TRUSTED_PROXIES: %q is link-local: a link-local proxy cannot be trusted, as its address names a host only together with an interface; give the proxy's routable address or CIDR", item)
		case zoned:
			return nil, errorf("BYWARD_TRUSTED_PROXIES: %q has an IPv6 zone: give the proxy's routable address or CIDR, without a zone", item)
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

// normalizeOrigin returns an origin as browsers send it (browserOrigin), with its host[:port]
// checked as BYWARD_ALLOWED_HOSTS checks one (normalizeAllowedHost), and refused when no browser
// could send it (browserIPv4).
func normalizeOrigin(o string) (string, error) {
	u, err := url.Parse(o)
	switch {
	case err == nil && u.User != nil:
		return "", fmt.Errorf("%s is not an origin (scheme://host[:port]): it has a user name or password", logging.Quote(o))
	case strings.ContainsAny(o, "?#"):
		return "", fmt.Errorf("%s is not an origin (scheme://host[:port]): it has a query or a fragment", logging.Quote(o))
	case err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" || u.Path != "":
		return "", fmt.Errorf("%s is not an origin (scheme://host[:port])", logging.Quote(o))
	}
	if _, err := normalizeAllowedHost(u.Host); err != nil {
		return "", fmt.Errorf("%s: %w", logging.Quote(o), err)
	}
	if err := browserIPv4(u.Hostname()); err != nil {
		return "", fmt.Errorf("%s: %w", logging.Quote(o), err)
	}
	return browserOrigin(u), nil
}

// asciiHost refuses a host with non-ASCII characters. Browsers and MCP clients send an
// internationalized host in its ASCII (xn--) form in Host, Origin and every URL they compare
// (WHATWG URL "domain to ASCII", RFC 6454 §7.3), so a Unicode host here could never match them.
func asciiHost(host string) error {
	if strings.ContainsFunc(host, func(r rune) bool { return r >= 0x80 }) {
		const fix = "give its ASCII (xn--) form, which is what browsers and MCP clients send"
		if q := logging.Quote(host); q != logging.Hidden {
			return fmt.Errorf("the host %s is not ASCII; %s", q, fix)
		}
		return fmt.Errorf("%s has a host that is not ASCII; %s", logging.Hidden, fix)
	}
	return nil
}

// normalizeAllowedHost returns a BYWARD_ALLOWED_HOSTS entry, or BYWARD_PUBLIC_URL's host:port,
// which joins the same list, as the public listener compares it with a Host header (CanonicalHost):
// in lower case, an IPv4 address in dotted decimal (127.1 is 127.0.0.1), and an IPv6 address in
// brackets in its shortest form.
// It refuses any form a Host header cannot carry, since such an entry could never match there.
// Accepted: host or host:port (a host may be an IPv4 address), [IPv6], [IPv6]:port, or a bare IPv6
// address taken whole (never as IPv6:port); a port from 1 to 65535 without a sign or leading zero,
// and no IPv6 zone.
func normalizeAllowedHost(h string) (string, error) {
	if err := asciiHost(h); err != nil {
		return "", err
	}
	invalid := fmt.Errorf("%s is not a host[:port]: give host, host:port, an IPv6 address, [IPv6] or [IPv6]:port, with a port from 1 to 65535 and no IPv6 zone", logging.Quote(h))
	if strings.ContainsAny(h, "/ ") {
		return "", invalid
	}
	stored, v6, port, isV6, hasPort := h, "", "", false, false
	switch {
	case strings.HasPrefix(h, "["):
		inner, rest, ok := strings.Cut(h[1:], "]")
		if !ok || (rest != "" && !strings.HasPrefix(rest, ":")) {
			return "", invalid
		}
		v6, isV6, port, hasPort = inner, true, strings.TrimPrefix(rest, ":"), rest != ""
	case strings.ContainsAny(h, "[]"):
		return "", invalid
	case strings.Count(h, ":") > 1:
		v6, isV6, stored = h, true, "["+h+"]"
	default:
		host, p, ok := strings.Cut(h, ":")
		if host == "" {
			return "", invalid
		}
		if !validHostName(host) {
			return "", fmt.Errorf("%s is not a host[:port]: %s", logging.Quote(h), hostNameRule)
		}
		port, hasPort = p, ok
	}
	if isV6 {
		ip, err := netip.ParseAddr(v6)
		if err != nil || !ip.Is6() || ip.Zone() != "" {
			return "", invalid
		}
	}
	if hasPort {
		// No sign, no leading zero: "+80", "-1", "0" and "080" all sort below '1'.
		if n, err := strconv.Atoi(port); err != nil || port[0] < '1' || n > 65535 {
			return "", invalid
		}
	}
	return CanonicalHost(stored), nil
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
