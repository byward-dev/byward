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
// absolute, an ASCII host, a path without a trailing slash, no query or fragment, and https unless
// the host is loopback (which the proxy itself accepts only with --dev).
func ParsePublicURL(raw string) (*url.URL, error) {
	u, err := parseURL("public-url", raw)
	if err != nil {
		return nil, err
	}
	var errs []string
	if err := asciiHost(u.Hostname()); err != nil {
		errs = append(errs, fmt.Sprintf("BYWARD_PUBLIC_URL: %v", err))
	}
	if u.Path == "" || strings.HasSuffix(u.Path, "/") {
		errs = append(errs, fmt.Sprintf("BYWARD_PUBLIC_URL: give the MCP endpoint path without a trailing slash, e.g. https://%s/mcp", u.Host))
	}
	if u.RawQuery != "" || u.Fragment != "" {
		errs = append(errs, "BYWARD_PUBLIC_URL: must not have a query or fragment")
	}
	if u.Scheme == "http" && !isLoopback(u.Hostname()) {
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

func parseURL(name, raw string) (*url.URL, error) {
	env := Setting{Name: name}.Env()
	if raw == "" {
		return nil, errorf("%s is required", env)
	}
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" || u.User != nil {
		return nil, errorf("%s: want an absolute http(s) URL without credentials, got %q", env, raw)
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
		p, err := netip.ParsePrefix(item)
		if err != nil {
			a, aerr := netip.ParseAddr(item)
			if aerr != nil {
				return nil, errorf("BYWARD_TRUSTED_PROXIES: %q is not a CIDR or an IP address", item)
			}
			p = netip.PrefixFrom(a.Unmap(), a.Unmap().BitLen())
		}
		out = append(out, p.Masked())
	}
	return out, nil
}

func splitList(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// normalizeOrigin returns scheme://host[:port] in lower case, the form browsers send.
func normalizeOrigin(o string) (string, error) {
	u, err := url.Parse(o)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" || u.Path != "" || u.RawQuery != "" || u.User != nil {
		return "", fmt.Errorf("%q is not an origin (scheme://host[:port])", o)
	}
	if err := asciiHost(u.Hostname()); err != nil {
		return "", err
	}
	return strings.ToLower(u.Scheme + "://" + u.Host), nil
}

// asciiHost refuses a host with non-ASCII characters. Browsers and MCP clients send an
// internationalized host in its ASCII (xn--) form in Host, Origin and every URL they compare
// (WHATWG URL "domain to ASCII", RFC 6454 §7.3), so a Unicode host here could never match them.
func asciiHost(host string) error {
	if strings.ContainsFunc(host, func(r rune) bool { return r >= 0x80 }) {
		return fmt.Errorf("the host %q is not ASCII; give its ASCII (xn--) form, which is what browsers and MCP clients send", host)
	}
	return nil
}

// bracketedIPv6 reports whether h is [v6] or [v6]:port, v6 an IPv6 address without a zone.
func bracketedIPv6(h string) bool {
	inner, rest, ok := strings.Cut(strings.TrimPrefix(h, "["), "]")
	if !ok || !strings.HasPrefix(h, "[") {
		return false
	}
	if port, hasPort := strings.CutPrefix(rest, ":"); rest != "" && (!hasPort || port == "" || strings.Trim(port, "0123456789") != "") {
		return false
	}
	ip, err := netip.ParseAddr(inner)
	return err == nil && ip.Is6() && ip.Zone() == ""
}

// plainHost reports whether h, without brackets, is a host, host:port with a digits-only port, or
// a bare IPv6 address without a zone (more than one colon: it cannot carry a port).
func plainHost(h string) bool {
	switch strings.Count(h, ":") {
	case 0:
		return h != ""
	case 1:
		host, port, _ := strings.Cut(h, ":")
		return host != "" && port != "" && strings.Trim(port, "0123456789") == ""
	default:
		ip, err := netip.ParseAddr(h)
		return err == nil && ip.Is6() && ip.Zone() == ""
	}
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
