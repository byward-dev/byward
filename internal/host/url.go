package host

import (
	"errors"
	"net/url"
	"strconv"
	"strings"
	"unicode"
)

// URLReason says why raw is not an absolute http(s) URL as byward follows one, or "" when it is
// one, with url.Parse's result. It is the one URL rule (#651): every URL setting (config's
// parseHTTPURL) and every endpoint an IdP's discovery document names (oidc's checkURL) take it. The
// reason is fixed text completing "it …", never url.Parse's error, which quotes the value. White
// space, control and invisible formatting characters are refused first: url.Parse accepts a space or a
// non-ASCII control character in a path (#422), which no URL holds (RFC 3986 §2). Then: a scheme,
// http or https, with "//" and a host; no IPv6 zone (URLZoneReason); no user name or password; a port,
// if any, as IsPortNumber takes it.
func URLReason(raw string) (*url.URL, string) {
	u, err := url.Parse(raw)
	switch {
	case strings.ContainsFunc(raw, unicode.IsSpace):
		return u, "has white space, which a URL cannot hold; write a space in a path as %20"
	case strings.ContainsFunc(raw, unicode.IsControl):
		return u, "has a control character, which a URL cannot hold"
	case strings.ContainsFunc(raw, func(r rune) bool { return unicode.Is(unicode.Cf, r) }):
		return u, "has an invisible formatting character, such as a zero-width space, which a URL cannot hold"
	case err != nil:
		return u, urlParseReason(err)
	case u.Scheme == "", u.Scheme != "https" && u.Scheme != "http" && isDigits(strings.SplitN(u.Opaque, "/", 2)[0]):
		// url.Parse reads host:port written without a scheme (localhost:9000/mcp) as a scheme and an opaque part.
		return u, "has no scheme such as https://"
	case u.Scheme != "https" && u.Scheme != "http":
		return u, "has a scheme other than http or https"
	case u.Opaque != "":
		return u, `has no "//" after its scheme`
	case u.Host == "":
		return u, "has no host"
	case u.Hostname() == "": // http://:9000/mcp: a port alone, which a dialer reads as this host (#614)
		return u, "has no host before its port"
	case HasZone(u.Hostname()):
		return u, URLZoneReason
	case u.User != nil:
		return u, "holds a user name or password"
	case (u.Port() != "" || strings.HasSuffix(u.Host, ":")) && !IsPortNumber(u.Port()):
		return u, PortReason
	}
	return u, ""
}

// URLZoneReason is why a URL is refused for an IPv6 zone (#644): a URL cannot carry one (WHATWG URL
// §3.1 omits zones), so a browser or MCP client following the public URL, the resource documentation
// or the issuer could not use it, and no browser sends an allowed origin with one; the upstream URL, a
// CIMD client ID on the client denylist and a discovered IdP endpoint are held to the same rule. The
// listen addresses take a zone that names an interface (config's zoneReason).
const URLZoneReason = "has an IPv6 zone, which a URL cannot carry; give the address without its %zone"

// IsPortNumber reports whether port is a TCP port as a URL may write it: 1 to 65535, no sign, no
// leading zero (#602). url.Parse checks only that a port is digits, so :0, :08080 and :99999 parse.
// The listen addresses take 0, which asks the kernel for a port; no URL a client follows does.
func IsPortNumber(port string) bool {
	n, err := strconv.Atoi(port)
	return err == nil && port[0] >= '1' && n <= 65535 // Atoi took it, so a first byte from '1' is a digit
}

// PortReason is why a host:port, or a URL, is refused for its port.
const PortReason = "has a port that is not a number from 1 to 65535 without a sign or leading zero"

// urlParseReason says why url.Parse refused a value, by its error, as a clause completing "it …".
// The errors of net/url are read by type, or by their fixed text before any quoted part; one not
// named here gets a general reason. An EscapeError holds the escape url.Parse refused, which is read
// (never shown) to tell a malformed one from a host's %-escape of an ASCII character, which url.Parse
// refuses too; a malformed escape elsewhere, such as in a query, which url.Parse does not check, plays
// no part.
func urlParseReason(err error) string {
	var escape url.EscapeError
	var badHost url.InvalidHostError
	switch inner := errors.Unwrap(err); {
	case errors.As(err, &escape) && !isEscape(string(escape)):
		return `has a "%" not followed by two hexadecimal digits`
	case errors.As(err, &escape): // url.Parse refuses a host's %-escape of an ASCII character too
		return "has a %-escape in its host, which a host name cannot hold"
	case errors.As(err, &badHost):
		return "has a character a host cannot hold"
	case inner == nil:
	case inner.Error() == "missing protocol scheme", inner.Error() == "first path segment in URL cannot contain colon":
		// The second is url.Parse's error for 127.0.0.1:9000/mcp: a "scheme" cannot start with a digit.
		return "has no scheme such as https://"
	case strings.HasPrefix(inner.Error(), `invalid port ":`):
		return "has a port that is not a number"
	case strings.HasPrefix(inner.Error(), "invalid port "): // after [IPv6], anything but :port
		return `has text after the "]" of its IPv6 address that is not a ":" and a port`
	case inner.Error() == "missing ']' in host":
		return `has a "[" in its host without its "]"`
	case inner.Error() == "invalid IP-literal", strings.HasPrefix(inner.Error(), "invalid host: "):
		return ErrBrackets.Error()
	case inner.Error() == "net/url: invalid userinfo":
		return "holds a user name or password"
	}
	return "does not parse as a URL"
}

// isEscape reports whether s is a well-formed %-escape: "%" and two hexadecimal digits.
func isEscape(s string) bool {
	_, err := url.PathUnescape(s) // a path segment's unescaping refuses only a malformed escape
	return len(s) == 3 && s[0] == '%' && err == nil
}

// isDigits reports whether s is ASCII digits only, at least one.
func isDigits(s string) bool { return s != "" && strings.Trim(s, "0123456789") == "" }
