package config

import (
	"net/textproto"
	"slices"
	"strconv"
	"strings"
)

// AssertionClaimNames are the optional claims an identity assertion may carry.
var AssertionClaimNames = []string{"roles", "groups", "email", "name"}

// reservedHeaders may not carry the assertion: the proxy, the transport or the MCP protocol owns
// them, or they carry forwarding or browser data (ADR-0016 §2, §4; ADR-0018 §6).
var reservedHeaders = map[string]bool{"Host": true, "Cookie": true, "Set-Cookie": true, "Content-Length": true, "Content-Type": true,
	"Transfer-Encoding": true, "Connection": true, "Keep-Alive": true, "Upgrade": true, "Te": true, "Trailer": true, "Accept": true,
	"Accept-Encoding": true, "Forwarded": true, "Origin": true, "Referer": true, "Mcp-Session-Id": true, "Mcp-Protocol-Version": true,
	"Last-Event-Id": true, "Traceparent": true, "Tracestate": true, "Baggage": true, "Www-Authenticate": true}

// assertion reads the identity assertion settings: a header that is a valid token and not one the
// proxy relies on, and claims from AssertionClaimNames (or none).
func (c *Config) assertion(v *Values) []error {
	var errs []error
	var err error
	if c.AssertionHeader, err = upstreamHeader(v, "assertion-header", "X-Byward-Identity"); err != nil {
		errs = append(errs, err)
	}
	ihEnv := Setting{Name: "identity-headers"}.Env()
	if c.IdentityHeaders, err = strconv.ParseBool(v.get("identity-headers")); err != nil {
		errs = append(errs, errorf("%s: want true or false, got %q", ihEnv, v.get("identity-headers")))
	} else if c.IdentityHeaders && c.UpstreamCommand != nil {
		errs = append(errs, errorf("%s is for an HTTP upstream; a stdio upstream gets the user in its environment (BYWARD_SUBJECT, docs/how-to/stdio-upstream.md)", ihEnv))
	}
	if c.AssertionUnverifiedEmail, err = strconv.ParseBool(v.get("assertion-unverified-email")); err != nil {
		errs = append(errs, errorf("%s: want true or false, got %q", Setting{Name: "assertion-unverified-email"}.Env(), v.get("assertion-unverified-email")))
	}
	cEnv := Setting{Name: "assertion-claims"}.Env()
	raw := strings.TrimSpace(v.get("assertion-claims"))
	if raw == "none" {
		return errs
	}
	seen := map[string]bool{}
	for _, name := range splitList(raw) {
		name = strings.ToLower(name)
		switch {
		case !slices.Contains(AssertionClaimNames, name):
			errs = append(errs, errorf("%s: %q is not one of %s, or none", cEnv, name, strings.Join(AssertionClaimNames, ", ")))
		case !seen[name]:
			seen[name] = true
			c.AssertionClaims = append(c.AssertionClaims, name)
		}
	}
	if raw != "" && len(splitList(raw)) == 0 {
		errs = append(errs, errorf("%s is set but lists nothing; give claims, or none", cEnv))
	}
	return errs
}

// upstreamHeader reads a setting naming a header the proxy sets on upstream requests: a valid
// token, and not one the proxy, the transport or MCP relies on. example is a header of the
// operator's own to suggest.
func upstreamHeader(v *Values, setting, example string) (string, error) {
	env := Setting{Name: setting}.Env()
	h := textproto.CanonicalMIMEHeaderKey(strings.TrimSpace(v.get(setting)))
	switch {
	case h == "" || strings.ContainsFunc(h, func(r rune) bool { return !isTokenChar(r) }):
		return "", errorf("%s: want a header name such as Authorization or %s, got %q", env, example, v.get(setting))
	case reservedHeaders[h] || strings.HasPrefix(h, "X-Forwarded-") || strings.HasPrefix(h, "Proxy-") || strings.HasPrefix(h, "Sec-") || strings.HasPrefix(h, "Access-Control-"):
		return "", errorf("%s: %s is a header the proxy, the transport or MCP relies on; use Authorization or a header of your own such as %s", env, h, example)
	}
	return h, nil
}

// The plain identity headers (ADR-0016 §5). Their names are fixed, and reserved even while
// BYWARD_IDENTITY_HEADERS is off: no other setting may use them, and every inbound copy is removed.
const (
	HeaderSubject  = "X-Byward-Subject"
	HeaderClientID = "X-Byward-Client-Id"
	// HeaderPrincipalType is user, or client for an app-only caller (ADR-0022 §5).
	HeaderPrincipalType = "X-Byward-Principal-Type"
	HeaderRoles         = "X-Byward-Roles"
	HeaderGroups        = "X-Byward-Groups"
	HeaderEmail         = "X-Byward-Email"
	// HeaderEmailVerified is "true" or "false", sent exactly when HeaderEmail is.
	HeaderEmailVerified = "X-Byward-Email-Verified"
	HeaderName          = "X-Byward-Name"
)

// IdentityHeaderNames are the plain identity headers.
var IdentityHeaderNames = []string{HeaderSubject, HeaderClientID, HeaderPrincipalType, HeaderRoles, HeaderGroups, HeaderEmail, HeaderEmailVerified, HeaderName}

// headerClashes refuses two purposes in one header: the identity assertion, the operator's
// upstream credential, the On-Behalf-Of token and the plain identity headers each have their own
// (ADR-0016 §4, §5, §7; ADR-0017 §3). The
// relay reads "_" as "-" (invariant 16), so X_Api_Key and X-Api-Key are one header.
func (c *Config) headerClashes() []error {
	var errs []error
	aEnv, cEnv := Setting{Name: "assertion-header"}.Env(), Setting{Name: "upstream-credential-header"}.Env()
	if c.UpstreamCredentialHeader != "" && sameHeader(c.UpstreamCredentialHeader, c.AssertionHeader) {
		errs = append(errs, errorf("%s and %s are both %s, but the credential and the identity assertion never share a header (ADR-0016 §7): set %s to a header of your own, such as X-Byward-Identity, and verify the assertion there",
			cEnv, aEnv, c.UpstreamCredentialHeader, aEnv))
	}
	for _, u := range []struct{ env, header string }{{aEnv, c.AssertionHeader}, {cEnv, c.UpstreamCredentialHeader}, {Setting{Name: "obo-header"}.Env(), c.OBOHeader}} {
		for _, plain := range IdentityHeaderNames {
			if sameHeader(u.header, plain) {
				errs = append(errs, errorf("%s: %s is one of the plain identity headers the proxy sets (docs/how-to/plain-identity-headers.md); use another header", u.env, u.header))
			}
		}
	}
	return errs
}

// sameHeader reports whether two header names reach the upstream as one.
func sameHeader(a, b string) bool {
	return a != "" && strings.EqualFold(strings.ReplaceAll(a, "_", "-"), strings.ReplaceAll(b, "_", "-"))
}

// isTokenChar reports whether r may appear in an HTTP header name (RFC 9110 §5.6.2).
func isTokenChar(r rune) bool {
	return r < 0x7f && (r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("!#$%&'*+-.^_`|~", r))
}
