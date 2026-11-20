package config

import (
	"net/textproto"
	"strings"

	"golang.org/x/net/http/httpguts"
)

// reservedHeaders may not be set by any upstream header setting (the assertion, upstream
// credential and On-Behalf-Of headers): the proxy, the transport or the MCP protocol owns them, or
// they carry forwarding or browser data (ADR-0016 §2, §4; ADR-0018 §6).
var reservedHeaders = withMCPHeaders(map[string]bool{"Host": true, "Cookie": true, "Set-Cookie": true, "Content-Length": true,
	"Content-Type": true, "Transfer-Encoding": true, "Connection": true, "Keep-Alive": true, "Upgrade": true, "Te": true,
	"Trailer": true, "Accept": true, "Accept-Encoding": true, "Forwarded": true, "Origin": true, "Referer": true,
	"Traceparent": true, "Tracestate": true, "Baggage": true, "Www-Authenticate": true})

// MCPRequestHeaders are the request headers MCP's Streamable HTTP transport defines (2025-11-25 and
// 2026-07-28), spelled as the spec spells them: the one list the header rules check against. No
// upstream header setting may name one (reservedHeaders), the operator may not strip one
// (mcpHeaders), and a browser's preflight may send them (origin's CORS list).
var MCPRequestHeaders = []string{"Mcp-Session-Id", "Mcp-Protocol-Version", "Mcp-Method", "Mcp-Name", "Last-Event-ID"}

// MCPParamPrefix starts the Mcp-Param-{name} headers a 2026-07-28 client mirrors tool parameters
// into, in canonical form.
const MCPParamPrefix = "Mcp-Param-"

// withMCPHeaders adds MCPRequestHeaders, in canonical form, to m and returns it.
func withMCPHeaders(m map[string]bool) map[string]bool {
	for _, h := range MCPRequestHeaders {
		m[CanonicalHeader(h)] = true
	}
	return m
}

// parseHeaderName reads a setting naming a header the proxy sets on upstream requests: a valid token,
// and not one the proxy, the transport or MCP relies on. example is a header of the operator's own to
// suggest. A refused name is never shown: a value pasted as Name: value holds a token after the name
// (#466).
func parseHeaderName(val Value, example string) (string, error) {
	raw := val.Given.raw()
	want := "a header name such as Authorization or " + example
	h := textproto.CanonicalMIMEHeaderKey(strings.TrimSpace(raw))
	if !httpguts.ValidHeaderFieldName(h) {
		return "", refusedForm(val.Setting, whole, raw, want, "it is not a header name")
	}
	if shown := relied(CanonicalHeader(h)); shown != "" { // as the upstream may read it: X_Forwarded_For is X-Forwarded-For
		return "", refusedMeaning(val.Setting, whole, shown, want, "the proxy, the transport or MCP relies on it; use Authorization or a header of your own")
	}
	return h, nil
}

// relied is how a refusal names n, a canonical header the proxy, the transport or MCP relies on: by
// name when it is one of reservedHeaders, by its family otherwise, since what follows a prefix is the
// operator's text; "" when nothing relies on it.
func relied(n string) string {
	if reservedHeaders[n] {
		return n
	}
	for _, p := range []string{"X-Forwarded-", "Proxy-", "Sec-", "Access-Control-", MCPParamPrefix} {
		if strings.HasPrefix(n, p) {
			return "a header starting " + p
		}
	}
	return ""
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
// (ADR-0016 §4, §5, §7; ADR-0017 §3). Names are compared by CanonicalHeader, so X_Api_Key and
// X-Api-Key are one header.
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
	return a != "" && CanonicalHeader(a) == CanonicalHeader(b)
}

// CanonicalHeader is a header name as it reaches the upstream: `_` folded to `-`, because some
// upstream frameworks read the two alike (invariant 16; the oauth2-proxy CVE-2025-64484 bypass),
// then canonicalized (textproto.CanonicalMIMEHeaderKey). Every comparison of a header name the
// proxy sets, strips or reserves uses it, in config and in the relay alike.
func CanonicalHeader(name string) string {
	return textproto.CanonicalMIMEHeaderKey(strings.ReplaceAll(name, "_", "-"))
}
