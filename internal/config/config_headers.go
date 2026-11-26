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

// headerExamples is each header setting's example of a header of the operator's own, which its
// refusals suggest.
var headerExamples = map[string]string{ //nolint:gosec // G101: header names an operator may use, not a credential
	"assertion-header": "X-Byward-Identity", "upstream-credential-header": "X-Api-Key",
	"obo-header": "X-Byward-Downstream-Token"}

// headerNameWant is what the header setting name wants, in every refusal of it. It panics on a setting
// without an example, which every test that loads the setting catches.
func headerNameWant(name string) string {
	example, ok := headerExamples[name]
	if !ok {
		panic("config: no header example for " + name)
	}
	return "a header name such as Authorization or " + example
}

// parseHeaderName reads a setting naming a header the proxy sets on upstream requests: a valid token,
// and not one the proxy, the transport or MCP relies on; its refusals suggest the setting's example
// (headerExamples). A refused name is never shown: a value pasted as Name: value holds a token after
// the name (#466).
func parseHeaderName(val Value) (string, error) {
	raw := val.Given.raw()
	want := headerNameWant(val.Setting.Name)
	h := textproto.CanonicalMIMEHeaderKey(strings.TrimSpace(raw))
	switch {
	case strings.Contains(raw, ":"):
		return "", refusedForm(val, whole, raw, want, headerLineReason)
	case !httpguts.ValidHeaderFieldName(h):
		return "", refusedForm(val, whole, raw, want, "it is not a header name")
	}
	if shown := relied(CanonicalHeader(h)); shown != "" { // as the upstream may read it: X_Forwarded_For is X-Forwarded-For
		return "", refusedMeaning(val, whole, shown, want, "the proxy, the transport or MCP relies on it; use Authorization or a header of your own")
	}
	return h, nil
}

// headerLineReason is why a header name holding a ":" is refused: it is a header line, Name: value,
// pasted whole, and what follows the name is often a credential (#466).
const headerLineReason = `it holds a ":", as a header line does: give only the header's name, the part before the ":"`

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

// suchAs is ", such as <example>", the header setting name's example, for a clash's advice, or nothing
// when the example is the very header that clashes (clashing), which the advice would point back at.
func suchAs(name, clashing string) string {
	if example := headerExamples[name]; !sameHeader(example, clashing) {
		return ", such as " + example
	}
	return ""
}

// headerClashes refuses two purposes in one header: the identity assertion, the operator's
// upstream credential, the On-Behalf-Of token and the plain identity headers each have their own
// (ADR-0016 §4, §5, §7; ADR-0017 §3). Names are compared by CanonicalHeader, so X_Api_Key and
// X-Api-Key are one header.
func (c *Config) headerClashes() []error {
	var errs []error
	assertionHeaderName, credentialHeaderName := c.Values.NameAsGiven("assertion-header"), c.Values.NameAsGiven("upstream-credential-header")
	if c.UpstreamCredentialHeader != "" && sameHeader(c.UpstreamCredentialHeader, c.AssertionHeader) {
		// The header is not shown: an accepted name can be any token.
		errs = append(errs, errorf("%s and %s name the same header, but the credential and the identity assertion never share a header (ADR-0016 §7): set %s to a header of your own%s, and verify the assertion there",
			credentialHeaderName, assertionHeaderName, assertionHeaderName, suchAs("assertion-header", c.AssertionHeader)))
	}
	for _, u := range []struct{ name, header string }{{"assertion-header", c.AssertionHeader},
		{"upstream-credential-header", c.UpstreamCredentialHeader}, {"obo-header", c.OBOHeader}} {
		for _, plain := range IdentityHeaderNames {
			if sameHeader(u.header, plain) { // shown by the fixed name it matches, never as given
				errs = append(errs, refusedMeaning(c.Values.valueOf(u.name), whole, plain, headerNameWant(u.name),
					"it is one of the plain identity headers the proxy sets (docs/how-to/plain-identity-headers.md); use another header"))
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
