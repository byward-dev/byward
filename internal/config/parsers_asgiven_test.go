package config

import (
	"errors"
	"strings"
	"testing"
	"time"
)

// Every parser names the setting of the Value it is given as the operator gave it (#623): each of its
// refusals of a value's form or meaning goes through refusedForm, refusedMeaning or listsNothing with
// that Value, never a Setting or a Value rebuilt without its source. Each row is run by flag and, as
// its control, by env; a parser with several refusals has a row for each.
func TestEveryParserNamesItsSettingAsGiven(t *testing.T) {
	one := func(f func(Value) error) func(Value) error { return f }
	list := func(f func(Value) []error) func(Value) error {
		return func(v Value) error { return errors.Join(f(v)...) }
	}
	// says holds a literal fragment of each row's refusal, by row name, so the row reaches its own
	// refusal of the parser, not an earlier one that names the setting as well.
	says := map[string]string{
		"a boolean":                                            "it is neither true nor false",
		"a word":                                               "want off or entra; got a value (5 characters, not shown): it is not one of them",
		"a duration that does not parse":                       "it is not a duration",
		"a duration out of range":                              "got 1h0m0s: it is out of range",
		"a stream idle timeout":                                "want a duration of at least 1m",
		"a header timeout":                                     "want a duration from 1s to 1h",
		"a number that is not whole":                           "it is not a whole number",
		"a number too large to read":                           "(20 characters, not shown): it is out of range",
		"a number out of range":                                "got 20000: it is out of range",
		"wording with a control character":                     "it has a control or formatting character",
		"wording too long":                                     "it is too long",
		"a scope":                                              "want one scope token",
		"a list of none":                                       "got a list of none",
		"a tenant":                                             "want the tenant ID",
		"an Entra client ID":                                   "want the application (client) ID",
		"a key algorithm":                                      "want PS256 or RS256",
		"a claim name":                                         "it is blank or has white space at an end",
		"a gate claim the token always holds":                  "it is a claim of the sign-in itself",
		"a secret expiry":                                      "it is neither",
		"an issuer that is no URL":                             "it has a scheme other than http or https",
		"an issuer on http elsewhere":                          "an issuer is http only on a loopback host",
		"an OIDC scope":                                        "want a scope such as openid or email",
		"an On-Behalf-Of scope list of none":                   "got a list of none",
		"a sign-in scope for On-Behalf-Of":                     "it is a sign-in scope",
		"an On-Behalf-Of scope that is no URI":                 "it is not a scope URI",
		"On-Behalf-Of scopes for two APIs":                     "they are for different APIs",
		"assertion claims given empty":                         "want claims from roles, groups, email or name, or none; got nothing",
		"assertion claims in upper case":                       "give none in lower case",
		"assertion claims with none beside one":                "none stands alone",
		"an unknown assertion claim":                           "(5 characters, not shown): it is not one of them",
		"a client denylist entry":                              "it is a CIMD client ID with a user name or password",
		"a CIMD host":                                          "it has a character no host name holds at position 2",
		"a header line":                                        "as a header line does",
		"a header name with a space":                           "it is not a header name",
		"a header MCP relies on":                               "the proxy, the transport or MCP relies on it",
		"a public URL that is no URL":                          "want an absolute http(s) URL",
		"a public host:port the Host allow-list refuses":       "its host:port has a label that starts or ends with a hyphen",
		"an upstream host with a character no host name holds": "want an absolute http(s) URL such as http://127.0.0.1:9000/mcp; got a value (14 characters, not shown): its host has a character",
		"a public URL ending in a number":                      "ends in a number, so browsers refuse it",
		"a public URL with an IPv6 address as browsers do not write it": "its IPv6 address is not in the form browsers write it",
		"a public URL in upper case":                                    "its host name has upper-case letters",
		"a public URL with its scheme's default port":                   "its port 443 is https's default, which browsers drop",
		"a public URL ending in /":                                      "got a path that is empty or ends in /",
		"a public URL with a query":                                     "got a query or fragment, not shown",
		"a public URL on http elsewhere":                                "give https, or a loopback host",
		"a resource documentation URL":                                  "want an absolute http(s) URL such as https://docs.example.com/mcp",
		"an upstream URL":                                               "want an absolute http(s) URL such as http://127.0.0.1:9000/mcp",
		"a rate limit that is not endpoint=per-minute":                  "it is not endpoint=per-minute for one of the endpoints",
		"a rate limit too large to read":                                "its limit is out of range",
		"a rate limit that is not whole":                                "its limit is not a whole number",
		"a rate limit out of range":                                     "the limit is out of range",
		"a proxy that is no address":                                    "it is neither a CIDR nor an IP address",
		"a proxy IPv4-mapped prefix too short":                          "it is an IPv4-mapped prefix shorter than /96",
		"a link-local proxy":                                            "it is link-local",
		"a proxy with a zone":                                           "it has an IPv6 zone",
		"an origin":                                                     "it has no scheme such as https://",
		"an allowed host":                                               `it holds a "/" or a space`,
		"an allowed host browsers read as another IPv4 address":         "its host is not an IPv4 address in dotted decimal",
		"a listen address":                                              "it is not host:port",
		"an upstream command":                                           "want a JSON array of strings",
		"a stripped header family":                                      "it has a *",
		"a stripped header line":                                        "as a header line does",
		"a stripped header that is no name":                             "it is not a header name",
		"a stripped header MCP needs":                                   "got entry 1 of 1, Mcp-Session-Id: MCP needs it at the upstream",
		"a stripped MCP parameter header":                               "a header starting " + MCPParamPrefix + ": MCP needs it at the upstream",
		"a stripped trace header":                                       "with tracing on, the proxy sets it",
	}
	for _, tc := range []struct {
		name, setting, raw string
		parse              func(Value) error
	}{
		{"a boolean", "cimd", "maybe", one(func(v Value) error { _, err := parseBool(v); return err })},
		{"a word", "app-tokens", "maybe", one(func(v Value) error { _, err := parseWord(v, "off", "entra"); return err })},
		{"a duration that does not parse", "refresh-grace", "soon", one(func(v Value) error {
			_, err := parseDuration(v, "a duration", func(time.Duration) bool { return true })
			return err
		})},
		{"a duration out of range", "refresh-grace", "1h", one(func(v Value) error {
			_, err := parseDuration(v, "a duration", func(d time.Duration) bool { return d < time.Minute })
			return err
		})},
		{"a stream idle timeout", "stdio-stream-idle-timeout", "soon", one(func(v Value) error { _, err := parseStreamIdleTimeout(v); return err })},
		{"a header timeout", "upstream-header-timeout", "soon", one(func(v Value) error { _, err := parseHeaderTimeout(v); return err })},
		{"a number that is not whole", "stdio-max-processes", "x", one(func(v Value) error { _, err := parseWholeNumber(v, 1, 10000); return err })},
		{"a number too large to read", "stdio-max-processes", "99999999999999999999", one(func(v Value) error { _, err := parseWholeNumber(v, 1, 10000); return err })},
		{"a number out of range", "stdio-max-processes", "20000", one(func(v Value) error { _, err := parseWholeNumber(v, 1, 10000); return err })},
		{"wording with a control character", "operator-name", "a\x01b", one(func(v Value) error { _, err := parseWording(v, 80); return err })},
		{"wording too long", "operator-name", strings.Repeat("a", 81), one(func(v Value) error { _, err := parseWording(v, 80); return err })},
		{"a scope", "scope", "a b", one(func(v Value) error { _, err := parseScope(v); return err })},
		{"a list of none", "app-roles", ",", list(func(v Value) []error { _, errs := parseChecked(v, appRoleValues); return errs })},
		{"a tenant", "entra-tenant", "nope", one(func(v Value) error { _, err := parseTenant(v); return err })},
		{"an Entra client ID", "entra-client-id", "nope", one(func(v Value) error { _, err := parseEntraClientID(v); return err })},
		{"a key algorithm", "oidc-client-key-alg", "XX256", one(func(v Value) error { _, err := parseKeyAlg(v); return err })},
		{"a claim name", "oidc-subject-claim", " sub", one(func(v Value) error { _, err := parseClaimName(v, "sub"); return err })},
		{"a gate claim the token always holds", "oidc-roles-claim", "aud", one(func(v Value) error { _, err := parseGateClaimName(v, "roles"); return err })},
		{"a secret expiry", "entra-client-secret-expires-at", "soon", one(func(v Value) error { _, err := parseSecretExpiry(v); return err })},
		{"an issuer that is no URL", "oidc-issuer", "ftp://sso.example.com", one(func(v Value) error { _, err := parseIssuer(v); return err })},
		{"an issuer on http elsewhere", "oidc-issuer", "http://sso.example.com", one(func(v Value) error { _, err := parseIssuer(v); return err })},
		{"an OIDC scope", "oidc-scopes", `open\id`, list(func(v Value) []error { _, errs := parseChecked(v, oidcScopeEntries); return errs })},
		{"an On-Behalf-Of scope list of none", "obo-scopes", " ", list(func(v Value) []error { _, errs := parseOBOScopes(v); return errs })},
		{"a sign-in scope for On-Behalf-Of", "obo-scopes", "openid", list(func(v Value) []error { _, errs := parseOBOScopes(v); return errs })},
		{"an On-Behalf-Of scope that is no URI", "obo-scopes", "nope", list(func(v Value) []error { _, errs := parseOBOScopes(v); return errs })},
		{"On-Behalf-Of scopes for two APIs", "obo-scopes", "api://a/x api://b/y", list(func(v Value) []error { _, errs := parseOBOScopes(v); return errs })},
		{"assertion claims given empty", "assertion-claims", "", list(func(v Value) []error { _, errs := parseAssertionClaims(v); return errs })},
		{"assertion claims in upper case", "assertion-claims", "None", list(func(v Value) []error { _, errs := parseAssertionClaims(v); return errs })},
		{"assertion claims with none beside one", "assertion-claims", "none,roles", list(func(v Value) []error { _, errs := parseAssertionClaims(v); return errs })},
		{"an unknown assertion claim", "assertion-claims", "bogus", list(func(v Value) []error { _, errs := parseAssertionClaims(v); return errs })},
		{"a client denylist entry", "client-denylist", "https://user:pw@app.example/", list(func(v Value) []error { _, errs := parseChecked(v, denylistEntries); return errs })},
		{"a CIMD host", "cimd-trusted-hosts", "a b", list(func(v Value) []error { _, errs := parseCIMDHosts(v); return errs })},
		{"a header line", "assertion-header", "X-A: b", one(func(v Value) error { _, err := parseHeaderName(v); return err })},
		{"a header name with a space", "assertion-header", "X A", one(func(v Value) error { _, err := parseHeaderName(v); return err })},
		{"a header MCP relies on", "assertion-header", "Mcp-Session-Id", one(func(v Value) error { _, err := parseHeaderName(v); return err })},
		{"a public URL that is no URL", "public-url", "ftp://mcp.example.com/mcp", one(func(v Value) error { _, err := parsePublicURL(v); return err })},
		{"a public host:port the Host allow-list refuses", "public-url", "https://-a.example/mcp", one(func(v Value) error { _, err := parsePublicURL(v); return err })},
		{"a public URL ending in a number", "public-url", "https://mcp.10/mcp", one(func(v Value) error { _, err := parsePublicURL(v); return err })},
		{"a public URL with an IPv6 address as browsers do not write it", "public-url", "https://[2001:DB8::1]/mcp", one(func(v Value) error { _, err := parsePublicURL(v); return err })},
		{"a public URL in upper case", "public-url", "https://MCP.example.com/mcp", one(func(v Value) error { _, err := parsePublicURL(v); return err })},
		{"a public URL with its scheme's default port", "public-url", "https://mcp.example.com:443/mcp", one(func(v Value) error { _, err := parsePublicURL(v); return err })},
		{"a public URL ending in /", "public-url", "https://mcp.example.com/", one(func(v Value) error { _, err := parsePublicURL(v); return err })},
		{"a public URL with a query", "public-url", "https://mcp.example.com/mcp?x=1", one(func(v Value) error { _, err := parsePublicURL(v); return err })},
		{"a public URL on http elsewhere", "public-url", "http://mcp.example.com/mcp", one(func(v Value) error { _, err := parsePublicURL(v); return err })},
		{"a resource documentation URL", "resource-documentation", "ftp://docs.example.com", one(func(v Value) error { _, err := parseResourceDocumentation(v); return err })},
		{"an upstream URL", "upstream-url", "ftp://u/mcp", one(func(v Value) error { _, err := parseUpstreamURL(v); return err })},
		{"an upstream host with a character no host name holds", "upstream-url", "http://a*b/mcp", one(func(v Value) error { _, err := parseUpstreamURL(v); return err })},
		{"a rate limit that is not endpoint=per-minute", "oauth-rate-limits", "nope", list(func(v Value) []error { _, errs := parseRateLimits(v); return errs })},
		{"a rate limit too large to read", "oauth-rate-limits", "token=99999999999999999999", list(func(v Value) []error { _, errs := parseRateLimits(v); return errs })},
		{"a rate limit that is not whole", "oauth-rate-limits", "token=x", list(func(v Value) []error { _, errs := parseRateLimits(v); return errs })},
		{"a rate limit out of range", "oauth-rate-limits", "token=0", list(func(v Value) []error { _, errs := parseRateLimits(v); return errs })},
		{"a proxy that is no address", "trusted-proxies", "nope", one(func(v Value) error { _, err := parseProxies(v); return err })},
		{"a proxy IPv4-mapped prefix too short", "trusted-proxies", "::ffff:10.0.0.0/90", one(func(v Value) error { _, err := parseProxies(v); return err })},
		{"a link-local proxy", "trusted-proxies", "fe80::1", one(func(v Value) error { _, err := parseProxies(v); return err })},
		{"a proxy with a zone", "trusted-proxies", "2001:db8::1%eth0", one(func(v Value) error { _, err := parseProxies(v); return err })},
		{"an origin", "allowed-origins", "nope", list(func(v Value) []error { _, errs := parseOrigins(v); return errs })},
		{"an allowed host", "allowed-hosts", "a b", list(func(v Value) []error { _, errs := parseAllowedHosts(v); return errs })},
		{"an allowed host browsers read as another IPv4 address", "allowed-hosts", "127.1", list(func(v Value) []error { _, errs := parseAllowedHosts(v); return errs })},
		{"a listen address", "listen", "nope", one(func(v Value) error { _, err := parseListen(v, "host:port"); return err })},
		{"an upstream command", "upstream-command", "[]", one(func(v Value) error { _, err := parseUpstreamCommand(v, nil); return err })},
		{"a stripped header family", "upstream-strip-headers", "X-*", list(func(v Value) []error { _, errs := parseStripHeaders(v); return errs })},
		{"a stripped header line", "upstream-strip-headers", "X-A: b", list(func(v Value) []error { _, errs := parseStripHeaders(v); return errs })},
		{"a stripped header that is no name", "upstream-strip-headers", "X A", list(func(v Value) []error { _, errs := parseStripHeaders(v); return errs })},
		{"a stripped header MCP needs", "upstream-strip-headers", "Mcp-Session-Id", list(func(v Value) []error { _, errs := parseStripHeaders(v); return errs })},
		{"a stripped MCP parameter header", "upstream-strip-headers", MCPParamPrefix + "x", list(func(v Value) []error { _, errs := parseStripHeaders(v); return errs })},
		{"a stripped trace header", "upstream-strip-headers", "traceparent", list(func(v Value) []error { _, errs := parseStripHeaders(v); return errs })},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, fragment := lookup(tc.setting), says[tc.name]
			if fragment == "" {
				t.Fatalf("no fragment of the refusal for %q: add it to says", tc.name)
			}
			for _, given := range []struct {
				source Source
				want   string
			}{{SourceEnv, s.Env() + ": "}, {SourceFlag, "--" + tc.setting + ": "}} {
				err := tc.parse(Value{Setting: s, Given: NewOpaque(tc.raw), Source: given.source})
				if err == nil || !strings.HasPrefix(err.Error(), given.want) || !strings.Contains(err.Error(), fragment) {
					t.Errorf("given by %s: err = %v, want it to start with %q and say %q", given.source, err, given.want, fragment)
				}
			}
		})
	}
}
