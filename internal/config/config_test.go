package config

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/byward-dev/byward/internal/logging"
)

// base is the Entra quickstart: the only settings an operator must set (ADR-0020 §8).
var base = []string{
	"BYWARD_PUBLIC_URL=https://mcp.example.com/mcp",
	"BYWARD_UPSTREAM_URL=http://upstream:9000/mcp",
	"BYWARD_ENTRA_TENANT=00000000-0000-0000-0000-000000000001",
	"BYWARD_ENTRA_CLIENT_ID=00000000-0000-0000-0000-000000000002",
	"BYWARD_ENTRA_CLIENT_SECRET_FILE=/run/secrets/entra",
}

// baseFiles serves the secret file named in base.
func baseFiles(p string) ([]byte, error) {
	if p == "/run/secrets/entra" {
		return []byte("s3cret-entra\n"), nil
	}
	return nil, os.ErrNotExist
}

func isConfigError(err error) bool {
	var ce *configError
	return errors.As(err, &ce)
}

func load(t *testing.T, args []string, env ...string) (*Config, error) {
	t.Helper()
	c, _, err := Load(args, append(append([]string{}, base...), env...), baseFiles)
	return c, err
}

func TestDefaults(t *testing.T) {
	c, err := load(t, nil)
	if err != nil {
		t.Fatal(err)
	}
	if c.Listen != "127.0.0.1:8080" || c.LogFormat != "json" || c.Scope != "mcp" || c.Dev {
		t.Fatalf("unexpected defaults: %+v", c)
	}
	if c.Issuer() != "https://mcp.example.com" {
		t.Fatalf("issuer = %q", c.Issuer())
	}
}

func TestFlagBeatsEnvBeatsDefault(t *testing.T) {
	c, err := load(t, []string{"--listen", "0.0.0.0:9"}, "BYWARD_LISTEN=127.0.0.1:7", "BYWARD_LOG_FORMAT=text")
	if err != nil {
		t.Fatal(err)
	}
	if c.Listen != "0.0.0.0:9" || c.LogFormat != "text" {
		t.Fatalf("listen=%q log=%q", c.Listen, c.LogFormat)
	}
	src := map[string]Source{}
	for _, v := range c.Values.Effective() {
		src[v.Setting.Name] = v.Source
	}
	if src["listen"] != SourceFlag || src["log-format"] != SourceEnv || src["scope"] != SourceDefault || src["public-url"] != SourceEnv {
		t.Fatalf("sources: %v", src)
	}
}

func TestUnknownEnvSuggestsSetting(t *testing.T) {
	_, err := load(t, nil, "BYWARD_PUBLC_URL=x")
	if !isConfigError(err) || !strings.Contains(err.Error(), "did you mean BYWARD_PUBLIC_URL?") {
		t.Fatalf("err = %v", err)
	}
}

func TestUnknownEnvFarFromAnySettingHasNoSuggestion(t *testing.T) {
	_, err := load(t, nil, "BYWARD_ZZZZZZZZZZZZZZ=x")
	if !isConfigError(err) || strings.Contains(err.Error(), "did you mean") {
		t.Fatalf("err = %v", err)
	}
}

// scopeRefused is BYWARD_SCOPE's refusal of a value of n characters for a character no scope token holds.
func scopeRefused(n int) string {
	return "BYWARD_SCOPE: want one scope token, such as mcp; got a value (" + strconv.Itoa(n) + " characters, not shown): " + scopeCharsRefused
}

// scopeCharsRefused is the reason, written out: the test pins the literal, never the code's constant.
const scopeCharsRefused = "it has a character a scope token cannot hold: white space, a double quote, a backslash or one that is not printable ASCII"

func TestInvalidSettingsAreRejectedNamingTheSetting(t *testing.T) {
	cases := []struct {
		name, env, want string
	}{
		{"required", "BYWARD_PUBLIC_URL=", "BYWARD_PUBLIC_URL is required"},
		{"http loopback without dev", "BYWARD_PUBLIC_URL=http://127.0.0.1:8080/mcp", "needs --dev"},
		{"log format", "BYWARD_LOG_FORMAT=xml", "BYWARD_LOG_FORMAT: want json or text; got a value (3 characters, not shown): it is not one of them"},
		{"two scopes", "BYWARD_SCOPE=a b", scopeRefused(3)},
		{"a scope with a tab", "BYWARD_SCOPE=mcp\tx", scopeRefused(5)},
		{"a scope that is not ASCII", "BYWARD_SCOPE=mcpü", scopeRefused(4)},
		{"a scope with DEL", "BYWARD_SCOPE=mcp\x7f", scopeRefused(4)},
		{"a scope with a quote", `BYWARD_SCOPE=a"b`, scopeRefused(3)},
		{"a scope with a backslash", `BYWARD_SCOPE=a\b`, scopeRefused(3)},
		{"operator name too long", "BYWARD_OPERATOR_NAME=" + strings.Repeat("é", 81), "BYWARD_OPERATOR_NAME: want text of at most 80 characters, without control or formatting characters; got a value (81 characters, not shown): it is too long"},
		{"operator name with a newline", "BYWARD_OPERATOR_NAME=a\nb", "BYWARD_OPERATOR_NAME: want text of at most 80 characters, without control or formatting characters; got a value (3 characters, not shown): it has a control or formatting character"},
		{"operator name with a bidi override", "BYWARD_OPERATOR_NAME=Evil \u202eTI", "BYWARD_OPERATOR_NAME: want text of at most 80 characters, without control or formatting characters; got a value (8 characters, not shown): it has a control or formatting character"},
		{"scope description with a bidi override", "BYWARD_SCOPE_DESCRIPTION=Read \u202edashboards", "BYWARD_SCOPE_DESCRIPTION: want text of at most 200 characters, without control or formatting characters; got a value (16 characters, not shown): it has a control or formatting character"},
		{"scope description too long", "BYWARD_SCOPE_DESCRIPTION=" + strings.Repeat("x", 201), "BYWARD_SCOPE_DESCRIPTION: want text of at most 200 characters, without control or formatting characters; got a value (201 characters, not shown): it is too long"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := load(t, nil, c.env)
			if !isConfigError(err) || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("want a config error containing %q, got %v", c.want, err)
			}
		})
	}
}

// The refusals of the URL and host settings, pinned whole (ADR-0031 §1): each names its setting and
// why, and a value refused for its form by its place and length, never the value. The texts below are this test's own literals,
// never the code's constants, so a changed message fails here.
const (
	wantPublicURL     = `BYWARD_PUBLIC_URL: want the MCP endpoint's URL such as https://mcp.example.com/mcp; got a value `
	wantPublicAsURL   = `BYWARD_PUBLIC_URL: want an absolute http(s) URL such as https://mcp.example.com/mcp; got a value `
	wantUpstreamURL   = `BYWARD_UPSTREAM_URL: want an absolute http(s) URL such as http://127.0.0.1:9000/mcp; got a value `
	orUpstreamCommand = ` (or BYWARD_UPSTREAM_COMMAND, or a command after --)`
	wantHosts         = `BYWARD_ALLOWED_HOSTS: want a host[:port] such as mcp.example.com or 127.0.0.1:8080; got entry 1 of 1 `
	wantOrigins       = `BYWARD_ALLOWED_ORIGINS: want an origin (scheme://host[:port]) such as https://app.example; got entry 1 of 1 `
	wantDenylist      = `BYWARD_CLIENT_DENYLIST: want a CIMD client ID (an https URL) or a host name such as app.example; got entry 1 of 1 `
	wantTrusted       = `BYWARD_CIMD_TRUSTED_HOSTS: want a host name such as claude.ai; got entry 1 of 1 `
	wantAllowed       = `BYWARD_CIMD_ALLOWED_HOSTS: want a host name such as claude.ai; got entry 1 of 1 `
	rulePort          = `has a port that is not a number from 1 to 65535 without a sign or leading zero`
	ruleForms         = `give host, host:port, an IPv6 address, [IPv6] or [IPv6]:port, with a port from 1 to 65535 and no IPv6 zone`
	ruleNotASCII      = `holds a character that is not ASCII; give an internationalized host in its ASCII (xn--) form, which browsers and MCP clients send`
	ruleReadAsIPv4    = `ends in a number, so a browser reads it as an IPv4 address: one it also reaches by other spellings (127.1 and 0x7f000001 are 127.0.0.1) that no entry can match, or none at all; give a host name`
	ruleIPHost        = `is an IP address, which this list never names: an address is also reached by other spellings (127.1 and 0x7f000001 are 127.0.0.1) that no entry can match; give a host name`
	ruleEndsInNumber  = `is not an IPv4 address but ends in a number, so browsers refuse it`
	ruleDottedDecimal = `is not an IPv4 address in dotted decimal, the only form browsers send; browsers read it as `
	ruleNameChar      = "has a character no host name holds at position "
	ruleNameChars     = `; a host name has only letters, digits, - . and _`
	ruleZone          = `has an IPv6 zone that is not an interface name: 1 to 15 bytes, not . or .., without white space, a control character, a slash or a colon`
	ruleLabel         = `has an empty label (a leading, double or trailing dot); drop the extra dot`
	ruleEdgeHyphen    = `has a label that starts or ends with a hyphen; a label starts and ends with a letter or a digit`
)

func TestAURLOrHostRefusedForItsFormSaysWhereAndWhyNeverWhat(t *testing.T) {
	cases := []struct {
		name, env, want string
	}{
		{"trailing slash", "BYWARD_PUBLIC_URL=https://mcp.example.com/mcp/", `BYWARD_PUBLIC_URL: want the MCP endpoint's path without a trailing slash, such as https://mcp.example.com/mcp; got a path that is empty or ends in /: give the endpoint's path, without the trailing slash`},
		{"no path", "BYWARD_PUBLIC_URL=https://mcp.example.com", `BYWARD_PUBLIC_URL: want the MCP endpoint's path without a trailing slash, such as https://mcp.example.com/mcp; got a path that is empty or ends in /: give the endpoint's path, without the trailing slash`},
		{"origin with path", "BYWARD_ALLOWED_ORIGINS=https://a.example/path", wantOrigins + `(22 characters, not shown): it has a path`},
		{"documentation not a URL", "BYWARD_RESOURCE_DOCUMENTATION=javascript:x", `BYWARD_RESOURCE_DOCUMENTATION: want an absolute http(s) URL such as https://docs.example.com/mcp; got a value (12 characters, not shown): it has a scheme other than http or https`},
		{"query", "BYWARD_PUBLIC_URL=https://mcp.example.com/mcp?x=1", `BYWARD_PUBLIC_URL: want a URL without a query or fragment, such as https://mcp.example.com/mcp; got a query or fragment, not shown: remove it`},
		{"fragment", "BYWARD_PUBLIC_URL=https://mcp.example.com/mcp#f", `BYWARD_PUBLIC_URL: want a URL without a query or fragment, such as https://mcp.example.com/mcp; got a query or fragment, not shown: remove it`},
		{"http public", "BYWARD_PUBLIC_URL=http://mcp.example.com/mcp", `BYWARD_PUBLIC_URL: want https (http only on a loopback host, with --dev), such as https://mcp.example.com/mcp; got http: give https, or a loopback host`},
		// #344: the public host joins the public Host allow-list, so it follows the browser-matched host
		// name rule BYWARD_ALLOWED_HOSTS does (hostPort, ADR-0032 §3), in the same words.
		{"public host with a trailing dot", "BYWARD_PUBLIC_URL=https://mcp.example.com./mcp", wantPublicURL + `(28 characters, not shown): its host:port ` + ruleLabel},
		{"public host with a double dot", "BYWARD_PUBLIC_URL=https://a..b/mcp", wantPublicURL + `(16 characters, not shown): its host:port ` + ruleLabel},
		{"public host with a leading dot", "BYWARD_PUBLIC_URL=https://.mcp.example.com/mcp", wantPublicURL + `(28 characters, not shown): its host:port ` + ruleLabel},
		// A character no host name holds, beyond RFC 3986's sub-delimiters: the class P and O host name
		// is an allow-list (ADR-0032 §3).
		{"public host with a double quote", `BYWARD_PUBLIC_URL=https://se"kr/mcp`, wantPublicURL + `(17 characters, not shown): its host:port ` + ruleNameChar + `3` + ruleNameChars},
		// A character RFC 3986 and browsers allow in a host but no DNS name holds (ADR-0032 §3, D4): its
		// place is named, never the character.
		{"public host with a wildcard", "BYWARD_PUBLIC_URL=https://a*b/mcp", wantPublicURL + `(15 characters, not shown): its host:port ` + ruleNameChar + `2` + ruleNameChars},
		{"public host with a tilde", "BYWARD_PUBLIC_URL=https://s3cret~tok.example/mcp", wantPublicURL + `(30 characters, not shown): its host:port ` + ruleNameChar + `7` + ruleNameChars},
		{"public host made only of a hyphen", "BYWARD_PUBLIC_URL=https://-/mcp", wantPublicURL + `(13 characters, not shown): its host:port ` + ruleEdgeHyphen},
		{"public host with leading hyphen", "BYWARD_PUBLIC_URL=https://-a.example/mcp", wantPublicURL + `(22 characters, not shown): its host:port ` + ruleEdgeHyphen},
		{"public host with trailing hyphen", "BYWARD_PUBLIC_URL=https://a-.example/mcp", wantPublicURL + `(22 characters, not shown): its host:port ` + ruleEdgeHyphen},
		{"public host with inner label leading hyphen", "BYWARD_PUBLIC_URL=https://a.-b.example/mcp", wantPublicURL + `(24 characters, not shown): its host:port ` + ruleEdgeHyphen},
		// The upstream's host too, which url.Parse and Go's dialer would take (ADR-0032 §3, D4).
		{"upstream host with a tilde", "BYWARD_UPSTREAM_URL=http://s3cret~tok:8000/mcp", wantUpstreamURL + `(26 characters, not shown): its host ` + ruleNameChar + `7` + ruleNameChars + orUpstreamCommand},
		{"upstream host with a dollar sign", "BYWARD_UPSTREAM_URL=http://my$mcp:8000/mcp", wantUpstreamURL + `(22 characters, not shown): its host ` + ruleNameChar + `3` + ruleNameChars + orUpstreamCommand},
		{"upstream host with a sub-delimiter after a valid label", "BYWARD_UPSTREAM_URL=http://mcp.a=b/mcp", wantUpstreamURL + `(18 characters, not shown): its host ` + ruleNameChar + `6` + ruleNameChars + orUpstreamCommand},
		{"upstream host with a less-than sign", "BYWARD_UPSTREAM_URL=http://se<kr/mcp", wantUpstreamURL + `(16 characters, not shown): its host ` + ruleNameChar + `3` + ruleNameChars + orUpstreamCommand},
		{"upstream host not in ASCII", "BYWARD_UPSTREAM_URL=http://ésekr:8000/mcp", wantUpstreamURL + `(21 characters, not shown): its host ` + ruleNotASCII + orUpstreamCommand},
		// A browser lower-cases a host name, and byward does not rewrite it: the issuer and the IdP
		// redirect URI are built from it as written (#472).
		{"public host name in upper case", "BYWARD_PUBLIC_URL=https://MCP.Example.com/mcp", `BYWARD_PUBLIC_URL: want the MCP endpoint's URL with its host as browsers write it, such as https://mcp.example.com/mcp; got a value (27 characters, not shown): its host name has upper-case letters; write it in lower case, as browsers do`},
		// A URL cannot carry an IPv6 zone, with a port after it too (#644; without one: urlzone_test).
		{"public URL with an IPv6 zone and a port", "BYWARD_PUBLIC_URL=https://[fe80::1%25eth0]:8443/mcp", `BYWARD_PUBLIC_URL: want an absolute http(s) URL such as https://mcp.example.com/mcp; got a value (33 characters, not shown): it has an IPv6 zone, which a URL cannot carry; give the address without its %zone`},
		// Browsers and MCP clients send IDN hosts in ASCII (xn--) form, so a Unicode host never matches.
		{"unicode public host with a port", "BYWARD_PUBLIC_URL=https://bücher.example:8443/mcp", wantPublicURL + `(31 characters, not shown): its host:port ` + ruleNotASCII},
		{"unicode public host", "BYWARD_PUBLIC_URL=https://bücher.example/mcp", wantPublicURL + `(26 characters, not shown): its host:port ` + ruleNotASCII},
		{"escaped unicode public host", "BYWARD_PUBLIC_URL=https://b%C3%BCcher.example/mcp", wantPublicURL + `(31 characters, not shown): its host:port ` + ruleNotASCII},
		{"unicode allowed origin", "BYWARD_ALLOWED_ORIGINS=https://bücher.example", wantOrigins + `(22 characters, not shown): its host:port ` + ruleNotASCII},
		{"origin with an empty label", "BYWARD_ALLOWED_ORIGINS=https://a..b", wantOrigins + `(12 characters, not shown): its host:port ` + ruleLabel},
		{"origin with a leading dot", "BYWARD_ALLOWED_ORIGINS=https://.app.example.com", wantOrigins + `(24 characters, not shown): its host:port ` + ruleLabel},
		{"origin with a trailing dot", "BYWARD_ALLOWED_ORIGINS=https://app.example.com.", wantOrigins + `(24 characters, not shown): its host:port ` + ruleLabel},
		{"origin with a shortened IPv4 address", "BYWARD_ALLOWED_ORIGINS=https://127.1", wantOrigins + `(13 characters, not shown): its host ` + ruleDottedDecimal + `127.0.0.1`},
		{"origin ending in an upper-case hex label", "BYWARD_ALLOWED_ORIGINS=https://192.168.0.0xFF", wantOrigins + `(22 characters, not shown): its host ` + ruleDottedDecimal + `192.168.0.255`},
		{"origin with an IPv4 part over 255", "BYWARD_ALLOWED_ORIGINS=https://10.0.0.999", wantOrigins + `(18 characters, not shown): its host ` + ruleEndsInNumber},
		{"origin with user info", "BYWARD_ALLOWED_ORIGINS=https://user@app.example.com", wantOrigins + `(28 characters, not shown): it holds a user name or password`},
		{"origin with an unclosed IPv6 bracket", "BYWARD_ALLOWED_ORIGINS=https://[::1", wantOrigins + `(12 characters, not shown): it has a "[" in its host without its "]"`},
		{"origin with white space", "BYWARD_ALLOWED_ORIGINS=https://a\u00a0b.example", wantOrigins + `(19 characters, not shown): it has white space, which a URL cannot hold; write a space in a path as %20`},
		{"origin with a control character", "BYWARD_ALLOWED_ORIGINS=https://a.example\x01", wantOrigins + `(18 characters, not shown): it has a control character, which a URL cannot hold`},
		{"origin ending in a hex label of every hex digit", "BYWARD_ALLOWED_ORIGINS=https://a.0x0123456789abcdef", wantOrigins + `(28 characters, not shown): its host ` + ruleEndsInNumber},
		{"origin ending in a bare 0", "BYWARD_ALLOWED_ORIGINS=https://a.0", wantOrigins + `(11 characters, not shown): its host ` + ruleEndsInNumber},
		{"origin ending in a bare 0x", "BYWARD_ALLOWED_ORIGINS=https://a.0x", wantOrigins + `(12 characters, not shown): its host ` + ruleEndsInNumber},
		{"origin ending in a label of every digit", "BYWARD_ALLOWED_ORIGINS=https://a.1234567890", wantOrigins + `(20 characters, not shown): its host ` + ruleEndsInNumber},
		{"origin with a shortened IPv4 address and a port", "BYWARD_ALLOWED_ORIGINS=http://127.1:8080", wantOrigins + `(17 characters, not shown): its host ` + ruleDottedDecimal + `127.0.0.1`},
		{"origin with a hex IPv4 label", "BYWARD_ALLOWED_ORIGINS=https://0x7f.0.0.1", wantOrigins + `(18 characters, not shown): its host ` + ruleDottedDecimal + `127.0.0.1`},
		{"origin with a fragment", "BYWARD_ALLOWED_ORIGINS=https://app.example.com#", wantOrigins + `(24 characters, not shown): it has a query or a fragment`},
		{"origin with an empty query", "BYWARD_ALLOWED_ORIGINS=https://app.example.com?", wantOrigins + `(24 characters, not shown): it has a query or a fragment`},
		{"unicode allowed host", "BYWARD_ALLOWED_HOSTS=bücher.example:8443", wantHosts + `(19 characters, not shown): it ` + ruleNotASCII},
		{"host with path", "BYWARD_ALLOWED_HOSTS=a.example/x", wantHosts + `(11 characters, not shown): it holds a "/" or a space; ` + ruleForms},
		{"host with space", "BYWARD_ALLOWED_HOSTS=a b", wantHosts + `(3 characters, not shown): it holds a "/" or a space; ` + ruleForms},
		{"bracketed host name", "BYWARD_ALLOWED_HOSTS=[mcp.internal.example]", wantHosts + `(22 characters, not shown): it has brackets that do not enclose an IPv6 address alone; ` + ruleForms},
		{"bracketed IPv4 with a port", "BYWARD_ALLOWED_HOSTS=[127.0.0.1]:8443", wantHosts + `(16 characters, not shown): it has brackets that do not enclose an IPv6 address alone; ` + ruleForms},
		// One ':' inside passes the brackets, as host.Parse's rule does; the host is then no IPv6 address.
		{"one colon in brackets", "BYWARD_ALLOWED_HOSTS=[a:b]:8443", wantHosts + `(10 characters, not shown): it is not an IPv6 address without a zone; ` + ruleForms},
		{"IPv6 with a zone", "BYWARD_ALLOWED_HOSTS=[fe80::1%eth0]:8443", wantHosts + `(19 characters, not shown): it is not an IPv6 address without a zone; ` + ruleForms},
		{"unclosed bracket", "BYWARD_ALLOWED_HOSTS=[::1", wantHosts + `(4 characters, not shown): it has brackets that do not enclose an IPv6 address alone; ` + ruleForms},
		{"name with a closing bracket", "BYWARD_ALLOWED_HOSTS=mcp.example]", wantHosts + `(12 characters, not shown): it has brackets that do not enclose an IPv6 address alone; ` + ruleForms},
		{"name with an opening bracket", "BYWARD_ALLOWED_HOSTS=mcp.example[", wantHosts + `(12 characters, not shown): it has brackets that do not enclose an IPv6 address alone; ` + ruleForms},
		{"name with user info", "BYWARD_ALLOWED_HOSTS=a@b", wantHosts + `(3 characters, not shown): it ` + ruleNameChar + `2` + ruleNameChars},
		{"name with a query", "BYWARD_ALLOWED_HOSTS=a?b", wantHosts + `(3 characters, not shown): it ` + ruleNameChar + `2` + ruleNameChars},
		{"name with a fragment", "BYWARD_ALLOWED_HOSTS=a#b", wantHosts + `(3 characters, not shown): it ` + ruleNameChar + `2` + ruleNameChars},
		{"name with a backslash", "BYWARD_ALLOWED_HOSTS=a\\b", wantHosts + `(3 characters, not shown): it ` + ruleNameChar + `2` + ruleNameChars},
		{"name with a semicolon", "BYWARD_ALLOWED_HOSTS=a;b", wantHosts + `(3 characters, not shown): it ` + ruleNameChar + `2` + ruleNameChars},
		{"name with a tab", "BYWARD_ALLOWED_HOSTS=a\tb", wantHosts + `(3 characters, not shown): it ` + ruleNameChar + `2` + ruleNameChars},
		{"name that is a wildcard", "BYWARD_ALLOWED_HOSTS=*", wantHosts + `(1 character, not shown): it ` + ruleNameChar + `1` + ruleNameChars},
		{"name with a port and a bad character", "BYWARD_ALLOWED_HOSTS=a*b:8080", wantHosts + `(8 characters, not shown): it ` + ruleNameChar + `2` + ruleNameChars},
		{"trailing dot", "BYWARD_ALLOWED_HOSTS=mcp.example.com.", wantHosts + `(16 characters, not shown): it ` + ruleLabel},
		{"trailing dot with a port", "BYWARD_ALLOWED_HOSTS=mcp.example.com.:8443", wantHosts + `(21 characters, not shown): it ` + ruleLabel},
		{"leading dot", "BYWARD_ALLOWED_HOSTS=.example.com", wantHosts + `(12 characters, not shown): it ` + ruleLabel},
		{"double dot", "BYWARD_ALLOWED_HOSTS=mcp..example.com:8443", wantHosts + `(21 characters, not shown): it ` + ruleLabel},
		// A label that starts or ends with a hyphen (#630), in the browser-matched settings' own words.
		{"allowed host label with a leading hyphen", "BYWARD_ALLOWED_HOSTS=mcp.-a.example:8443", wantHosts + `(19 characters, not shown): it ` + ruleEdgeHyphen},
		{"origin label with a trailing hyphen", "BYWARD_ALLOWED_ORIGINS=https://app-.example", wantOrigins + `(20 characters, not shown): its host:port ` + ruleEdgeHyphen},
		{"bracket then an empty port", "BYWARD_ALLOWED_HOSTS=[::1]:", wantHosts + `(6 characters, not shown): it ` + rulePort},
		{"bracket then junk", "BYWARD_ALLOWED_HOSTS=[::1]x", wantHosts + `(6 characters, not shown): it has brackets that do not enclose an IPv6 address alone; ` + ruleForms},
		{"bracket then digits without a colon", "BYWARD_ALLOWED_HOSTS=[::1]8080", wantHosts + `(9 characters, not shown): it has brackets that do not enclose an IPv6 address alone; ` + ruleForms},
		{"bracket then a junk port", "BYWARD_ALLOWED_HOSTS=[::1]:80a", wantHosts + `(9 characters, not shown): it ` + rulePort},
		// What follows the "]" is judged as a port, and what the brackets enclose as an address (#644).
		{"bracket then a port and a stray bracket", "BYWARD_ALLOWED_HOSTS=[::1]:80]", wantHosts + `(9 characters, not shown): it ` + rulePort},
		{"a bracket inside brackets", "BYWARD_ALLOWED_HOSTS=[a:[b]", wantHosts + `(6 characters, not shown): it is not an IPv6 address without a zone; ` + ruleForms},
		{"host then an empty port", "BYWARD_ALLOWED_HOSTS=localhost:", wantHosts + `(10 characters, not shown): it ` + rulePort},
		{"host then a junk port", "BYWARD_ALLOWED_HOSTS=localhost:abc", wantHosts + `(13 characters, not shown): it ` + rulePort},
		{"host then a signed port", "BYWARD_ALLOWED_HOSTS=localhost:+80", wantHosts + `(13 characters, not shown): it ` + rulePort},
		{"port 0", "BYWARD_ALLOWED_HOSTS=localhost:0", wantHosts + `(11 characters, not shown): it ` + rulePort},
		{"port over 65535", "BYWARD_ALLOWED_HOSTS=localhost:65536", wantHosts + `(15 characters, not shown): it ` + rulePort},
		{"port with a leading zero", "BYWARD_ALLOWED_HOSTS=localhost:080", wantHosts + `(13 characters, not shown): it ` + rulePort},
		{"bracketed port over 65535", "BYWARD_ALLOWED_HOSTS=[::1]:99999", wantHosts + `(11 characters, not shown): it ` + rulePort},
		{"a port without a host", "BYWARD_ALLOWED_HOSTS=:8080", wantHosts + `(5 characters, not shown): it has no host before its ":"; ` + ruleForms},
		{"bare IPv6 with a zone", "BYWARD_ALLOWED_HOSTS=fe80::1%eth0", wantHosts + `(12 characters, not shown): it is not an IPv6 address without a zone; ` + ruleForms},
		{"many colons, not IPv6", "BYWARD_ALLOWED_HOSTS=a:b:c", wantHosts + `(5 characters, not shown): it is not an IPv6 address without a zone; ` + ruleForms},
		{"cimd host with a scheme", "BYWARD_CIMD_TRUSTED_HOSTS=https://claude.ai", wantTrusted + `(17 characters, not shown): it ` + ruleNameChar + `6` + ruleNameChars},
		{"cimd host with a path", "BYWARD_CIMD_TRUSTED_HOSTS=claude.ai/oauth", wantTrusted + `(15 characters, not shown): it ` + ruleNameChar + `10` + ruleNameChars},
		{"cimd host with user info", "BYWARD_CIMD_ALLOWED_HOSTS=user@claude.example", wantAllowed + `(19 characters, not shown): it ` + ruleNameChar + `5` + ruleNameChars},
		// #344: names no client ID can carry, refused as in BYWARD_ALLOWED_HOSTS.
		{"cimd host with a query", "BYWARD_CIMD_ALLOWED_HOSTS=a?b.example", wantAllowed + `(11 characters, not shown): it ` + ruleNameChar + `2` + ruleNameChars},
		{"cimd host with a fragment", "BYWARD_CIMD_TRUSTED_HOSTS=a#b.example", wantTrusted + `(11 characters, not shown): it ` + ruleNameChar + `2` + ruleNameChars},
		{"cimd host with a semicolon", "BYWARD_CIMD_ALLOWED_HOSTS=a;b.example", wantAllowed + `(11 characters, not shown): it ` + ruleNameChar + `2` + ruleNameChars},
		{"cimd host with a trailing dot", "BYWARD_CIMD_TRUSTED_HOSTS=claude.ai.", wantTrusted + `(10 characters, not shown): it ` + ruleLabel},
		{"cimd host with a space", "BYWARD_CIMD_TRUSTED_HOSTS=claude .ai", wantTrusted + `(10 characters, not shown): it ` + ruleNameChar + `7` + ruleNameChars},
		{"cimd host with a port", "BYWARD_CIMD_ALLOWED_HOSTS=claude.ai:443", wantAllowed + `(13 characters, not shown): it ` + ruleNameChar + `10` + ruleNameChars},
		{"cimd wildcard host", "BYWARD_CIMD_TRUSTED_HOSTS=*.example.com", wantTrusted + `(13 characters, not shown): it ` + ruleNameChar + `1` + ruleNameChars},
		// The name rule comes first: "a*b" lacks a dot too, but a dot would not fix it.
		{"cimd host breaking the rule and without a dot", "BYWARD_CIMD_TRUSTED_HOSTS=a*b", wantTrusted + `(3 characters, not shown): it ` + ruleNameChar + `2` + ruleNameChars},
		{"cimd single-label host", "BYWARD_CIMD_TRUSTED_HOSTS=localhost", wantTrusted + `(9 characters, not shown): it has no dot; give a name with at least one dot`},
		{"cimd unicode host", "BYWARD_CIMD_TRUSTED_HOSTS=bücher.example", wantTrusted + `(14 characters, not shown): it ` + ruleNotASCII},
		// R6 and R5 (#524): an address is reached by spellings no entry matches (hostrule.golden pins the spellings).
		{"cimd trusted IPv4 address", "BYWARD_CIMD_TRUSTED_HOSTS=203.0.113.5", wantTrusted + `(11 characters, not shown): it ` + ruleIPHost},
		{"cimd allowed IPv6 address", "BYWARD_CIMD_ALLOWED_HOSTS=::1", wantAllowed + `(3 characters, not shown): it ` + ruleIPHost},
		{"cimd trusted short IPv4 address", "BYWARD_CIMD_TRUSTED_HOSTS=127.1", wantTrusted + `(5 characters, not shown): it ` + ruleReadAsIPv4},
		{"cimd allowed host ending in a number", "BYWARD_CIMD_ALLOWED_HOSTS=mcp.10", wantAllowed + `(6 characters, not shown): it ` + ruleReadAsIPv4},
		// Within the label rule, an empty label is named before an edge hyphen, as for every host
		// setting (nameReason).
		{"cimd host with an empty label and an edge hyphen", "BYWARD_CIMD_TRUSTED_HOSTS=-a..b.example", wantTrusted + `(13 characters, not shown): it ` + ruleLabel},
		// A host entry follows the CIMD host lists' rule (but may end in a dot), so an entry that could never match a
		// redirect host fails at load instead of denying nothing.
		{"client denylist http URL", "BYWARD_CLIENT_DENYLIST=http://app.example/client.json", wantDenylist + `(30 characters, not shown): it ` + ruleNameChar + `5` + ruleNameChars},
		{"client denylist double dot", "BYWARD_CLIENT_DENYLIST=a..b", wantDenylist + `(4 characters, not shown): it ` + ruleLabel},
		{"client denylist leading dot", "BYWARD_CLIENT_DENYLIST=.bad.example", wantDenylist + `(12 characters, not shown): it ` + ruleLabel},
		{"client denylist two trailing dots", "BYWARD_CLIENT_DENYLIST=app.example..", wantDenylist + `(13 characters, not shown): it ` + ruleLabel},
		{"client denylist inner tab", "BYWARD_CLIENT_DENYLIST=bad\tx.example", wantDenylist + `(13 characters, not shown): it ` + ruleNameChar + `4` + ruleNameChars},
		{"client denylist percent-encoding", "BYWARD_CLIENT_DENYLIST=%62ad.example", wantDenylist + `(13 characters, not shown): it ` + ruleNameChar + `1` + ruleNameChars},
		{"client denylist brackets", "BYWARD_CLIENT_DENYLIST=[bad].example", wantDenylist + `(13 characters, not shown): it ` + ruleNameChar + `1` + ruleNameChars},
		{"client denylist host with a port", "BYWARD_CLIENT_DENYLIST=app.example:443", wantDenylist + `(15 characters, not shown): it ` + ruleNameChar + `12` + ruleNameChars},
		{"client denylist single-label host among good ones", "BYWARD_CLIENT_DENYLIST=app.example,localhost", `BYWARD_CLIENT_DENYLIST: want a CIMD client ID (an https URL) or a host name such as app.example; got entry 2 of 2 (9 characters, not shown): it has no dot; give a name with at least one dot`},
		{"client denylist https without slashes", "BYWARD_CLIENT_DENYLIST=https:app.example", wantDenylist + `(17 characters, not shown): it ` + ruleNameChar + `6` + ruleNameChars},
		// R6 and R5: an IP address, or a name a browser reads as IPv4, is reached by spellings no entry
		// matches.
		{"client denylist IPv4 address", "BYWARD_CLIENT_DENYLIST=203.0.113.5", wantDenylist + `(11 characters, not shown): it ` + ruleIPHost},
		{"client denylist short IPv4 address", "BYWARD_CLIENT_DENYLIST=127.1", wantDenylist + `(5 characters, not shown): it ` + ruleReadAsIPv4},
		{"client denylist short IPv4 address with a trailing dot", "BYWARD_CLIENT_DENYLIST=127.1.", wantDenylist + `(6 characters, not shown): it ` + ruleReadAsIPv4},
		{"client denylist hex IPv4 address", "BYWARD_CLIENT_DENYLIST=127.0x1", wantDenylist + `(7 characters, not shown): it ` + ruleReadAsIPv4},
		{"client denylist host ending in an empty hex number", "BYWARD_CLIENT_DENYLIST=app.0x", wantDenylist + `(6 characters, not shown): it ` + ruleReadAsIPv4},
		{"client denylist host ending in every hex digit", "BYWARD_CLIENT_DENYLIST=a.0X0123456789abcdefABCDEF", wantDenylist + `(26 characters, not shown): it ` + ruleReadAsIPv4},
		{"client denylist host ending in every decimal digit", "BYWARD_CLIENT_DENYLIST=a.0123456789", wantDenylist + `(12 characters, not shown): it ` + ruleReadAsIPv4},
		{"client denylist unicode host with a trailing dot", "BYWARD_CLIENT_DENYLIST=bücher.example.", wantDenylist + `(15 characters, not shown): it ` + ruleNotASCII},
		{"client denylist URL with an IPv6 zone", "BYWARD_CLIENT_DENYLIST=https://[fe80::1%25eth0]/c.json", wantDenylist + `(31 characters, not shown): it has an IPv6 zone, which a URL cannot carry; give the address without its %zone`},
		// A pasted credential is named before the zone.
		{"client denylist URL with a password and an IPv6 zone", "BYWARD_CLIENT_DENYLIST=https://u:p@[fe80::1%25eth0]/c.json", wantDenylist + `(35 characters, not shown): it is a CIMD client ID with a user name or password`},
		{"client denylist unicode host", "BYWARD_CLIENT_DENYLIST=bücher.example", wantDenylist + `(14 characters, not shown): it ` + ruleNotASCII},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := load(t, nil, c.env)
			if !isConfigError(err) || err.Error() != c.want {
				t.Fatalf("want the config error %q, got %v", c.want, err)
			}
		})
	}
}

func TestConsentWordingLoadsUpToItsLimitCountedAsCharacters(t *testing.T) {
	c, err := load(t, nil, "BYWARD_OPERATOR_NAME="+strings.Repeat("é", 80), "BYWARD_SCOPE_DESCRIPTION="+strings.Repeat("é", 200))
	if err != nil {
		t.Fatal(err)
	}
	if c.OperatorName != strings.Repeat("é", 80) || c.ScopeDescription != strings.Repeat("é", 200) {
		t.Fatalf("operator %q, scope description %q", c.OperatorName, c.ScopeDescription)
	}
}

func TestBaseSettingsAreValid(t *testing.T) {
	if _, err := load(t, nil); err != nil {
		t.Fatalf("the base settings the rejection cases build on must load: %v", err)
	}
}

func TestDevAllowsLoopbackHTTPAndRecordsIt(t *testing.T) {
	c, err := load(t, []string{"--dev"}, "BYWARD_PUBLIC_URL=http://localhost:8080/mcp")
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(c.Relaxations, "|"); !c.Dev || len(c.Relaxations) != 2 ||
		!strings.Contains(got, "secret file permissions are not checked") || !strings.Contains(got, "http public URL on loopback") {
		t.Fatalf("dev=%v relaxations=%v", c.Dev, c.Relaxations)
	}
}

// Every form a Host header carries loads, in lower case, with any port from 1 to 65535, and a bare IPv6 address is
// stored in brackets, as a Host header carries it, so the public listener can match it (#325).
func TestAllowedHostsLoadEveryHostHeaderFormAndBracketABareIPv6(t *testing.T) {
	c, err := load(t, nil, "BYWARD_ALLOWED_HOSTS=a,mcp.example.com,mcp.example.com:9765,10.0.0.5:8080,localhost:1,::1,2001:db8::1,[2001:db8::1],[::1]:65535,my_svc-1,xn--bcher-kva.example,Mixed-Case.Example,0123456789.abcdefghijklmnopqrstuvwxyz.ABCDEFGHIJKLMNOPQRSTUVWXYZ")
	want := []string{"a", "mcp.example.com", "mcp.example.com:9765", "10.0.0.5:8080", "localhost:1", "[::1]", "[2001:db8::1]", "[2001:db8::1]", "[::1]:65535", "my_svc-1", "xn--bcher-kva.example", "mixed-case.example", "0123456789.abcdefghijklmnopqrstuvwxyz.abcdefghijklmnopqrstuvwxyz"}
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(c.AllowedHosts, want) {
		t.Fatalf("hosts=%v, want %v", c.AllowedHosts, want)
	}
}

// An allowed host is stored as browsers write it (ADR-0032 §2, class B): a name in lower case and an
// IPv6 address in its shortest form, the form the TLS certificate names check and the no-auth loopback
// check read (the Host check canonicalises both sides itself, #447). An IPv4 address is taken only in
// dotted decimal, and a name ending in a number not at all (TestAnAllowedHostNotInDottedDecimalOrEndingInANumberIsRefusedSayingWhatABrowserDoes).
func TestAnAllowedHostIsStoredWithItsAddressAsBrowsersWriteItAndANameOnlyInLowerCase(t *testing.T) {
	for given, stored := range map[string]string{
		"127.0.0.1:8080":       "127.0.0.1:8080",
		"2001:DB8:0:0::1":      "[2001:db8::1]",
		"MCP.Example.com:8443": "mcp.example.com:8443",
	} {
		t.Run(given, func(t *testing.T) {
			c, err := load(t, nil, "BYWARD_ALLOWED_HOSTS="+given)
			if err != nil {
				t.Fatal(err)
			}
			if !slices.Equal(c.AllowedHosts, []string{stored}) {
				t.Fatalf("stored %q, want %q", c.AllowedHosts, stored)
			}
		})
	}
}

// An allowed host a browser reads as an IPv4 address not written in dotted decimal (ADR-0032 R3) is
// refused, naming the address a browser reads, never rewritten into it (010.0.0.1 may have meant
// 10.0.0.1, #480); one a browser refuses as a name ending in a number (R4) is refused saying so.
func TestAnAllowedHostNotInDottedDecimalOrEndingInANumberIsRefusedSayingWhatABrowserDoes(t *testing.T) {
	for given, why := range map[string]string{
		"127.1":           ruleDottedDecimal + "127.0.0.1",
		"127.1:8080":      ruleDottedDecimal + "127.0.0.1",
		"0x7f.0.0.1":      ruleDottedDecimal + "127.0.0.1",
		"2130706433":      ruleDottedDecimal + "127.0.0.1",
		"010.0.0.1":       ruleDottedDecimal + "8.0.0.1, reading a part with a leading 0 as octal",
		"MCP.10":          ruleEndsInNumber,
		"10.0.0.999:8443": ruleEndsInNumber,
	} {
		want := wantHosts + fmt.Sprintf("(%d characters, not shown): its host ", len(given)) + why
		if _, err := load(t, nil, "BYWARD_ALLOWED_HOSTS="+given); !isConfigError(err) || err.Error() != want {
			t.Errorf("BYWARD_ALLOWED_HOSTS=%s: %v\nwant %s", given, err, want)
		}
	}
}

// Any IPv6 address may be listed in brackets, with or without a port: loopback or not, mapped or
// not (#319).
func TestAnIPv6AllowedHostIsAcceptedInBrackets(t *testing.T) {
	c, err := load(t, nil, "BYWARD_ALLOWED_HOSTS=[2001:db8::1]:8443,[fe80::1],[::ffff:10.0.0.1],[::1]:8080")
	if err != nil {
		t.Fatal(err)
	}
	if len(c.AllowedHosts) != 4 {
		t.Fatalf("hosts=%v, want 4", c.AllowedHosts)
	}
}

func TestListsAreNormalized(t *testing.T) {
	c, err := load(t, nil, "BYWARD_ALLOWED_ORIGINS= https://App.Example ,http://localhost:3000", "BYWARD_ALLOWED_HOSTS=Internal:8080")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(c.AllowedOrigins, ",") != "https://app.example,http://localhost:3000" || c.AllowedHosts[0] != "internal:8080" {
		t.Fatalf("origins=%v hosts=%v", c.AllowedOrigins, c.AllowedHosts)
	}
}

// BYWARD_ALLOWED_ORIGINS holds origins as browsers send them (RFC 6454 §6.2), so each entry can match a
// browser's Origin header: lower case, the scheme's default port dropped as the public URL's origin
// drops it, and an IPv6 address as the WHATWG URL serializer writes it. Entries no browser could send
// are refused (TestAURLOrHostRefusedForItsFormSaysWhereAndWhyNeverWhat).
func TestAllowedOriginsAreStoredAsBrowsersSendThem(t *testing.T) {
	for given, stored := range map[string]string{
		"https://App.example.com:443":   "https://app.example.com",
		"http://app.example.com:80":     "http://app.example.com",
		"http://app.example.com:443":    "http://app.example.com:443",
		"https://app.example.com:8443":  "https://app.example.com:8443",
		"https://[2001:DB8:0:0::1]:443": "https://[2001:db8::1]",
		"https://[::ffff:127.0.0.1]":    "https://[::ffff:7f00:1]",
		"https://1.2.3.4.example.com":   "https://1.2.3.4.example.com",
		"https://1.example.com":         "https://1.example.com",
		"https://a.1a":                  "https://a.1a",
		"https://a.0xzz":                "https://a.0xzz",
		"https://a.0a":                  "https://a.0a",
		"http://127.0.0.1:3000":         "http://127.0.0.1:3000",
		"HTTPS://XN--BCHER-KVA.example": "https://xn--bcher-kva.example",
	} {
		t.Run(given, func(t *testing.T) {
			c, err := load(t, nil, "BYWARD_ALLOWED_ORIGINS="+given)
			if err != nil {
				t.Fatal(err)
			}
			if !slices.Equal(c.AllowedOrigins, []string{stored}) {
				t.Fatalf("stored %q, want %q", c.AllowedOrigins, stored)
			}
		})
	}
}

func TestHelpFlagAsksForUsageListingEnvNames(t *testing.T) {
	if _, _, err := Load([]string{"-h"}, base, baseFiles); !IsHelp(err) {
		t.Fatalf("want help, got %v", err)
	}
	if !strings.Contains(Usage(), "BYWARD_PUBLIC_URL") {
		t.Fatal("usage lacks env names")
	}
}

func TestPositionalArgumentIsAConfigError(t *testing.T) {
	const want = "want settings as --name=value flags, and the stdio upstream command after --; got an unexpected argument (5 characters, not shown)"
	if _, _, err := Load([]string{"extra"}, base, baseFiles); !isConfigError(err) || err.Error() != want {
		t.Fatalf("got %v, want the config error %q", err, want)
	}
}

func TestVersionNeedsNoOtherSettings(t *testing.T) {
	_, act, err := Load([]string{"--version", "--json"}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !act.Version || !act.JSON {
		t.Fatalf("act=%+v, want Version and JSON", act)
	}
}

// secretReg is a registry of one secret setting, for the tests of reading a secret on its own.
var secretReg = []Setting{{Name: "client-secret", shape: secretShape, Help: "secret"}}

func files(m map[string]string) readFileFunc {
	return func(p string) ([]byte, error) {
		if v, ok := m[p]; ok {
			return []byte(v), nil
		}
		return nil, os.ErrNotExist
	}
}

func TestSecretFromEnvFile(t *testing.T) {
	v, err := resolve(secretReg, nil, []string{"BYWARD_CLIENT_SECRET_FILE=/run/secrets/x"}, files(map[string]string{"/run/secrets/x": "s3cret\n"}), nil)
	if err != nil {
		t.Fatal(err)
	}
	got := v.Effective()[0]
	if got.Given.raw() != "s3cret" || got.Source != SourceFile || got.Display() != "<redacted>" {
		t.Fatalf("got %+v display=%q", got, got.Display())
	}
}

func TestSecretFromFlagFileBeatsEnvFile(t *testing.T) {
	v, err := resolve(secretReg, []string{"--client-secret-file", "/a"}, []string{"BYWARD_CLIENT_SECRET_FILE=/b"}, files(map[string]string{"/a": "A", "/b": "B"}), nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := v.byKey["client-secret"].Given.raw(); got != "A" {
		t.Fatalf("got %q, want A", got)
	}
}

func TestSecretFileMissingIsConfigError(t *testing.T) {
	_, err := resolve(secretReg, nil, []string{"BYWARD_CLIENT_SECRET_FILE=/nope"}, files(nil), nil)
	if !isConfigError(err) || !strings.Contains(err.Error(), "BYWARD_CLIENT_SECRET_FILE") {
		t.Fatalf("want a config error naming the setting, got %v", err)
	}
}

func TestInlineSecretIsReported(t *testing.T) {
	v, err := resolve(secretReg, nil, []string{"BYWARD_CLIENT_SECRET=inline"}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := v.inlineSecrets(); len(got) != 1 || got[0].Env() != "BYWARD_CLIENT_SECRET" {
		t.Fatalf("inline = %v", got)
	}
	if v.Effective()[0].Display() != "<redacted>" {
		t.Fatal("inline secret not redacted")
	}
}

func TestSecretHasNoInlineFlag(t *testing.T) {
	_, err := resolve(secretReg, []string{"--client-secret", "x"}, nil, nil, nil)
	if !isConfigError(err) {
		t.Fatalf("want config error, got %v", err)
	}
}

func TestInlineSecretRejectedOutsideDevMode(t *testing.T) {
	v, err := resolve(secretReg, nil, []string{"BYWARD_CLIENT_SECRET=inline"}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := checkInlineSecrets(v, false); !isConfigError(err) || !strings.Contains(err.Error(), "BYWARD_CLIENT_SECRET_FILE") {
		t.Fatalf("without dev: want error pointing at the _FILE variable, got %v", err)
	}
	relaxed, err := checkInlineSecrets(v, true)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(relaxed, "BYWARD_CLIENT_SECRET") {
		t.Fatalf("with dev: relaxation=%q", relaxed)
	}
}

func TestSecretFileNeedsAFileReader(t *testing.T) {
	_, err := resolve(secretReg, nil, []string{"BYWARD_CLIENT_SECRET_FILE=/run/secrets/x"}, nil, nil)
	if !isConfigError(err) || !strings.Contains(err.Error(), "not available") {
		t.Fatalf("got %v", err)
	}
}

// A secret file that cannot be read is named as it was given, the _FILE variable or the
// --<name>-file flag, for every secret setting: never by the other form, which the operator did not set.
func TestASecretFileThatCannotBeReadIsNamedAsGiven(t *testing.T) {
	missing := func(string) ([]byte, error) { return nil, os.ErrNotExist }
	for _, s := range registry {
		if !s.Secret() {
			continue
		}
		for _, f := range secretFileForms(s, "/run/secrets/x") {
			_, err := resolve(registry, f.args, f.env, missing, nil)
			want := f.from + ": want the path of a file holding the secret, such as /run/secrets/" + s.Name +
				"; got a value (14 characters, not shown): it cannot be read: file does not exist"
			if !isConfigError(err) || err.Error() != want {
				t.Errorf("%s: err = %v, want %q", f.from, err, want)
			}
		}
	}
}

// ADR-0020 §8: the Entra quickstart needs at most five settings, and each of them is required.
func TestEntraQuickstartNeedsFiveSettings(t *testing.T) {
	if len(base) > 5 {
		t.Fatalf("the quickstart has %d settings, want at most 5: %v", len(base), base)
	}
	if _, err := load(t, nil); err != nil {
		t.Fatalf("the quickstart does not load: %v", err)
	}
	for i := range base {
		without := append(append([]string{}, base[:i]...), base[i+1:]...)
		if _, _, err := Load(nil, without, baseFiles); !isConfigError(err) {
			t.Errorf("without %s: %v, want a configuration error (it is required)", strings.SplitN(base[i], "=", 2)[0], err)
		}
	}
}

func TestBrokerSettingsAreRequired(t *testing.T) {
	for _, name := range []string{"BYWARD_ENTRA_TENANT", "BYWARD_ENTRA_CLIENT_ID"} { // only that, not also refused as no GUID
		want := name + " is required with BYWARD_IDP=entra (or set BYWARD_INSECURE_NO_AUTH to try the proxy without sign-in)"
		if _, err := load(t, nil, name+"="); !isConfigError(err) || err.Error() != want {
			t.Errorf("%s: %v\nwant %s", name, err, want)
		}
	}
	if _, err := load(t, nil, "BYWARD_ENTRA_CLIENT_SECRET_FILE="); !isConfigError(err) || !strings.Contains(err.Error(), "BYWARD_ENTRA_CLIENT_SECRET_FILE, BYWARD_ENTRA_CLIENT_CERTIFICATE_FILE or BYWARD_ENTRA_FEDERATED_TOKEN_FILE is required") {
		t.Errorf("secret: %v", err)
	}
	c, err := load(t, nil)
	if err != nil {
		t.Fatal(err)
	}
	if c.EntraClientSecret != "s3cret-entra" || c.KeysDir == "" {
		t.Fatalf("c=%+v, want EntraClientSecret and KeysDir", c)
	}
}

// The Entra tenant and client ID each take a GUID, in either case, as given: whether Entra's audience
// check takes an upper-case client ID is #514's. Anything else is refused by its length, with where
// to find the value.
func TestTheEntraIDsTakeAGUIDInEitherCaseAndRefuseAnythingElse(t *testing.T) {
	settings := []struct {
		env, want string
		got       func(*Config) string
	}{
		{"BYWARD_ENTRA_TENANT", "the tenant ID, a GUID such as 00000000-0000-0000-0000-000000000000 (Entra admin center, Overview, Tenant ID)",
			func(c *Config) string { return c.EntraTenant }},
		{"BYWARD_ENTRA_CLIENT_ID", "the application (client) ID, a GUID such as 00000000-0000-0000-0000-000000000000 (Entra admin center, App registrations, your app, Overview, Application (client) ID)",
			func(c *Config) string { return c.EntraClientID }},
	}
	for _, s := range settings {
		for _, tc := range []struct{ name, value string }{
			{"lower case", "0a1b2c3d-4e5f-6a7b-8c9d-0e1f2a3b4c5d"},
			{"upper case", "0A1B2C3D-4E5F-6A7B-8C9D-0E1F2A3B4C5D"},
			{"mixed case", "0A1b2C3d-4E5f-6A7b-8C9d-0E1F2a3B4c5D"},
		} {
			t.Run(s.env+" "+tc.name, func(t *testing.T) {
				c, err := load(t, nil, s.env+"="+tc.value)
				if err != nil {
					t.Fatalf("%v; want %s taken", err, tc.value)
				}
				if got := s.got(c); got != tc.value {
					t.Fatalf("got %q, want it as given, %q", got, tc.value)
				}
			})
		}
		for _, tc := range []struct{ name, value string }{
			{"a domain", "contoso.onmicrosoft.com"},
			{"one character short", "0a1b2c3d-4e5f-6a7b-8c9d-0e1f2a3b4c5"},
			{"one character long", "0a1b2c3d-4e5f-6a7b-8c9d-0e1f2a3b4c5d0"},
			{"a dash out of place", "0a1b2c3d4-e5f-6a7b-8c9d-0e1f2a3b4c5d"},
			{"a letter that is not hex", "0a1b2c3d-4e5f-6a7b-8c9d-0e1f2a3b4c5g"},
			{"in braces", "{0a1b2c3d-4e5f-6a7b-8c9d-0e1f2a3b4c}"},
		} {
			t.Run(s.env+" "+tc.name, func(t *testing.T) {
				want := fmt.Sprintf("%s: want %s; got a value (%d characters, not shown): it is not a GUID", s.env, s.want, len(tc.value))
				if _, err := load(t, nil, s.env+"="+tc.value); !isConfigError(err) || err.Error() != want {
					t.Fatalf("err = %v\nwant %s", err, want)
				}
			})
		}
	}
}

func TestInternalListenDefaultsToLoopbackAndMustDifferFromListen(t *testing.T) {
	base := []string{"BYWARD_INSECURE_NO_AUTH=true", "BYWARD_PUBLIC_URL=http://127.0.0.1:8080/mcp", "BYWARD_UPSTREAM_URL=http://u/mcp"}
	cfg, _, err := Load(nil, base, nil)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.InternalListen != "127.0.0.1:9090" {
		t.Fatalf("default internal listener = %q, want 127.0.0.1:9090", cfg.InternalListen)
	}
	cfg, _, err = Load(nil, append(base, "BYWARD_INTERNAL_LISTEN="), nil)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.InternalListen != "" {
		t.Fatalf("BYWARD_INTERNAL_LISTEN= must turn the internal listener off, got %q", cfg.InternalListen)
	}
	for _, bad := range []string{"9090", "127.0.0.1:8080"} {
		if _, _, err := Load(nil, append(base, "BYWARD_INTERNAL_LISTEN="+bad), nil); err == nil || !strings.Contains(err.Error(), "BYWARD_INTERNAL_LISTEN") {
			t.Errorf("BYWARD_INTERNAL_LISTEN=%q: want an error naming the setting, got %v", bad, err)
		}
	}
}

func noAuthEnv(extra ...string) []string {
	return append([]string{"BYWARD_INSECURE_NO_AUTH=true", "BYWARD_PUBLIC_URL=http://127.0.0.1:8080/mcp", "BYWARD_UPSTREAM_URL=http://u/mcp"}, extra...)
}

func TestOAuthRateLimitsDefaultToADR0018AndCanBeRaisedWithinBounds(t *testing.T) {
	cfg, _, err := Load(nil, noAuthEnv(), nil)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]int{"authorize": 30, "consent": 60, "callback": 30, "token": 60, "revoke": 30, "register": 30}
	for ep, n := range want {
		if cfg.OAuthRateLimits[ep] != n {
			t.Errorf("default %s = %d/min, want %d", ep, cfg.OAuthRateLimits[ep], n)
		}
	}
	cfg, _, err = Load(nil, noAuthEnv("BYWARD_OAUTH_RATE_LIMITS=authorize=1, token=10000"), nil) // both bounds
	if err != nil {
		t.Fatal(err)
	}
	if cfg.OAuthRateLimits["authorize"] != 1 || cfg.OAuthRateLimits["token"] != 10000 {
		t.Fatalf("the bounds: %v; want both accepted", cfg.OAuthRateLimits)
	}
	cfg, _, err = Load(nil, noAuthEnv("BYWARD_OAUTH_RATE_LIMITS=authorize=120, token=600"), nil)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.OAuthRateLimits["authorize"] != 120 || cfg.OAuthRateLimits["token"] != 600 || cfg.OAuthRateLimits["callback"] != 30 {
		t.Errorf("overrides = %v, want authorize 120, token 600 and the other defaults", cfg.OAuthRateLimits)
	}
	// An entry refused for its form by its place and length; a limit out of range as parsed.
	const refused = "BYWARD_OAUTH_RATE_LIMITS: want endpoint=per-minute entries such as token=60, the endpoint authorize, consent, callback, token, revoke or register and the limit a whole number from 1 to 10000; got entry 1 of 1"
	for bad, why := range map[string]string{
		"metadata=10":                " (11 characters, not shown): it is not endpoint=per-minute for one of the endpoints",
		"authorize":                  " (9 characters, not shown): it is not endpoint=per-minute for one of the endpoints",
		"authorize=fast":             " (14 characters, not shown): its limit is not a whole number",
		"authorize=0":                ", authorize=0: the limit is out of range",
		" authorize = 010001":        ", authorize=10001: the limit is out of range",
		"authorize=-5":               ", authorize=-5: the limit is out of range",
		"token=99999999999999999999": " (26 characters, not shown): its limit is out of range",
	} {
		t.Run(strconv.Quote(bad), func(t *testing.T) {
			if _, _, err := Load(nil, noAuthEnv("BYWARD_OAUTH_RATE_LIMITS="+bad), nil); !isConfigError(err) || err.Error() != refused+why {
				t.Errorf("got %v, want %q", err, refused+why)
			}
		})
	}
}

func TestSecretFileRelaxationOnlyWithDev(t *testing.T) {
	c, err := load(t, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(c.Relaxations, "|"); strings.Contains(got, "secret file permissions") {
		t.Errorf("without --dev the relaxations claim the secret file check is off: %q", got)
	}
}

func TestSecretFilesNameTheFileEachSecretCameFrom(t *testing.T) {
	read := func(string) ([]byte, error) { return []byte("s3cret"), nil }
	cases := []struct {
		name string
		args []string
		env  []string
		want []SecretFile
	}{
		{"env", nil, []string{"BYWARD_ENTRA_CLIENT_SECRET_FILE=/run/secrets/entra"}, []SecretFile{{"BYWARD_ENTRA_CLIENT_SECRET_FILE", "/run/secrets/entra"}}},
		{"flag", []string{"--entra-client-secret-file=/run/secrets/flag"}, nil, []SecretFile{{"--entra-client-secret-file", "/run/secrets/flag"}}},
		{"inline (dev only)", []string{"--dev"}, []string{"BYWARD_ENTRA_CLIENT_SECRET=inline"}, nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			vals, err := resolve(registry, c.args, c.env, read, nil)
			if err != nil {
				t.Fatal(err)
			}
			if got := vals.SecretFiles(); fmt.Sprint(got) != fmt.Sprint(c.want) {
				t.Errorf("SecretFiles() = %v, want %v", got, c.want)
			}
		})
	}
}

func TestUpstreamHeaderTimeoutDefaultsToFiveMinutesWithinBounds(t *testing.T) {
	const refused = "BYWARD_UPSTREAM_HEADER_TIMEOUT: want a duration from 1s to 1h, such as 5m; got "
	cases := []struct {
		env  string
		want time.Duration
		err  string // the whole refusal, when refused
	}{
		{"", 5 * time.Minute, ""},
		{"BYWARD_UPSTREAM_HEADER_TIMEOUT=1s", time.Second, ""},
		{"BYWARD_UPSTREAM_HEADER_TIMEOUT=1h", time.Hour, ""},
		{"BYWARD_UPSTREAM_HEADER_TIMEOUT=999ms", 0, refused + "999ms: it is out of range"},
		{"BYWARD_UPSTREAM_HEADER_TIMEOUT=61m", 0, refused + "1h1m0s: it is out of range"},
		{"BYWARD_UPSTREAM_HEADER_TIMEOUT=0s", 0, refused + "0s: it is out of range"},
		{"BYWARD_UPSTREAM_HEADER_TIMEOUT=3600001ms", 0, refused + "1h0m0.001s: it is out of range"}, // shown as parsed
	}
	for _, c := range cases {
		t.Run(c.env, func(t *testing.T) {
			var env []string
			if c.env != "" {
				env = []string{c.env}
			}
			cfg, _, err := Load(nil, noAuthEnv(env...), nil)
			switch {
			case c.err != "" && (!isConfigError(err) || err.Error() != c.err):
				t.Errorf("got %v, want %q", err, c.err)
			case c.err == "" && err != nil:
				t.Errorf("%v", err)
			case c.err == "" && cfg.UpstreamHeaderTimeout != c.want:
				t.Errorf("timeout %s, want %s", cfg.UpstreamHeaderTimeout, c.want)
			}
		})
	}
}

// Trusted proxies are CIDRs or addresses, masked; an IPv4-mapped one is the IPv4 prefix it maps,
// since peers are compared unmapped, and one shorter than /96 maps no IPv4 prefix (masked, it would
// trust IPv6 addresses), so it is refused. An entry inside fe80::/10 is refused, as it would trust no
// peer; a zone too: it was dropped, and it swallowed any prefix length after it. Link-local is said
// first, so removing the zone never leads to the second refusal. An entry refused for its form says
// which part is wrong: the address, or the prefix length (not a whole number, a leading zero, longer
// than the address).
func TestTrustedProxiesTakeCIDRsAndAddresses(t *testing.T) {
	cfg, _, err := Load(nil, noAuthEnv("BYWARD_TRUSTED_PROXIES=10.0.0.0/8, 192.0.2.7, 2001:db8::/32, 10.1.2.3/8"), nil)
	if err != nil {
		t.Fatal(err)
	}
	got := fmt.Sprint(cfg.TrustedProxies)
	if want := "[10.0.0.0/8 192.0.2.7/32 2001:db8::/32 10.0.0.0/8]"; got != want {
		t.Errorf("trusted proxies = %s, want %s (bare addresses as /32 or /128, prefixes masked)", got, want)
	}
	for given, stored := range map[string]string{
		"::ffff:10.0.0.5":       "10.0.0.5/32",
		"::ffff:10.0.0.5/128":   "10.0.0.5/32",
		"::ffff:172.16.0.0/108": "172.16.0.0/12",
		"::ffff:0:0/96":         "0.0.0.0/0",
		// Around fe80::/10 but not inside it (TestALoadedTrustedProxyListDecidesTheClientAddress).
		"::/0":           "::/0",
		"fe80::/9":       "fe80::/9", // starts in fe80::/10 but is wider
		"fe00::/9":       "fe00::/9",
		"fec0::1":        "fec0::1/128",
		"169.254.0.0/16": "169.254.0.0/16", // IPv4 link-local has no zone
	} {
		t.Run(given, func(t *testing.T) {
			cfg, _, err := Load(nil, noAuthEnv("BYWARD_TRUSTED_PROXIES="+given), nil)
			if err != nil {
				t.Fatal(err)
			}
			if got := fmt.Sprint(cfg.TrustedProxies); got != "["+stored+"]" {
				t.Errorf("stored %s, want [%s]", got, stored)
			}
		})
	}
	cfg, _, err = Load(nil, noAuthEnv(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.TrustedProxies) != 0 {
		t.Errorf("default trusted proxies = %v, want none", cfg.TrustedProxies)
	}
	const refused = "BYWARD_TRUSTED_PROXIES: want a CIDR or an IP address such as 10.0.0.0/8 or 192.0.2.1; got entry 1 of 1"
	for _, tc := range []struct{ name, value, want string }{
		{"a hostname", "proxy.internal", refused + ` (14 characters, not shown): it is neither a CIDR nor an IP address`},
		{"a CIDR whose address is not one", "10.0.0/8", refused + ` (8 characters, not shown): its address, before the "/", is not an IP address`},
		{"a CIDR with no prefix length", "10.0.0.0/", refused + ` (9 characters, not shown): its prefix length, after the "/", is not a whole number`},
		{"a CIDR whose prefix length is a word", "10.0.0.0/x", refused + ` (10 characters, not shown): its prefix length, after the "/", is not a whole number`},
		{"a prefix length with a leading zero", "10.0.0.0/08", refused + ` (11 characters, not shown): its prefix length has a leading zero`},
		{"an IPv4 prefix longer than /32", "192.168.1.0/33", refused + ` (14 characters, not shown): its prefix length is longer than /32, the length of an IPv4 address`},
		{"an IPv4 prefix length past any integer", "10.0.0.0/99999999999999999999", refused + ` (29 characters, not shown): its prefix length is longer than /32, the length of an IPv4 address`},
		{"an IPv6 prefix longer than /128", "2001:db8::/129", refused + ` (14 characters, not shown): its prefix length is longer than /128, the length of an IPv6 address`},
		{"a mapped /8, shown as netip writes it", "0:0:0:0:0:FFFF:10.0.0.0/8", refused + `, ::ffff:10.0.0.0/8: it is an IPv4-mapped prefix shorter than /96: it maps no IPv4 prefix and would trust IPv6 addresses; give the IPv4 prefix instead (::ffff:10.0.0.0/104 is 10.0.0.0/8)`},
		{"a mapped /95", "::ffff:10.0.0.0/95", refused + `, ::ffff:10.0.0.0/95: it is an IPv4-mapped prefix shorter than /96: it maps no IPv4 prefix and would trust IPv6 addresses; give the IPv4 prefix instead (::ffff:10.0.0.0/104 is 10.0.0.0/8)`},
		// Parsed as an address, everything after % is the zone, the prefix length included.
		{"a zoned prefix", "2001:db8::1%eth0/64", refused + `, 2001:db8::1: it has an IPv6 zone, not shown: give the proxy's routable address or CIDR, without a zone`},
		{"a zoned address", "2001:db8::1%eth0", refused + `, 2001:db8::1: it has an IPv6 zone, not shown: give the proxy's routable address or CIDR, without a zone`},
		{"a zoned mapped address", "::ffff:10.0.0.1%eth0", refused + `, 10.0.0.1: it has an IPv6 zone, not shown: give the proxy's routable address or CIDR, without a zone`},
		{"a zoned link-local prefix", "fe80::1%eth0/64", refused + `, fe80::1/128: it is link-local: a link-local proxy cannot be trusted, as its address names a host only together with an interface; give the proxy's routable address or CIDR`},
		{"a zoned link-local address", "fe80::1%eth0", refused + `, fe80::1/128: it is link-local: a link-local proxy cannot be trusted, as its address names a host only together with an interface; give the proxy's routable address or CIDR`},
		{"a link-local address", "fe80::1", refused + `, fe80::1/128: it is link-local: a link-local proxy cannot be trusted, as its address names a host only together with an interface; give the proxy's routable address or CIDR`},
		{"the link-local prefix", "fe80::/10", refused + `, fe80::/10: it is link-local: a link-local proxy cannot be trusted, as its address names a host only together with an interface; give the proxy's routable address or CIDR`},
		{"the last link-local address", "febf:ffff:ffff:ffff:ffff:ffff:ffff:ffff", refused + `, febf:ffff:ffff:ffff:ffff:ffff:ffff:ffff/128: it is link-local: a link-local proxy cannot be trusted, as its address names a host only together with an interface; give the proxy's routable address or CIDR`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, _, err := Load(nil, noAuthEnv("BYWARD_TRUSTED_PROXIES="+tc.value), nil); err == nil || err.Error() != tc.want {
				t.Errorf("err = %v\nwant %s", err, tc.want)
			}
		})
	}
}

// A duration refused for its form says what is wrong with it, from time.ParseDuration's error, which
// quotes the value, so is never shown: a number without a unit, a unit it does not take, or neither.
func TestADurationRefusedForItsFormSaysWhatIsWrong(t *testing.T) {
	const (
		refused     = "BYWARD_UPSTREAM_HEADER_TIMEOUT: want a duration from 1s to 1h, such as 5m; got a value "
		noUnit      = ": it has a number without a unit; give one of ns, us, ms, s, m or h"
		badUnit     = ": it has a unit that is not one of ns, us, ms, s, m or h"
		notDuration = ": it is not a duration"
	)
	for _, tc := range []struct{ value, want string }{
		{"5", "(1 character, not shown)" + noUnit},
		{"1m30", "(4 characters, not shown)" + noUnit},
		{"1.5", "(3 characters, not shown)" + noUnit},
		{"10x", "(3 characters, not shown)" + badUnit},
		{"30sec", "(5 characters, not shown)" + badUnit},
		{"5 m", "(3 characters, not shown)" + badUnit},
		{"ten", "(3 characters, not shown)" + notDuration},
		{"s", "(1 character, not shown)" + notDuration},
	} {
		t.Run(tc.value, func(t *testing.T) {
			if _, err := load(t, nil, "BYWARD_UPSTREAM_HEADER_TIMEOUT="+tc.value); !isConfigError(err) || err.Error() != refused+tc.want {
				t.Fatalf("err = %v\nwant %s", err, refused+tc.want)
			}
		})
	}
}

// A loaded trusted-proxy list decides the client address where it is resolved
// (logging.ClientAddress). A mapped prefix trusts the IPv4 proxy it maps: kept mapped, it would trust
// none, as peers are compared unmapped. ::/0, accepted although it contains fe80::/10, still trusts no
// link-local peer, which arrives zoned.
func TestALoadedTrustedProxyListDecidesTheClientAddress(t *testing.T) {
	for _, tc := range []struct{ name, proxies, peer, want string }{
		{"a mapped prefix trusts its IPv4 proxy", "::ffff:10.0.0.0/104", "10.1.2.3:4000", "198.51.100.1"},
		{"::/0 trusts an IPv6 proxy", "::/0", "[2001:db8::1]:4000", "198.51.100.1"},
		{"::/0 does not trust a zoned link-local proxy", "::/0", "[fe80::1%eth0]:4000", "fe80::1%eth0"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg, _, err := Load(nil, noAuthEnv("BYWARD_TRUSTED_PROXIES="+tc.proxies), nil)
			if err != nil {
				t.Fatal(err)
			}
			var client string
			h := logging.ClientAddress(cfg.TrustedProxies, http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) { client = logging.RemoteIP(r) }))
			r := httptest.NewRequest(http.MethodGet, "/", nil)
			r.RemoteAddr = tc.peer
			r.Header.Set("X-Forwarded-For", "198.51.100.1")
			h.ServeHTTP(httptest.NewRecorder(), r)
			if client != tc.want {
				t.Fatalf("client %s, want %s (198.51.100.1 when the peer is trusted, else the peer)", client, tc.want)
			}
		})
	}
}

// The key, client and store paths default into the data directory; the restore counter sits next to
// the keys, outside the state directory (ADR-0007 §6, §9).
func TestPathsDefaultIntoTheDataDirectory(t *testing.T) {
	cases := []struct {
		name                                string
		env                                 []string
		data, keys, clients, store, counter string
	}{
		{"defaults", nil, "/var/lib/byward", "/var/lib/byward/keys", "/var/lib/byward/clients.json",
			"/var/lib/byward/state", "/var/lib/byward/store-writes"},
		{"another data directory", []string{"BYWARD_DATA_DIR=/srv/proxy"}, "/srv/proxy", "/srv/proxy/keys", "/srv/proxy/clients.json",
			"/srv/proxy/state", "/srv/proxy/store-writes"},
		{"explicit paths", []string{"BYWARD_KEYS_DIR=/etc/byward/keys", "BYWARD_STATIC_CLIENTS_FILE=/etc/byward/clients.json",
			"BYWARD_STORE_DIR=/data/state"}, "/var/lib/byward", "/etc/byward/keys", "/etc/byward/clients.json",
			"/data/state", "/etc/byward/store-writes"},
		{"keys directory with a trailing slash", []string{"BYWARD_KEYS_DIR=/etc/byward/keys/"}, "/var/lib/byward",
			"/etc/byward/keys/", "/var/lib/byward/clients.json", "/var/lib/byward/state", "/etc/byward/store-writes"},
		{"explicit counter file", []string{"BYWARD_STORE_COUNTER_FILE=/data/counter/writes"}, "/var/lib/byward",
			"/var/lib/byward/keys", "/var/lib/byward/clients.json", "/var/lib/byward/state", "/data/counter/writes"},
		// "/var/lib/byward/state-counter" shares a name prefix with the state directory but is not inside it.
		{"counter beside the state directory with a shared prefix", []string{"BYWARD_STORE_COUNTER_FILE=/var/lib/byward/state-counter/writes"},
			"/var/lib/byward", "/var/lib/byward/keys", "/var/lib/byward/clients.json", "/var/lib/byward/state",
			"/var/lib/byward/state-counter/writes"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c, err := load(t, nil, tc.env...)
			if err != nil {
				t.Fatal(err)
			}
			got := []string{c.DataDir, c.KeysDir, c.StaticClientsFile, c.StoreDir, c.StoreCounterFile}
			if want := []string{tc.data, tc.keys, tc.clients, tc.store, tc.counter}; !slices.Equal(got, want) {
				t.Fatalf("data, keys, clients, store, counter = %q, want %q", got, want)
			}
		})
	}
}

// The server needs to know whether the operator named the static clients file: a named file must
// exist, while the default one may be absent when apps can register themselves.
func TestTheConfigSaysWhetherTheStaticClientsFileWasNamed(t *testing.T) {
	for _, tc := range []struct {
		env   []string
		named bool
	}{{nil, false}, {[]string{"BYWARD_STATIC_CLIENTS_FILE=/etc/byward/clients.json"}, true}} {
		c, err := load(t, nil, tc.env...)
		if err != nil {
			t.Fatalf("env %q: %v", tc.env, err)
		}
		if c.StaticClientsFileNamed != tc.named {
			t.Fatalf("env %q: named = %v, want %v", tc.env, c.StaticClientsFileNamed, tc.named)
		}
	}
}

func TestRefreshGraceDefaultsTo30sAndAcceptsItsBounds(t *testing.T) {
	for _, tc := range []struct {
		name string
		env  []string
		want time.Duration
	}{
		{"default", nil, 30 * time.Second},
		{"lower bound", []string{"BYWARD_REFRESH_GRACE=0s"}, 0},
		{"upper bound", []string{"BYWARD_REFRESH_GRACE=60s"}, time.Minute},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, err := load(t, nil, tc.env...)
			if err != nil {
				t.Fatal(err)
			}
			if c.RefreshGrace != tc.want {
				t.Fatalf("grace %v, want %v", c.RefreshGrace, tc.want)
			}
		})
	}
}

func TestInvalidStoreSettingsAreRejected(t *testing.T) {
	// A relative path in each setting is TestEveryPathSettingRefusesARelativePath's; the first rows here
	// pin which errors a path derived from another one reports.
	cases := []struct {
		name    string
		env     []string
		want    string
		notWant string // "" when anything else may be reported too
	}{
		// Every default derives from the data directory, so a relative one is reported, not the paths
		// derived from it.
		{"a relative data directory", []string{"BYWARD_DATA_DIR=data"}, "BYWARD_DATA_DIR: want an absolute path", "BYWARD_KEYS_DIR"},
		// The counter file derived from a relative keys directory is not reported a second time; one the
		// operator sets is.
		{"a counter derived from a relative keys directory", []string{"BYWARD_KEYS_DIR=keys"}, "BYWARD_KEYS_DIR: want an absolute path", "BYWARD_STORE_COUNTER_FILE"},
		{"a relative counter beside a relative keys directory", []string{"BYWARD_KEYS_DIR=keys", "BYWARD_STORE_COUNTER_FILE=writes"}, `BYWARD_STORE_COUNTER_FILE: want an absolute path, one starting with /; got a relative one: no path is relative to the working directory (ADR-0007 §6)`, ""},
		{"counter inside the state directory", []string{"BYWARD_STORE_COUNTER_FILE=/var/lib/byward/state/writes"}, "BYWARD_STORE_COUNTER_FILE: want a path outside BYWARD_STORE_DIR; got one inside it: a restored backup", ""},
		{"keys inside the state directory", []string{"BYWARD_KEYS_DIR=/var/lib/byward/state/keys"}, "keep the keys directory outside the state directory", ""},
		{"grace not a duration", []string{"BYWARD_REFRESH_GRACE=soon"}, "BYWARD_REFRESH_GRACE: want a duration", ""},
		{"grace negative", []string{"BYWARD_REFRESH_GRACE=-1000ms"}, "BYWARD_REFRESH_GRACE: want a duration from 0s to 60s, such as 30s; got -1s: it is out of range", "-1000ms"},
		{"grace over a minute, shown as parsed", []string{"BYWARD_REFRESH_GRACE=61000ms"}, "BYWARD_REFRESH_GRACE: want a duration from 0s to 60s, such as 30s; got 1m1s: it is out of range", "61000ms"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := load(t, nil, tc.env...)
			if !isConfigError(err) || !strings.Contains(err.Error(), tc.want) || (tc.notWant != "" && strings.Contains(err.Error(), tc.notWant)) {
				t.Fatalf("want a config error containing %q and not %q, got %v", tc.want, tc.notWant, err)
			}
		})
	}
}

func TestCIMDHostListsAreNormalizedAndRefusedWhileCIMDIsOff(t *testing.T) {
	c, err := load(t, nil, "BYWARD_CIMD_TRUSTED_HOSTS=Claude.AI, vscode.dev", "BYWARD_CIMD_ALLOWED_HOSTS=apps.example.com")
	if err != nil {
		t.Fatal(err)
	}
	if !c.CIMD || !slices.Equal(c.CIMDTrustedHosts, []string{"claude.ai", "vscode.dev"}) || !slices.Equal(c.CIMDAllowedHosts, []string{"apps.example.com"}) {
		t.Fatalf("CIMD %v, trusted %v, allowed %v", c.CIMD, c.CIMDTrustedHosts, c.CIMDAllowedHosts)
	}
	c, err = load(t, nil, "BYWARD_CIMD=false")
	if err != nil {
		t.Fatal(err)
	}
	if c.CIMD {
		t.Fatalf("CIMD off: %v", c.CIMD)
	}
	// Host lists with CIMD off would silently do nothing; both settings are named as given.
	for _, tc := range []struct {
		args []string
		env  []string
		want string
	}{
		{nil, []string{"BYWARD_CIMD=false", "BYWARD_CIMD_TRUSTED_HOSTS=claude.ai"}, "BYWARD_CIMD_TRUSTED_HOSTS has no effect while BYWARD_CIMD is false; remove one of them"},
		{[]string{"--cimd=false", "--cimd-allowed-hosts", "claude.ai"}, nil, "--cimd-allowed-hosts has no effect while --cimd is false; remove one of them"},
	} {
		if _, err := load(t, tc.args, tc.env...); !isConfigError(err) || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%v %v: err = %v, want %q", tc.args, tc.env, err, tc.want)
		}
	}
}

// DCR is on unless turned off; the denylist takes comma-separated entries, as given: a CIMD client ID
// (checked where it is used, internal/registration) or a host name, which may end in a dot.
func TestDCRIsOnByDefaultAndTheDenylistTakesCommaSeparatedEntries(t *testing.T) {
	c, err := load(t, nil, "BYWARD_CLIENT_DENYLIST=https://evil.example/client.json, app.example.")
	if err != nil {
		t.Fatal(err)
	}
	if !c.DCR || !slices.Equal(c.ClientDenylist, []string{"https://evil.example/client.json", "app.example."}) {
		t.Fatalf("DCR %v, denylist %q", c.DCR, c.ClientDenylist)
	}
	// Names that only look like numbers are host names: hex letters in the last label, digits in
	// another one or only at its start, 0x followed by something other than hex digits only (app.0x7g,
	// a.0xg, a.0xag). A client ID at an IP address without a zone loads too: IPv4, IPv6 and
	// IPv4-mapped (only a zone is refused, #644).
	for _, entry := range []string{"app.de", "app.cafe", "123.example", "0x7f.example", "app.0x7g", "a.0xg", "a.0xag", "app.1example",
		"https://8.8.8.8/c.json", "https://[2001:db8::1]/c.json", "https://[::ffff:8.8.8.8]/c.json"} {
		if _, err := load(t, nil, "BYWARD_CLIENT_DENYLIST="+entry); err != nil {
			t.Errorf("%q refused: %v", entry, err)
		}
	}
	if c, err = load(t, nil, "BYWARD_DCR=false"); err != nil {
		t.Fatal(err)
	}
	if c.DCR {
		t.Fatal("DCR on with BYWARD_DCR=false")
	}
}

// #334, ADR-0032 §3: a name with any ASCII character but letters, digits, "-", "." and "_" (a control
// character, a sub-delim, "~", a %-escape, "@", "?", "#", "\\" ...) is refused as a host name, with or
// without a port, naming its place. ":", the
// brackets, "/" and the space belong to the form check and are covered there; "," separates the
// list's entries.
func TestAnAllowedHostNameRefusesEveryCharacterAHostNameCannotHave(t *testing.T) {
	const nameChars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._"
	for c := byte(1); c < 0x80; c++ {
		if strings.IndexByte(nameChars+":[]/, ", c) >= 0 {
			continue
		}
		for _, entry := range []string{"a" + string(c) + "b", "a" + string(c) + "b:8443"} {
			_, err := load(t, nil, "BYWARD_ALLOWED_HOSTS="+entry)
			if err == nil || !strings.Contains(err.Error(), "): it "+ruleNameChar+"2"+ruleNameChars) {
				t.Errorf("BYWARD_ALLOWED_HOSTS=%s: %v, want it refused as a host name", entry, err)
			}
		}
	}
}

// #344: every host list that follows the name rule loads underscores, xn-- names and mixed case,
// each on its own, stored in lower case except in the denylist, which keeps entries as given. The
// public URL refuses upper case (#472), so it loads only the lower-case names, each as its issuer.
func TestHostSettingsLoadUnderscoresIDNANamesAndMixedCase(t *testing.T) {
	for _, host := range []string{"my_svc.example", "xn--bcher-kva.example", "Mixed-Case.Example", "a-b.example"} {
		lower := strings.ToLower(host)
		settings := map[string]func(*Config) []string{
			"BYWARD_CIMD_TRUSTED_HOSTS=" + host: func(c *Config) []string { return c.CIMDTrustedHosts },
			"BYWARD_CIMD_ALLOWED_HOSTS=" + host: func(c *Config) []string { return c.CIMDAllowedHosts },
			"BYWARD_ALLOWED_HOSTS=" + host:      func(c *Config) []string { return c.AllowedHosts },
			"BYWARD_CLIENT_DENYLIST=" + host:    func(c *Config) []string { return c.ClientDenylist },
		}
		if host == lower {
			settings["BYWARD_PUBLIC_URL=https://"+host+"/mcp"] = func(c *Config) []string { return []string{strings.TrimPrefix(c.Issuer(), "https://")} }
		}
		for setting, stored := range settings {
			t.Run(setting, func(t *testing.T) {
				c, err := load(t, nil, setting)
				if err != nil {
					t.Fatal(err)
				}
				want := lower
				if strings.HasPrefix(setting, "BYWARD_CLIENT_DENYLIST=") {
					want = host // the denylist keeps its entries as given
				}
				if got := stored(c); !slices.Equal(got, []string{want}) {
					t.Errorf("stored %v, want [%s]", got, want)
				}
			})
		}
	}
}

// #630: a host name refuses labels with leading or trailing hyphens across all host settings
// (BYWARD_PUBLIC_URL, BYWARD_ALLOWED_HOSTS, BYWARD_ALLOWED_ORIGINS, BYWARD_CIMD_TRUSTED_HOSTS,
// BYWARD_CIMD_ALLOWED_HOSTS, BYWARD_CLIENT_DENYLIST, BYWARD_LISTEN, and BYWARD_INTERNAL_LISTEN).
func TestHostNameRuleRefusesLabelsWithLeadingOrTrailingHyphen(t *testing.T) {
	refused := []string{"-", "-a.example", "a-.example", "a.-b.example", "a.b-"}
	settings := []struct{ setting, format, want string }{
		// Every host setting but the listen addresses gives the rule as its own reason (#523, #524).
		{"public URL", "BYWARD_PUBLIC_URL=https://%s/mcp", ruleEdgeHyphen},
		{"allowed hosts", "BYWARD_ALLOWED_HOSTS=%s", ruleEdgeHyphen},
		{"allowed origins", "BYWARD_ALLOWED_ORIGINS=https://%s", ruleEdgeHyphen},
		{"CIMD trusted hosts", "BYWARD_CIMD_TRUSTED_HOSTS=%s", ruleEdgeHyphen},
		{"CIMD allowed hosts", "BYWARD_CIMD_ALLOWED_HOSTS=%s", ruleEdgeHyphen},
		{"client denylist", "BYWARD_CLIENT_DENYLIST=%s", ruleEdgeHyphen},
		{"listen", "BYWARD_LISTEN=%s:8080", "has a host that is neither an IP address nor a host name"},
		{"internal listen", "BYWARD_INTERNAL_LISTEN=%s:8081", "has a host that is neither an IP address nor a host name"},
	}
	for _, host := range refused {
		for _, tc := range settings {
			t.Run("settings/"+tc.setting+"/"+host, func(t *testing.T) {
				if _, err := load(t, nil, fmt.Sprintf(tc.format, host)); err == nil || !strings.Contains(err.Error(), tc.want) {
					t.Errorf(tc.format+" err = %v, want %q", host, err, tc.want)
				}
			})
		}
	}
}

// --dev changes nothing in a configuration but what it records as relaxations (and the fields
// decided beside them), on each setup with a --dev branch that also loads without it: the base
// (https, SQLite), a PostgreSQL store, and an http IdP issuer on loopback. So no setting is quietly
// relaxed (security invariant 12, #355).
func TestDevelopmentModeChangesOnlyWhatItRecords(t *testing.T) {
	for _, tc := range []struct {
		name string
		load func(args []string) (*Config, error)
	}{
		{"https, SQLite", func(args []string) (*Config, error) { return load(t, args) }},
		{"a PostgreSQL store", func(args []string) (*Config, error) {
			return loadDSN(t, args, "BYWARD_STORE_POSTGRES_DSN_FILE="+dsnFile)
		}},
		{"an http IdP issuer on loopback", func(args []string) (*Config, error) {
			c, _, err := Load(args, with("BYWARD_OIDC_ISSUER=http://127.0.0.1:8180/realms/byward")(without("BYWARD_OIDC_ISSUER")(slices.Clone(oidcBase))), oidcFiles)
			return c, err
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			without, err := tc.load(nil)
			if err != nil {
				t.Fatal(err)
			}
			with, err := tc.load([]string{"--dev"})
			if err != nil {
				t.Fatal(err)
			}
			for _, c := range []*Config{without, with} {
				c.Dev, c.Relaxations, c.Values, c.OIDCLoopbackHTTP = false, nil, nil, false
			}
			if !reflect.DeepEqual(without, with) {
				t.Fatalf("--dev changed the configuration beyond its relaxations:\nwithout %+v\nwith    %+v", without, with)
			}
		})
	}
}

// length is the number of characters notShown counts.
func length(s string) int { return len([]rune(s)) }

// #494: a listen address is host:port, as net.Listen takes it: the host empty, an IP address (a zoned
// IPv6 one included, its zone a name an interface can have or an interface index, #638) or a host
// name of letters, digits, - . and _ only
// (ADR-0032 §3) with one trailing dot at most, and the port a number from 0 to
// 65535; a service name such as http is refused. Brackets enclose an IPv6 address alone (#629): around
// a name, an IPv4 address or nothing they are refused, though net.SplitHostPort would strip them. A
// refused one is named by its length and why, never shown, so startup's net.Listen error can never
// quote it.
func TestAListenAddressIsHostColonANumericPortAndARefusedOneIsNeverShown(t *testing.T) {
	for _, ok := range []string{"127.0.0.1:8080", ":8080", "[::1]:8080", "localhost:0", "0.0.0.0:65535", "byward.internal:8443",
		"[fe80::1%lo0]:8080", "[fe80::1%ü]:8080", "byward.internal.:8443", "127.0.0.1:000080", "my_byward:8080",
		"[fe80::1%eth0]:80", "[::ffff:127.0.0.1]:80", "[2001:db8:0:0:0:0:0:1]:80",
		// A zone is a name an interface can have (#638): Linux's and macOS's, 15 bytes at most, or an
		// interface index, which Go takes as a number.
		"[fe80::1%en0]:80", "[fe80::1%utun3]:0", "[fe80::1%bridge100]:0", "[fe80::1%2]:80", "[fe80::1%abcdefghijklmno]:0",
		// A hyphen inside a label and an internationalized name in its xn-- form keep the host name rule.
		"a-b.example:8080", "xn--bcher-kva.example:8080"} {
		for _, name := range []string{"BYWARD_LISTEN", "BYWARD_INTERNAL_LISTEN"} {
			if _, err := load(t, nil, "BYWARD_LISTEN=127.0.0.1:1", name+"="+ok); err != nil {
				t.Errorf("%s=%q: %v", name, ok, err)
			}
		}
	}
	for _, tc := range []struct{ value, why string }{
		{"8080", "it is not host:port"},
		{"https://u:" + canaryText + "@h.example/x", "it is not host:port"},
		{"//h.example/x?k=" + canaryText + ":80", "its host " + ruleNameChar + "1" + ruleNameChars},
		{"h.example..:80", "it has a host that is neither an IP address nor a host name"},
		{".:80", "it has a host that is neither an IP address nor a host name"},     // "." once its trailing dot is stripped
		{"[::g]:80", "it has a host that is neither an IP address nor a host name"}, // no name, so no character place
		// "~" is a host character in RFC 3986 that no DNS name holds (ADR-0032 §3, D4). validHostName
		// refuses it too (#524), but the character rule comes first and names its place.
		{"s3cret~" + canaryText + ":80", "its host " + ruleNameChar + "7" + ruleNameChars},
		{"my$byward:80", "its host " + ruleNameChar + "3" + ruleNameChars},
		// The host is read before the port, so a bad host is named even beside a bad port.
		{"s3cret~" + canaryText + ":http", "its host " + ruleNameChar + "7" + ruleNameChars},
		{"bÿward:80", "its host " + ruleNotASCII},
		{"127.0.0.1:" + canaryText, "it has a port that is not a number"},
		{"127.0.0.1:http", "it has a port that is not a number"},
		{"127.0.0.1:", "it has a port that is not a number"},
		{"127.0.0.1:65536", "it has a port that is not a number from 0 to 65535"},
		{"127.0.0.1:+80", "it has a port that is not a number"},
		{"127.0.0.1:-1", "it has a port that is not a number"},
		{"127.0.0.1:99999999999999999999", "it has a port that is not a number from 0 to 65535"},
		{"[my_mcp]:80", "it has brackets that do not enclose an IPv6 address alone"},
		{"[a.b.]:80", "it has brackets that do not enclose an IPv6 address alone"},
		{"[]:80", "it has brackets that do not enclose an IPv6 address alone"},
		{"[1.2.3.4]:80", "it has brackets that do not enclose an IPv6 address alone"},
		{"[" + canaryText + "]:80", "it has brackets that do not enclose an IPv6 address alone"},
		// The brackets reason wins over the host and port reasons, and "is not host:port" wins over it.
		{"[a..b]:80", "it has brackets that do not enclose an IPv6 address alone"},
		{"[a b]:80", "it has brackets that do not enclose an IPv6 address alone"}, // before the host name characters too
		{"[1.2.3.4]:http", "it has brackets that do not enclose an IPv6 address alone"},
		{"[::1]", "it is not host:port"},
		// A zone no interface can be named, by Linux's rule plus no control character (#638); bytes, as
		// the kernel reads them, so à (C3 A0) holds its non-breaking space byte, though ü loads.
		{"[::1%x y]:80", "it " + ruleZone},
		{"[::1%x\ty]:80", "it " + ruleZone},
		{"[::1%x\x01y]:80", "it " + ruleZone},
		{"[::1%x\x7fy]:80", "it " + ruleZone},
		{"[::1%]:80", "it " + ruleZone},
		{"[::1%abcdefghijklmnop]:80", "it " + ruleZone},
		{"[::1%.]:80", "it " + ruleZone},
		{"[::1%..]:80", "it " + ruleZone},
		{"[::1%a/b]:80", "it " + ruleZone},
		{"[::1%/x]:80", "it " + ruleZone},
		{"[::1%x\ny]:80", "it " + ruleZone},
		{"[::1%x\vy]:80", "it " + ruleZone},
		{"[::1%x\x1fy]:80", "it " + ruleZone},
		{"[::1% %a]:80", "it " + ruleZone},
		{"[::ffff:1.2.3.4%x y]:80", "it " + ruleZone}, // an IPv4-mapped IPv6 address has a zone too
		{"[::1%a:b]:80", "it " + ruleZone},
		{"[::1%\u00e0]:80", "it " + ruleZone},
		{"[::1%" + canaryText + " x]:80", "it " + ruleZone},
		// A zone only on an IPv6 address: a '%' after anything else is part of the host, which gets the host
		// reason: after an address that is no IP address, or after an IPv4 one (the ':' after the '%' lets
		// it past the brackets).
		{"[zz:zz%a b]:80", "it has a host that is neither an IP address nor a host name"},
		{"[1.2.3.4%a:b]:80", "it has a host that is neither an IP address nor a host name"},
		// A '%' in a name is a character no host name holds.
		{"my% x:80", "its host " + ruleNameChar + "3" + ruleNameChars},
		// A ':' inside the brackets passes them, as host.Parse's rule does; a host that is still no IPv6
		// address gets the host reason.
		{"[a:b]:80", "it has a host that is neither an IP address nor a host name"},
		{"[::1x]:80", "it has a host that is neither an IP address nor a host name"},
	} {
		for _, s := range []struct{ env, want string }{
			{"BYWARD_LISTEN", "host:port such as 127.0.0.1:8080"},
			{"BYWARD_INTERNAL_LISTEN", "host:port such as 127.0.0.1:9090, or empty"},
		} {
			want := fmt.Sprintf("%s: want %s; got a value (%d characters, not shown): %s", s.env, s.want, length(tc.value), tc.why)
			_, err := load(t, nil, s.env+"="+tc.value)
			if !isConfigError(err) || err.Error() != want || holdsCanary(err.Error()) {
				t.Errorf("%s=%q: %v, want the error %q and never the value", s.env, tc.value, err, want)
			}
		}
	}
}

// A listen address set to nothing is as if unset (#428): the default. (A flag set to nothing is
// refused: TestAFlagSetToNothingIsRefusedAsGiven.)
func TestAListenAddressSetToNothingIsTheDefault(t *testing.T) {
	c, err := load(t, nil, "BYWARD_LISTEN=")
	if err != nil {
		t.Fatalf("BYWARD_LISTEN=: %v, want the default", err)
	}
	if c.Listen != "127.0.0.1:8080" {
		t.Errorf("BYWARD_LISTEN=: listen %q, want the default 127.0.0.1:8080", c.Listen)
	}
}

// Where the Values do not hold the setting, as a Config built by hand has none, doctor shows its
// upstream URL and issuer as Hidden: never as nothing a caller could take for unset, nor as given.
func TestValuesThatDoNotHoldTheSettingShowTheUpstreamURLAndIssuerAsHidden(t *testing.T) {
	for name, got := range map[string]string{
		"its upstream URL":                (&Config{UpstreamURL: &url.URL{Scheme: "https", Host: "up.example", RawQuery: "k=" + canaryText}}).ShownUpstreamURL(),
		"Values without the upstream URL": (&Config{UpstreamURL: &url.URL{Scheme: "https", Host: "up.example", RawQuery: "k=" + canaryText}, Values: &Values{}}).ShownUpstreamURL(),
		"its issuer":                      (&Config{OIDCIssuer: "https://u:" + canaryText + "@idp.example"}).ShownIssuer(),
		"Values without the issuer":       (&Config{OIDCIssuer: "https://idp.example/x?k=" + canaryText, Values: &Values{}}).ShownIssuer(),
	} {
		if got != logging.Hidden {
			t.Errorf("%s shows %q, want %q", name, got, logging.Hidden)
		}
	}
}

// Doctor names the upstream URL through its shape, as parsed (the aud); a stdio upstream has none, so
// it is Hidden.
func TestTheUpstreamURLIsShownAsParsedThroughItsShapeOrAsHiddenForAStdioUpstream(t *testing.T) {
	for _, tc := range []struct {
		name, want string
		env        []string
	}{
		{"its query left out", "https://up.example/mcp?…", []string{"BYWARD_UPSTREAM_URL=HTTPS://up.example/mcp?api_key=" + canaryText}},
		{"a stdio upstream, which has no URL", logging.Hidden, []string{"BYWARD_UPSTREAM_URL=", `BYWARD_UPSTREAM_COMMAND=["/usr/bin/server"]`}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, err := load(t, nil, tc.env...)
			if err != nil {
				t.Fatal(err)
			}
			if got := c.ShownUpstreamURL(); got != tc.want {
				t.Errorf("shown as %q, want %q", got, tc.want)
			}
		})
	}
}

// Doctor names the issuer through its shape as given, or, the setting unset, as the preset's own.
func TestTheIssuerIsShownThroughItsShapeOrAsThePresetsOwn(t *testing.T) {
	for _, tc := range []struct{ name, issuer, want string }{
		{"an issuer set, its path parameters left out", "https://idp.example/realms/a;k=" + canaryText, "https://idp.example/realms/a;…"},
		{"a preset's own issuer, the setting unset", "", "https://accounts.google.com"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, err := loadOIDC(t, func(env []string) []string {
				return with("BYWARD_IDP=google", "BYWARD_OIDC_ISSUER="+tc.issuer)(without("BYWARD_IDP", "BYWARD_OIDC_ISSUER")(env))
			})
			if err != nil {
				t.Fatal(err)
			}
			if got := c.ShownIssuer(); got != tc.want {
				t.Errorf("shown as %q, want %q", got, tc.want)
			}
		})
	}
}

// Config refuses a client denylist entry that does not parse as a URL only when it holds an @, a form
// that can carry a credential; any other is left to client registration, which refuses it at wiring.
func TestADenylistEntryThatDoesNotParseWithoutAnAtIsLoadedAsGivenForRegistration(t *testing.T) {
	c, err := load(t, nil, "BYWARD_CLIENT_DENYLIST=https://a%zz.example/x")
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(c.ClientDenylist, []string{"https://a%zz.example/x"}) {
		t.Fatalf("got %v, want it loaded as given", c)
	}
}

// An entry of BYWARD_CLIENT_DENYLIST that client registration refuses at wiring is named by its place
// and its length in characters, never shown, in the format of every refusal config makes.
func TestADenylistEntryRefusedAtWiringIsNamedByItsPlaceAndLength(t *testing.T) {
	const (
		want   = "BYWARD_CLIENT_DENYLIST: want a CIMD client ID (an https URL) or a host name such as app.example; got "
		reason = "it is not a client ID metadata document URL: only port 443 is fetched"
	)
	for _, tc := range []struct {
		name, list string
		index      int
		want       string
	}{
		{"the first entry", "https://app.example:8443/bü-" + canaryText + ".json, good.example", 0, want + "entry 1 of 2 (43 characters, not shown): " + reason},
		{"the second entry", "good.example, https://app.example:8443/c.json", 1, want + "entry 2 of 2 (31 characters, not shown): " + reason},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, err := load(t, nil, "BYWARD_CLIENT_DENYLIST="+tc.list)
			if err != nil {
				t.Fatal(err)
			}
			if got := c.RefusedDenylistEntry(tc.index, reason); !isConfigError(got) || got.Error() != tc.want {
				t.Errorf("got %v, want %q", got, tc.want)
			}
		})
	}
}

// A refused IdP brings its own refusal only: the settings that depend on the IdP are not refused
// for it too, as an IdP of nothing.
func TestARefusedIdPBringsNoOtherSettingsRefusalOfIt(t *testing.T) {
	const want = "BYWARD_IDP: want entra, oidc, google, okta, auth0 or keycloak; got a value (5 characters, not shown): it is not one of them"
	for name, env := range map[string][]string{
		"app-only tokens": {"BYWARD_IDP=bogus", "BYWARD_APP_TOKENS=entra", "BYWARD_APP_ROLES=r"},
		"On-Behalf-Of":    {"BYWARD_IDP=bogus", "BYWARD_OBO_SCOPES=https://graph.microsoft.com/User.Read"},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := load(t, nil, env...); !isConfigError(err) || err.Error() != want {
				t.Fatalf("err = %v, want only %q", err, want)
			}
		})
	}
}

// An Entra tenant left unset is refused as required, and only so.
func TestAnUnsetTenantIsRefusedOnlyAsRequired(t *testing.T) {
	_, err := load(t, nil, "BYWARD_ENTRA_TENANT=")
	if !isConfigError(err) || !strings.HasPrefix(err.Error(), "BYWARD_ENTRA_TENANT is required") || strings.Contains(err.Error(), "want the tenant ID") {
		t.Fatalf("err = %v, want only the tenant's required error", err)
	}
}

// The server-matched lists warn about the entries client registration cannot tell apart, by place
// and the setting as given (ADR-0032 R7): a CIMD list's entries folded by case, the denylist's by the
// key client registration gives (here a stand-in, strings.ToLower; registration's
// TestADenylistKeyIsSharedExactlyByEntriesDenyingTheSame pins the real one), and an allowed host that
// is also trusted, which is always allowed. A denylist host that is also trusted is no duplicate: the
// lists do different things.
func TestTheServerMatchedListsWarnAboutEntriesRegistrationCannotTellApart(t *testing.T) {
	const same, trusted = "name the same %s once folded (%s)", "is also in %s, whose hosts are always allowed"
	const denyFolds = "case, a trailing dot, an internationalized host by its xn-- form, an IP address's spelling, a default port, percent-encoding in the path"
	for _, tc := range []struct {
		name string
		args []string
		env  []string
		want []ListWarning
	}{
		{"trusted hosts by case", nil, []string{"BYWARD_CIMD=true", "BYWARD_CIMD_TRUSTED_HOSTS=claude.ai,Claude.AI"}, []ListWarning{
			{"BYWARD_CIMD_TRUSTED_HOSTS", "entries 1 and 2 of 2 " + fmt.Sprintf(same, "host", "case"), "remove one of them"}}},
		{"allowed hosts by case", nil, []string{"BYWARD_CIMD=true", "BYWARD_CIMD_ALLOWED_HOSTS=a.example,b.example,B.EXAMPLE"}, []ListWarning{
			{"BYWARD_CIMD_ALLOWED_HOSTS", "entries 2 and 3 of 3 " + fmt.Sprintf(same, "host", "case"), "remove one of them"}}},
		{"an allowed host that is also trusted", nil, []string{"BYWARD_CIMD=true", "BYWARD_CIMD_TRUSTED_HOSTS=claude.ai", "BYWARD_CIMD_ALLOWED_HOSTS=a.example,CLAUDE.ai"}, []ListWarning{
			{"BYWARD_CIMD_ALLOWED_HOSTS", "entry 2 of 2 " + fmt.Sprintf(trusted, "BYWARD_CIMD_TRUSTED_HOSTS"), "remove it"}}},
		{"named as given", []string{"--cimd-trusted-hosts", "claude.ai", "--cimd-allowed-hosts", "claude.ai,a.example,A.example"}, []string{"BYWARD_CIMD=true"}, []ListWarning{
			{"--cimd-allowed-hosts", "entry 1 of 3 " + fmt.Sprintf(trusted, "--cimd-trusted-hosts"), "remove it"},
			{"--cimd-allowed-hosts", "entries 2 and 3 of 3 " + fmt.Sprintf(same, "host", "case"), "remove one of them"}}},
		{"denylist entries with one key", nil, []string{"BYWARD_CLIENT_DENYLIST=a.example,B.example,https://c.example/x,b.EXAMPLE,a.example"}, []ListWarning{
			{"BYWARD_CLIENT_DENYLIST", "entries 2 and 4 of 5 " + fmt.Sprintf(same, "host or client ID", denyFolds), "remove one of them"},
			{"BYWARD_CLIENT_DENYLIST", "entries 1 and 5 of 5 " + fmt.Sprintf(same, "host or client ID", denyFolds), "remove one of them"}}},
		{"denylist named as given", []string{"--client-denylist", "a.example,A.example"}, nil, []ListWarning{
			{"--client-denylist", "entries 1 and 2 of 2 " + fmt.Sprintf(same, "host or client ID", denyFolds), "remove one of them"}}},
		// Removing every allowed host would empty the list, which allows any host: no "remove it" then.
		{"allowed hosts that are all trusted", nil, []string{"BYWARD_CIMD=true", "BYWARD_CIMD_TRUSTED_HOSTS=claude.ai,vscode.dev", "BYWARD_CIMD_ALLOWED_HOSTS=claude.ai,VSCODE.dev"}, nil},
		{"a denylist host that is also trusted", nil, []string{"BYWARD_CIMD=true", "BYWARD_CIMD_TRUSTED_HOSTS=claude.ai", "BYWARD_CLIENT_DENYLIST=claude.ai"}, nil},
		{"distinct entries", nil, []string{"BYWARD_CIMD=true", "BYWARD_CIMD_TRUSTED_HOSTS=claude.ai,app.claude.ai", "BYWARD_CIMD_ALLOWED_HOSTS=a.example,b.example",
			"BYWARD_CLIENT_DENYLIST=app.example,https://app.example/c.json"}, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, err := load(t, tc.args, tc.env...)
			if err != nil {
				t.Fatal(err)
			}
			if got := append(c.ListWarnings, c.DenylistWarnings(strings.ToLower)...); !slices.Equal(got, tc.want) {
				t.Fatalf("warnings %+v\nwant %+v", got, tc.want)
			}
		})
	}
}

// The browser-matched lists warn about the entries a browser cannot tell apart, each pair by place and
// the setting as given, never by value (ADR-0032 R7): folded by case, an IP address's spelling and a
// default port; a third copy is paired with the first; each entry that is the public URL's own is
// named once, never also as a pair; distinct entries warn nothing (the startup, check and doctor
// output: internal/server's TestDuplicateHostListEntriesAreAWarningByPlaceAlike).
func TestDuplicateAllowedHostsAndOriginsWarnByPlace(t *testing.T) {
	const same, self = "name the same %s once folded (case, an IP address's spelling, a default port)", "is the public URL's %s, which is always allowed"
	for _, tc := range []struct {
		name string
		env  []string
		want []ListWarning
	}{
		{"case, three copies", []string{"BYWARD_ALLOWED_HOSTS=a.example,A.example,a.EXAMPLE"}, []ListWarning{
			{"BYWARD_ALLOWED_HOSTS", "entries 1 and 2 of 3 " + fmt.Sprintf(same, "host"), "remove one of them"},
			{"BYWARD_ALLOWED_HOSTS", "entries 1 and 3 of 3 " + fmt.Sprintf(same, "host"), "remove one of them"}}},
		{"an address with and without a default port", []string{"BYWARD_ALLOWED_HOSTS=127.0.0.1,127.0.0.1:443,[::1],[::1]:80"}, []ListWarning{
			{"BYWARD_ALLOWED_HOSTS", "entries 1 and 2 of 4 " + fmt.Sprintf(same, "host"), "remove one of them"},
			{"BYWARD_ALLOWED_HOSTS", "entries 3 and 4 of 4 " + fmt.Sprintf(same, "host"), "remove one of them"}}},
		{"two entries that are the public URL's own", []string{"BYWARD_ALLOWED_HOSTS=mcp.example.com,MCP.example.com:443"}, []ListWarning{
			{"BYWARD_ALLOWED_HOSTS", "entry 1 of 2 " + fmt.Sprintf(self, "host"), "remove it"},
			{"BYWARD_ALLOWED_HOSTS", "entry 2 of 2 " + fmt.Sprintf(self, "host"), "remove it"}}},
		{"origins by address spelling and default port", []string{"BYWARD_ALLOWED_ORIGINS=https://[::1],https://[::1]:443,https://mcp.example.com"}, []ListWarning{
			{"BYWARD_ALLOWED_ORIGINS", "entries 1 and 2 of 3 " + fmt.Sprintf(same, "origin"), "remove one of them"},
			{"BYWARD_ALLOWED_ORIGINS", "entry 3 of 3 " + fmt.Sprintf(self, "origin"), "remove it"}}},
		{"another scheme is another origin", []string{"BYWARD_ALLOWED_ORIGINS=https://a.example,http://a.example,http://a.example:443"}, nil},
		{"a pair after a distinct first entry, named by its own places", []string{"BYWARD_ALLOWED_HOSTS=a.example,b.example,B.example"}, []ListWarning{
			{"BYWARD_ALLOWED_HOSTS", "entries 2 and 3 of 3 " + fmt.Sprintf(same, "host"), "remove one of them"}}},
		{"the public URL's host with another scheme's default port", []string{"BYWARD_PUBLIC_URL=https://mcp.example.com:80/mcp", "BYWARD_ALLOWED_HOSTS=mcp.example.com"}, []ListWarning{
			{"BYWARD_ALLOWED_HOSTS", "entry 1 of 1 " + fmt.Sprintf(self, "host"), "remove it"}}},
		{"distinct entries", []string{"BYWARD_ALLOWED_HOSTS=a.example,a.example:8443,b.example,127.0.0.1,[::1]",
			"BYWARD_ALLOWED_ORIGINS=https://a.example,http://a.example,https://a.example:8443,https://127.0.0.1"}, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, err := load(t, nil, tc.env...)
			if err != nil {
				t.Fatal(err)
			}
			if !slices.Equal(c.ListWarnings, tc.want) {
				t.Fatalf("warnings %+v\nwant %+v", c.ListWarnings, tc.want)
			}
		})
	}
}

// A duplicate warning names the list as the operator gave it (#623): by its flag when given by flag.
func TestADuplicateAllowedHostGivenByFlagIsNamedByItsFlag(t *testing.T) {
	c, err := load(t, []string{"--allowed-hosts=a.example,A.example"})
	if err != nil {
		t.Fatal(err)
	}
	want := []ListWarning{{"--allowed-hosts", "entries 1 and 2 of 2 name the same host once folded (case, an IP address's spelling, a default port)", "remove one of them"}}
	if !slices.Equal(c.ListWarnings, want) {
		t.Fatalf("warnings %+v\nwant %+v", c.ListWarnings, want)
	}
}
