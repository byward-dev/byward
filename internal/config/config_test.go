package config

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"slices"
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

func TestInvalidSettingsAreRejectedNamingTheSetting(t *testing.T) {
	cases := []struct {
		name, env, want string
	}{
		{"required", "BYWARD_PUBLIC_URL=", "BYWARD_PUBLIC_URL is required"},
		{"trailing slash", "BYWARD_PUBLIC_URL=https://mcp.example.com/mcp/", "BYWARD_PUBLIC_URL"},
		{"no path", "BYWARD_PUBLIC_URL=https://mcp.example.com", "BYWARD_PUBLIC_URL"},
		{"query", "BYWARD_PUBLIC_URL=https://mcp.example.com/mcp?x=1", "must not have a query or fragment"},
		{"fragment", "BYWARD_PUBLIC_URL=https://mcp.example.com/mcp#f", "must not have a query or fragment"},
		{"http public", "BYWARD_PUBLIC_URL=http://mcp.example.com/mcp", "must use https"},
		{"http loopback without dev", "BYWARD_PUBLIC_URL=http://127.0.0.1:8080/mcp", "needs --dev"},
		// #344: the public host joins the public Host allow-list, so it follows BYWARD_ALLOWED_HOSTS' name rule.
		{"public host with a trailing dot", "BYWARD_PUBLIC_URL=https://mcp.example.com./mcp", `BYWARD_PUBLIC_URL: "mcp.example.com." is not a host[:port]: a host name has only letters, digits and - . _ ~, and no empty label (no leading or double dot; drop a trailing one)`},
		{"public host empty, with a port", "BYWARD_PUBLIC_URL=https://:8443/mcp", `BYWARD_PUBLIC_URL: give a host, e.g. https://mcp.example.com/mcp`},
		{"public host with a double dot", "BYWARD_PUBLIC_URL=https://a..b/mcp", `BYWARD_PUBLIC_URL: "a..b" is not a host[:port]: a host name`},
		{"public host with a wildcard", "BYWARD_PUBLIC_URL=https://a*b/mcp", `BYWARD_PUBLIC_URL: "a*b" is not a host[:port]: a host name`},
		// #353: the port and the zone follow BYWARD_ALLOWED_HOSTS' rules too.
		{"public URL with an empty port", "BYWARD_PUBLIC_URL=https://a.example:/mcp", `BYWARD_PUBLIC_URL: "a.example:" is not a host[:port]: give host, host:port, an IPv6 address, [IPv6] or [IPv6]:port, with a port from 1 to 65535 and no IPv6 zone`},
		{"public URL with a port over 65535", "BYWARD_PUBLIC_URL=https://a.example:65536/mcp", `BYWARD_PUBLIC_URL: "a.example:65536" is not a host[:port]`},
		{"unicode public host with a port", "BYWARD_PUBLIC_URL=https://bücher.example:8443/mcp", `BYWARD_PUBLIC_URL: the host "bücher.example:8443" is not ASCII`},
		{"public URL with port 0", "BYWARD_PUBLIC_URL=https://a.example:0/mcp", `BYWARD_PUBLIC_URL: "a.example:0" is not a host[:port]`},
		{"public URL with a leading-zero port", "BYWARD_PUBLIC_URL=https://a.example:0443/mcp", `BYWARD_PUBLIC_URL: "a.example:0443" is not a host[:port]`},
		{"public URL with an IPv6 zone", "BYWARD_PUBLIC_URL=https://[fe80::1%25eth0]/mcp", `BYWARD_PUBLIC_URL: "[fe80::1%eth0]" is not a host[:port]: give host`},
		{"public URL with an IPv6 zone and a port", "BYWARD_PUBLIC_URL=https://[fe80::1%25eth0]:8443/mcp", `BYWARD_PUBLIC_URL: "[fe80::1%eth0]:8443" is not a host[:port]`},
		// Browsers and MCP clients send IDN hosts in ASCII (xn--) form, so a Unicode host never matches.
		{"unicode public host", "BYWARD_PUBLIC_URL=https://bücher.example/mcp", `BYWARD_PUBLIC_URL: the host "bücher.example" is not ASCII`},
		{"escaped unicode public host", "BYWARD_PUBLIC_URL=https://b%C3%BCcher.example/mcp", `BYWARD_PUBLIC_URL: the host "bücher.example" is not ASCII`},
		{"unicode allowed origin", "BYWARD_ALLOWED_ORIGINS=https://bücher.example", `BYWARD_ALLOWED_ORIGINS: "https://bücher.example": the host "bücher.example" is not ASCII`},
		{"origin with a leading-zero port", "BYWARD_ALLOWED_ORIGINS=https://app.example.com:0443", `BYWARD_ALLOWED_ORIGINS: "https://app.example.com:0443": "app.example.com:0443" is not a host[:port]`},
		{"origin with a port over 65535", "BYWARD_ALLOWED_ORIGINS=https://app.example.com:99999", `BYWARD_ALLOWED_ORIGINS: "https://app.example.com:99999": "app.example.com:99999" is not a host[:port]`},
		{"origin with port 0", "BYWARD_ALLOWED_ORIGINS=https://app.example.com:0", `BYWARD_ALLOWED_ORIGINS: "https://app.example.com:0": "app.example.com:0" is not a host[:port]`},
		{"origin with an empty port", "BYWARD_ALLOWED_ORIGINS=https://app.example.com:", `BYWARD_ALLOWED_ORIGINS: "https://app.example.com:": "app.example.com:" is not a host[:port]`},
		{"origin with an empty label", "BYWARD_ALLOWED_ORIGINS=https://a..b", `BYWARD_ALLOWED_ORIGINS: "https://a..b": "a..b" is not a host[:port]: a host name`},
		{"origin with a leading dot", "BYWARD_ALLOWED_ORIGINS=https://.app.example.com", `BYWARD_ALLOWED_ORIGINS: "https://.app.example.com": ".app.example.com" is not a host[:port]: a host name`},
		{"origin with a trailing dot", "BYWARD_ALLOWED_ORIGINS=https://app.example.com.", `BYWARD_ALLOWED_ORIGINS: "https://app.example.com.": "app.example.com." is not a host[:port]: a host name`},
		{"origin with an IPv6 zone", "BYWARD_ALLOWED_ORIGINS=https://[fe80::1%25eth0]", `BYWARD_ALLOWED_ORIGINS: "https://[fe80::1%25eth0]": "[fe80::1%eth0]" is not a host[:port]`},
		{"origin with a shortened IPv4 address", "BYWARD_ALLOWED_ORIGINS=https://127.1", `BYWARD_ALLOWED_ORIGINS: "https://127.1": "127.1" is not an IPv4 address in dotted decimal, the only form browsers send`},
		{"origin ending in an upper-case hex label", "BYWARD_ALLOWED_ORIGINS=https://192.168.0.0xFF", `BYWARD_ALLOWED_ORIGINS: "https://192.168.0.0xFF": "192.168.0.0xFF" is not an IPv4 address in dotted decimal`},
		{"origin with an IPv4 part over 255", "BYWARD_ALLOWED_ORIGINS=https://10.0.0.999", `BYWARD_ALLOWED_ORIGINS: "https://10.0.0.999": "10.0.0.999" is not an IPv4 address in dotted decimal`},
		{"origin with user info", "BYWARD_ALLOWED_ORIGINS=https://user@app.example.com", `is not an origin (scheme://host[:port]): it has a user name or password`},
		{"origin that is not a URL", "BYWARD_ALLOWED_ORIGINS=https://[::1", `BYWARD_ALLOWED_ORIGINS: "https://[::1" is not an origin`},
		{"origin ending in a hex label of every hex digit", "BYWARD_ALLOWED_ORIGINS=https://a.0x0123456789abcdef", `BYWARD_ALLOWED_ORIGINS: "https://a.0x0123456789abcdef": "a.0x0123456789abcdef" is not an IPv4 address in dotted decimal`},
		{"origin ending in a bare 0", "BYWARD_ALLOWED_ORIGINS=https://a.0", `BYWARD_ALLOWED_ORIGINS: "https://a.0": "a.0" is not an IPv4 address in dotted decimal`},
		{"origin ending in a bare 0x", "BYWARD_ALLOWED_ORIGINS=https://a.0x", `BYWARD_ALLOWED_ORIGINS: "https://a.0x": "a.0x" is not an IPv4 address in dotted decimal`},
		{"origin ending in a label of every digit", "BYWARD_ALLOWED_ORIGINS=https://a.1234567890", `BYWARD_ALLOWED_ORIGINS: "https://a.1234567890": "a.1234567890" is not an IPv4 address in dotted decimal`},
		{"origin with a shortened IPv4 address and a port", "BYWARD_ALLOWED_ORIGINS=http://127.1:8080", `BYWARD_ALLOWED_ORIGINS: "http://127.1:8080": "127.1" is not an IPv4 address in dotted decimal`},
		{"origin with a hex IPv4 label", "BYWARD_ALLOWED_ORIGINS=https://0x7f.0.0.1", `BYWARD_ALLOWED_ORIGINS: "https://0x7f.0.0.1": "0x7f.0.0.1" is not an IPv4 address in dotted decimal`},
		{"origin with a fragment", "BYWARD_ALLOWED_ORIGINS=https://app.example.com#", `is not an origin (scheme://host[:port]): it has a query or a fragment`},
		{"origin with an empty query", "BYWARD_ALLOWED_ORIGINS=https://app.example.com?", `is not an origin (scheme://host[:port]): it has a query or a fragment`},
		{"unicode allowed host", "BYWARD_ALLOWED_HOSTS=bücher.example:8443", `BYWARD_ALLOWED_HOSTS: the host "bücher.example:8443" is not ASCII`},
		{"origin with path", "BYWARD_ALLOWED_ORIGINS=https://a.example/path", "BYWARD_ALLOWED_ORIGINS"},
		{"host with path", "BYWARD_ALLOWED_HOSTS=a.example/x", `BYWARD_ALLOWED_HOSTS: "a.example/x" is not a host[:port]: give host`},
		{"host with space", "BYWARD_ALLOWED_HOSTS=a b", `BYWARD_ALLOWED_HOSTS: "a b" is not a host[:port]: give host`},
		{"bracketed host name", "BYWARD_ALLOWED_HOSTS=[mcp.internal.example]", `BYWARD_ALLOWED_HOSTS: "[mcp.internal.example]" is not a host[:port]: give host, host:port, an IPv6 address, [IPv6] or [IPv6]:port`},
		{"bracketed IPv4 with a port", "BYWARD_ALLOWED_HOSTS=[127.0.0.1]:8443", `BYWARD_ALLOWED_HOSTS: "[127.0.0.1]:8443" is not a host[:port]`},
		{"IPv6 with a zone", "BYWARD_ALLOWED_HOSTS=[fe80::1%eth0]:8443", `BYWARD_ALLOWED_HOSTS: "[fe80::1%eth0]:8443" is not a host[:port]`},
		{"unclosed bracket", "BYWARD_ALLOWED_HOSTS=[::1", `BYWARD_ALLOWED_HOSTS: "[::1" is not a host[:port]`},
		{"name with a closing bracket", "BYWARD_ALLOWED_HOSTS=mcp.example]", `BYWARD_ALLOWED_HOSTS: "mcp.example]" is not a host[:port]: give host`},
		{"name with an opening bracket", "BYWARD_ALLOWED_HOSTS=mcp.example[", `BYWARD_ALLOWED_HOSTS: "mcp.example[" is not a host[:port]: give host`},
		{"name with user info", "BYWARD_ALLOWED_HOSTS=a@b", "BYWARD_ALLOWED_HOSTS: " + logging.Hidden + ` is not a host[:port]: a host name has only letters, digits and - . _ ~`},
		{"name with a query", "BYWARD_ALLOWED_HOSTS=a?b", "BYWARD_ALLOWED_HOSTS: " + logging.Hidden + ` is not a host[:port]: a host name`},
		{"name with a fragment", "BYWARD_ALLOWED_HOSTS=a#b", "BYWARD_ALLOWED_HOSTS: " + logging.Hidden + ` is not a host[:port]: a host name`},
		{"name with a backslash", "BYWARD_ALLOWED_HOSTS=a\\b", `BYWARD_ALLOWED_HOSTS: "a\\b" is not a host[:port]: a host name`},
		{"name with a semicolon", "BYWARD_ALLOWED_HOSTS=a;b", `BYWARD_ALLOWED_HOSTS: "a;b" is not a host[:port]: a host name`},
		{"name with a tab", "BYWARD_ALLOWED_HOSTS=a\tb", `BYWARD_ALLOWED_HOSTS: "a\tb" is not a host[:port]: a host name`},
		{"name that is a wildcard", "BYWARD_ALLOWED_HOSTS=*", `BYWARD_ALLOWED_HOSTS: "*" is not a host[:port]: a host name`},
		{"name with a port and a bad character", "BYWARD_ALLOWED_HOSTS=a*b:8080", `BYWARD_ALLOWED_HOSTS: "a*b:8080" is not a host[:port]: a host name`},
		{"trailing dot", "BYWARD_ALLOWED_HOSTS=mcp.example.com.", `BYWARD_ALLOWED_HOSTS: "mcp.example.com." is not a host[:port]: a host name has only letters, digits and - . _ ~, and no empty label (no leading or double dot; drop a trailing one)`},
		{"trailing dot with a port", "BYWARD_ALLOWED_HOSTS=mcp.example.com.:8443", `BYWARD_ALLOWED_HOSTS: "mcp.example.com.:8443" is not a host[:port]: a host name`},
		{"leading dot", "BYWARD_ALLOWED_HOSTS=.example.com", `BYWARD_ALLOWED_HOSTS: ".example.com" is not a host[:port]: a host name`},
		{"double dot", "BYWARD_ALLOWED_HOSTS=mcp..example.com:8443", `BYWARD_ALLOWED_HOSTS: "mcp..example.com:8443" is not a host[:port]: a host name`},
		{"bracket then an empty port", "BYWARD_ALLOWED_HOSTS=[::1]:", `BYWARD_ALLOWED_HOSTS: "[::1]:" is not a host[:port]`},
		{"bracket then junk", "BYWARD_ALLOWED_HOSTS=[::1]x", `BYWARD_ALLOWED_HOSTS: "[::1]x" is not a host[:port]`},
		{"bracket then digits without a colon", "BYWARD_ALLOWED_HOSTS=[::1]8080", `BYWARD_ALLOWED_HOSTS: "[::1]8080" is not a host[:port]`},
		{"bracket then a junk port", "BYWARD_ALLOWED_HOSTS=[::1]:80a", `BYWARD_ALLOWED_HOSTS: "[::1]:80a" is not a host[:port]`},
		{"host then an empty port", "BYWARD_ALLOWED_HOSTS=localhost:", `BYWARD_ALLOWED_HOSTS: "localhost:" is not a host[:port]`},
		{"host then a junk port", "BYWARD_ALLOWED_HOSTS=localhost:abc", `BYWARD_ALLOWED_HOSTS: "localhost:abc" is not a host[:port]`},
		{"host then a signed port", "BYWARD_ALLOWED_HOSTS=localhost:+80", `BYWARD_ALLOWED_HOSTS: "localhost:+80" is not a host[:port]`},
		{"port 0", "BYWARD_ALLOWED_HOSTS=localhost:0", `BYWARD_ALLOWED_HOSTS: "localhost:0" is not a host[:port]: give host, host:port, an IPv6 address, [IPv6] or [IPv6]:port, with a port from 1 to 65535`},
		{"port over 65535", "BYWARD_ALLOWED_HOSTS=localhost:65536", `BYWARD_ALLOWED_HOSTS: "localhost:65536" is not a host[:port]`},
		{"port with a leading zero", "BYWARD_ALLOWED_HOSTS=localhost:080", `BYWARD_ALLOWED_HOSTS: "localhost:080" is not a host[:port]`},
		{"bracketed port over 65535", "BYWARD_ALLOWED_HOSTS=[::1]:99999", `BYWARD_ALLOWED_HOSTS: "[::1]:99999" is not a host[:port]`},
		{"a port without a host", "BYWARD_ALLOWED_HOSTS=:8080", `BYWARD_ALLOWED_HOSTS: ":8080" is not a host[:port]`},
		{"bare IPv6 with a zone", "BYWARD_ALLOWED_HOSTS=fe80::1%eth0", `BYWARD_ALLOWED_HOSTS: "fe80::1%eth0" is not a host[:port]: give host, host:port, an IPv6 address, [IPv6] or [IPv6]:port, with a port from 1 to 65535 and no IPv6 zone`},
		{"many colons, not IPv6", "BYWARD_ALLOWED_HOSTS=a:b:c", `BYWARD_ALLOWED_HOSTS: "a:b:c" is not a host[:port]`},
		{"listen without port", "BYWARD_LISTEN=8080", "BYWARD_LISTEN"},
		{"log format", "BYWARD_LOG_FORMAT=xml", "BYWARD_LOG_FORMAT"},
		{"two scopes", "BYWARD_SCOPE=a b", "BYWARD_SCOPE"},
		{"documentation not a URL", "BYWARD_RESOURCE_DOCUMENTATION=javascript:x", "BYWARD_RESOURCE_DOCUMENTATION"},
		{"cimd trusted hosts blank", "BYWARD_CIMD_TRUSTED_HOSTS= ,", "BYWARD_CIMD_TRUSTED_HOSTS is set but lists nothing"},
		{"cimd allowed hosts blank", "BYWARD_CIMD_ALLOWED_HOSTS=,", "BYWARD_CIMD_ALLOWED_HOSTS is set but lists nothing"},
		{"cimd host with a scheme", "BYWARD_CIMD_TRUSTED_HOSTS=https://claude.ai", `BYWARD_CIMD_TRUSTED_HOSTS: "https://claude.ai" is not a host name`},
		{"cimd host with a path", "BYWARD_CIMD_TRUSTED_HOSTS=claude.ai/oauth", `BYWARD_CIMD_TRUSTED_HOSTS: "claude.ai/oauth" is not a host name`},
		{"cimd host with user info", "BYWARD_CIMD_ALLOWED_HOSTS=user@claude.example", "BYWARD_CIMD_ALLOWED_HOSTS: " + logging.Hidden + ` is not a host name`},
		// #344: names no client ID can carry, refused as in BYWARD_ALLOWED_HOSTS.
		{"cimd host with a query", "BYWARD_CIMD_ALLOWED_HOSTS=a?b.example", "BYWARD_CIMD_ALLOWED_HOSTS: " + logging.Hidden + ` is not a host name such as claude.ai: a host name has only letters`},
		{"cimd host with a fragment", "BYWARD_CIMD_TRUSTED_HOSTS=a#b.example", "BYWARD_CIMD_TRUSTED_HOSTS: " + logging.Hidden + ` is not a host name`},
		{"cimd host with a semicolon", "BYWARD_CIMD_ALLOWED_HOSTS=a;b.example", `BYWARD_CIMD_ALLOWED_HOSTS: "a;b.example" is not a host name`},
		{"cimd host with a trailing dot", "BYWARD_CIMD_TRUSTED_HOSTS=claude.ai.", `BYWARD_CIMD_TRUSTED_HOSTS: "claude.ai." is not a host name such as claude.ai: a host name has only letters, digits and - . _ ~, and no empty label (no leading or double dot; drop a trailing one)`},
		{"cimd host with a space", "BYWARD_CIMD_TRUSTED_HOSTS=claude .ai", `"claude .ai" is not a host name`},
		{"cimd host with a port", "BYWARD_CIMD_ALLOWED_HOSTS=claude.ai:443", `BYWARD_CIMD_ALLOWED_HOSTS: "claude.ai:443" is not a host name`},
		{"cimd wildcard host", "BYWARD_CIMD_TRUSTED_HOSTS=*.example.com", `"*.example.com" is not a host name`},
		// The name rule comes first: "a*b" lacks a dot too, but a dot would not fix it.
		{"cimd host breaking the rule and without a dot", "BYWARD_CIMD_TRUSTED_HOSTS=a*b", `BYWARD_CIMD_TRUSTED_HOSTS: "a*b" is not a host name such as claude.ai: a host name has only letters`},
		{"cimd single-label host", "BYWARD_CIMD_TRUSTED_HOSTS=localhost", `BYWARD_CIMD_TRUSTED_HOSTS: "localhost" is not a host name such as claude.ai: give a name with at least one dot`},
		{"cimd unicode host", "BYWARD_CIMD_TRUSTED_HOSTS=bücher.example", `BYWARD_CIMD_TRUSTED_HOSTS: the host "bücher.example" is not ASCII`},
		{"client denylist blank", "BYWARD_CLIENT_DENYLIST= ,", "BYWARD_CLIENT_DENYLIST is set but lists nothing"},
		// A host entry follows the CIMD host lists' rule (but may end in a dot), so an entry that could never match a
		// redirect host fails at load instead of denying nothing.
		{"client denylist http URL", "BYWARD_CLIENT_DENYLIST=http://app.example/client.json", `BYWARD_CLIENT_DENYLIST: "http://app.example/client.json" is neither a CIMD client ID (an https URL) nor a host name such as app.example: a host name has only letters`},
		{"client denylist double dot", "BYWARD_CLIENT_DENYLIST=a..b", `BYWARD_CLIENT_DENYLIST: "a..b" is neither a CIMD client ID (an https URL) nor a host name such as app.example: a host name has only letters`},
		{"client denylist leading dot", "BYWARD_CLIENT_DENYLIST=.bad.example", `BYWARD_CLIENT_DENYLIST: ".bad.example" is neither a CIMD client ID (an https URL) nor a host name such as app.example: a host name has only letters`},
		{"client denylist two trailing dots", "BYWARD_CLIENT_DENYLIST=app.example..", `BYWARD_CLIENT_DENYLIST: "app.example.." is neither a CIMD client ID (an https URL) nor a host name such as app.example: a host name has only letters`},
		{"client denylist inner tab", "BYWARD_CLIENT_DENYLIST=bad\tx.example", `BYWARD_CLIENT_DENYLIST: "bad\tx.example" is neither a CIMD client ID (an https URL) nor a host name such as app.example: a host name has only letters`},
		{"client denylist percent-encoding", "BYWARD_CLIENT_DENYLIST=%62ad.example", `BYWARD_CLIENT_DENYLIST: "%62ad.example" is neither a CIMD client ID (an https URL) nor a host name such as app.example: a host name has only letters`},
		{"client denylist brackets", "BYWARD_CLIENT_DENYLIST=[bad].example", `BYWARD_CLIENT_DENYLIST: "[bad].example" is neither a CIMD client ID (an https URL) nor a host name such as app.example: a host name has only letters`},
		{"client denylist host with a port", "BYWARD_CLIENT_DENYLIST=app.example:443", `BYWARD_CLIENT_DENYLIST: "app.example:443" is neither a CIMD client ID (an https URL) nor a host name such as app.example: a host name has only letters`},
		{"client denylist single-label host among good ones", "BYWARD_CLIENT_DENYLIST=app.example,localhost", `BYWARD_CLIENT_DENYLIST: "localhost" is neither a CIMD client ID (an https URL) nor a host name such as app.example: give a name with at least one dot`},
		{"client denylist https without slashes", "BYWARD_CLIENT_DENYLIST=https:app.example", `BYWARD_CLIENT_DENYLIST: "https:app.example" is neither a CIMD client ID (an https URL) nor a host name such as app.example: a host name has only letters`},
		// A browser reads a host ending in a number as IPv4, which it reaches by other spellings too.
		{"client denylist IPv4 address", "BYWARD_CLIENT_DENYLIST=203.0.113.5", `BYWARD_CLIENT_DENYLIST: "203.0.113.5" ends in a number, so a browser reads it as an IPv4 address: one it also reaches by other spellings (127.1, 0x7f000001) that no entry can match (127.1 and 0x7f000001 are 127.0.0.1), or none at all; deny the app by its CIMD client ID or its redirect host's name`},
		{"client denylist short IPv4 address", "BYWARD_CLIENT_DENYLIST=127.1", `BYWARD_CLIENT_DENYLIST: "127.1" ends in a number`},
		{"client denylist IPv4 address with a trailing dot", "BYWARD_CLIENT_DENYLIST=127.1.", `BYWARD_CLIENT_DENYLIST: "127.1." ends in a number`},
		{"client denylist hex IPv4 address", "BYWARD_CLIENT_DENYLIST=127.0x1", `BYWARD_CLIENT_DENYLIST: "127.0x1" ends in a number`},
		{"client denylist host ending in an empty hex number", "BYWARD_CLIENT_DENYLIST=app.0x", `BYWARD_CLIENT_DENYLIST: "app.0x" ends in a number`},
		{"client denylist host ending in every hex digit", "BYWARD_CLIENT_DENYLIST=a.0X0123456789abcdefABCDEF", `BYWARD_CLIENT_DENYLIST: "a.0X0123456789abcdefABCDEF" ends in a number`},
		{"client denylist host ending in every decimal digit", "BYWARD_CLIENT_DENYLIST=a.0123456789", `BYWARD_CLIENT_DENYLIST: "a.0123456789" ends in a number`},
		{"client denylist unicode host with a trailing dot", "BYWARD_CLIENT_DENYLIST=bücher.example.", `BYWARD_CLIENT_DENYLIST: the host "bücher.example." is not ASCII`},
		{"client denylist unicode host", "BYWARD_CLIENT_DENYLIST=bücher.example", `BYWARD_CLIENT_DENYLIST: the host "bücher.example" is not ASCII; give its ASCII (xn--) form`},
		{"gate tenants blank", "BYWARD_GATE_TENANTS=,", "BYWARD_GATE_TENANTS is set but lists nothing"},
		{"gate roles blank", "BYWARD_GATE_ROLES= ,,", "BYWARD_GATE_ROLES is set but lists nothing"},
		{"gate groups blank", "BYWARD_GATE_GROUPS= ", "BYWARD_GATE_GROUPS is set but lists nothing"},
		{"gate email domains blank", "BYWARD_GATE_EMAIL_DOMAINS=,", "BYWARD_GATE_EMAIL_DOMAINS is set but lists nothing"},
		{"gate hosted domains blank", "BYWARD_GATE_HOSTED_DOMAINS=,", "BYWARD_GATE_HOSTED_DOMAINS is set but lists nothing"},
		{"operator name too long", "BYWARD_OPERATOR_NAME=" + strings.Repeat("é", 81), "BYWARD_OPERATOR_NAME: at most 80 characters, got 81"},
		{"operator name with a newline", "BYWARD_OPERATOR_NAME=a\nb", "BYWARD_OPERATOR_NAME: must not contain control or formatting characters"},
		{"operator name with a bidi override", "BYWARD_OPERATOR_NAME=Evil \u202eTI", "BYWARD_OPERATOR_NAME: must not contain control or formatting characters"},
		{"scope description with a bidi override", "BYWARD_SCOPE_DESCRIPTION=Read \u202edashboards", "BYWARD_SCOPE_DESCRIPTION: must not contain control or formatting characters"},
		{"scope description too long", "BYWARD_SCOPE_DESCRIPTION=" + strings.Repeat("x", 201), "BYWARD_SCOPE_DESCRIPTION: at most 200 characters"},
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
	c, err := load(t, nil, "BYWARD_ALLOWED_HOSTS=a,mcp.example.com,mcp.example.com:9765,10.0.0.5:8080,localhost:1,::1,2001:db8::1,[2001:db8::1],[::1]:65535,my_svc~1,xn--bcher-kva.example,Mixed-Case.Example,abcdefghijklmnopqrstuvwxyz.ABCDEFGHIJKLMNOPQRSTUVWXYZ.0123456789")
	want := []string{"a", "mcp.example.com", "mcp.example.com:9765", "10.0.0.5:8080", "localhost:1", "[::1]", "[2001:db8::1]", "[2001:db8::1]", "[::1]:65535", "my_svc~1", "xn--bcher-kva.example", "mixed-case.example", "abcdefghijklmnopqrstuvwxyz.abcdefghijklmnopqrstuvwxyz.0123456789"}
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(c.AllowedHosts, want) {
		t.Fatalf("hosts=%v, want %v", c.AllowedHosts, want)
	}
}

// An allowed host that is an IP address is stored as browsers write it (CanonicalHost), the form the
// TLS certificate names check and the no-auth loopback check read (the Host check canonicalises both
// sides itself, #447). Any other host is only lower-cased, even one ending in a number, which no
// browser sends but a Go client may.
func TestAnAllowedHostIsStoredWithItsAddressAsBrowsersWriteItAndANameOnlyInLowerCase(t *testing.T) {
	for given, stored := range map[string]string{
		"127.1:8080":      "127.0.0.1:8080",
		"2001:DB8:0:0::1": "[2001:db8::1]",
		"MCP.10":          "mcp.10",
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

// CanonicalHost writes a host[:port] as browsers do, whichever spelling it was given in. The
// expected values are what Node 25.1.0's WHATWG URL parser gives for http://<host>/ (checked
// 2026-11-17); a host it refuses (marked) keeps its spelling, in lower case, since no browser sends it.
func TestCanonicalHostWritesAnAddressAsBrowsersDoAndAnyOtherHostInLowerCase(t *testing.T) {
	for given, want := range map[string]string{
		"10.1":                       "10.0.0.1",
		"0x0a.0.0.1":                 "10.0.0.1",
		"010.0.0.1":                  "8.0.0.1",
		"0X10.1":                     "16.0.0.1",
		"0":                          "0.0.0.0",
		"0x":                         "0.0.0.0",
		"1.":                         "0.0.0.1",
		"10.0.0.1.":                  "10.0.0.1",
		"1.256":                      "1.0.1.0",
		"1.16777215":                 "1.255.255.255",
		"1.16777216":                 "1.16777216", // refused: the last of two numbers fills 3 bytes
		"1.0x":                       "1.0.0.0",
		"0x7f000001":                 "127.0.0.1",
		"017700000001":               "127.0.0.1",
		"4294967295":                 "255.255.255.255",
		"0xffffffff":                 "255.255.255.255",
		"127.1:8080":                 "127.0.0.1:8080",
		"4294967296":                 "4294967296",                 // refused: too large
		"256.0.0.1":                  "256.0.0.1",                  // refused
		"1.2.65536":                  "1.2.65536",                  // refused
		"09":                         "09",                         // refused: not octal
		"1..2":                       "1..2",                       // refused
		"a.0X0123456789abcdefABCDEF": "a.0x0123456789abcdefabcdef", // refused: a is not a number
		"mcp.10":                     "mcp.10",                     // refused: mcp is not a number
		"0x0g":                       "0x0g",                       // a name
		"[FE80::1%25ETH0]:80":        "[fe80::1%25eth0]:80",        // refused: a zone, which no URL carries
		"[::FFFF:1.2.3.4]:8080":      "[::ffff:102:304]:8080",      // a mapped address whose byte 14 is not 0
		"FE80::1%ETH0":               "fe80::1%eth0",               // refused: a bare IPv6 address, with a zone
		"0x10000000000000000":        "0x10000000000000000",        // refused: too large, never 0.0.0.0
		"18446744073709551616":       "18446744073709551616",       // refused: too large, never 0.0.0.0
		"1.2.3.4.0":                  "1.2.3.4.0",                  // refused: five numbers (the last, 0, is in range)
		"[127.0.0.1]":                "[127.0.0.1]",                // refused: IPv4 in brackets
		"[FE80::1]X":                 "[fe80::1]x",                 // refused: text after the brackets
		"255.1":                      "255.0.0.1",
		"Mcp.Example":                "mcp.example",
		"[2001:DB8:0:0::1]":          "[2001:db8::1]",
		"[2001:DB8:0:0::1]:8443":     "[2001:db8::1]:8443",
		"[::FFFF:127.0.0.1]":         "[::ffff:7f00:1]",
		"[1:0:0:0:2:0:0:3]":          "[1::2:0:0:3]",
		"[::1.2.3.4]":                "[::102:304]",
		"2001:db8::1":                "[2001:db8::1]", // a bare IPv6 address, a Host header form no URL carries: bracketed
		"[X]":                        "[x]",           // refused
	} {
		if got := CanonicalHost(given); got != want {
			t.Errorf("CanonicalHost(%q) = %q, want %q", given, got, want)
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
// are refused (TestInvalidSettingsAreRejectedNamingTheSetting).
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
	if _, _, err := Load([]string{"extra"}, base, baseFiles); !isConfigError(err) || !strings.Contains(err.Error(), "extra") {
		t.Fatalf("want config error naming the argument, got %v", err)
	}
}

func TestVersionNeedsNoOtherSettings(t *testing.T) {
	_, act, err := Load([]string{"--version", "--json"}, nil, nil)
	if err != nil || !act.Version || !act.JSON {
		t.Fatalf("act=%+v err=%v", act, err)
	}
}

// Secrets are exercised with a test registry: slice 1.1 has no secret settings yet.
var secretReg = []Setting{{Name: "client-secret", Secret: true, Help: "secret"}}

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
	if got.Raw != "s3cret" || got.Source != SourceFile || got.Display() != "<redacted>" {
		t.Fatalf("got %+v display=%q", got, got.Display())
	}
}

func TestSecretFromFlagFileBeatsEnvFile(t *testing.T) {
	v, err := resolve(secretReg, []string{"--client-secret-file", "/a"}, []string{"BYWARD_CLIENT_SECRET_FILE=/b"}, files(map[string]string{"/a": "A", "/b": "B"}), nil)
	if err != nil || v.get("client-secret") != "A" {
		t.Fatalf("got %q err=%v", v.get("client-secret"), err)
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
	if got := v.inlineSecrets(); len(got) != 1 || got[0] != "BYWARD_CLIENT_SECRET" {
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
	if err != nil || !strings.Contains(relaxed, "BYWARD_CLIENT_SECRET") {
		t.Fatalf("with dev: relaxation=%q err=%v", relaxed, err)
	}
}

func TestSecretFileNeedsAFileReader(t *testing.T) {
	_, err := resolve(secretReg, nil, []string{"BYWARD_CLIENT_SECRET_FILE=/run/secrets/x"}, nil, nil)
	if !isConfigError(err) || !strings.Contains(err.Error(), "not available") {
		t.Fatalf("got %v", err)
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
	for _, name := range []string{"BYWARD_ENTRA_TENANT", "BYWARD_ENTRA_CLIENT_ID"} {
		if _, err := load(t, nil, name+"="); !isConfigError(err) || !strings.Contains(err.Error(), name+" is required") {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := load(t, nil, "BYWARD_ENTRA_CLIENT_SECRET_FILE="); !isConfigError(err) || !strings.Contains(err.Error(), "BYWARD_ENTRA_CLIENT_SECRET_FILE, BYWARD_ENTRA_CLIENT_CERTIFICATE_FILE or BYWARD_ENTRA_FEDERATED_TOKEN_FILE is required") {
		t.Errorf("secret: %v", err)
	}
	if _, err := load(t, nil, "BYWARD_ENTRA_TENANT=contoso.onmicrosoft.com"); !isConfigError(err) || !strings.Contains(err.Error(), "want the tenant ID, a GUID") {
		t.Errorf("tenant: %v", err)
	}
	c, err := load(t, nil)
	if err != nil || c.EntraClientSecret != "s3cret-entra" || c.KeysDir == "" {
		t.Fatalf("c=%+v err=%v", c, err)
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
	cfg, _, err = Load(nil, noAuthEnv("BYWARD_OAUTH_RATE_LIMITS=authorize=120, token=600"), nil)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.OAuthRateLimits["authorize"] != 120 || cfg.OAuthRateLimits["token"] != 600 || cfg.OAuthRateLimits["callback"] != 30 {
		t.Errorf("overrides = %v, want authorize 120, token 600 and the other defaults", cfg.OAuthRateLimits)
	}
	for _, bad := range []string{"metadata=10", "authorize", "authorize=0", "authorize=10001", "authorize=fast", "authorize=-5"} {
		if _, _, err := Load(nil, noAuthEnv("BYWARD_OAUTH_RATE_LIMITS="+bad), nil); err == nil || !strings.Contains(err.Error(), "BYWARD_OAUTH_RATE_LIMITS") {
			t.Errorf("BYWARD_OAUTH_RATE_LIMITS=%q: want an error naming the setting, got %v", bad, err)
		}
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
	cases := []struct {
		env     string
		want    time.Duration
		wantErr bool
	}{
		{"", 5 * time.Minute, false},
		{"BYWARD_UPSTREAM_HEADER_TIMEOUT=1s", time.Second, false},
		{"BYWARD_UPSTREAM_HEADER_TIMEOUT=1h", time.Hour, false},
		{"BYWARD_UPSTREAM_HEADER_TIMEOUT=999ms", 0, true},
		{"BYWARD_UPSTREAM_HEADER_TIMEOUT=61m", 0, true},
		{"BYWARD_UPSTREAM_HEADER_TIMEOUT=0s", 0, true},
		{"BYWARD_UPSTREAM_HEADER_TIMEOUT=5", 0, true},
	}
	for _, c := range cases {
		var env []string
		if c.env != "" {
			env = []string{c.env}
		}
		cfg, _, err := Load(nil, noAuthEnv(env...), nil)
		switch {
		case c.wantErr && (err == nil || !strings.Contains(err.Error(), "BYWARD_UPSTREAM_HEADER_TIMEOUT")):
			t.Errorf("%q: want an error naming the setting, got %v", c.env, err)
		case !c.wantErr && err != nil:
			t.Errorf("%q: %v", c.env, err)
		case !c.wantErr && cfg.UpstreamHeaderTimeout != c.want:
			t.Errorf("%q: timeout %s, want %s", c.env, cfg.UpstreamHeaderTimeout, c.want)
		}
	}
}

// Trusted proxies are CIDRs or addresses, masked; an IPv4-mapped one is the IPv4 prefix it maps,
// since peers are compared unmapped, and one shorter than /96 maps no IPv4 prefix (masked, it would
// trust IPv6 addresses), so it is refused. An entry inside fe80::/10 is refused, as it would trust no
// peer; a zone too: it was dropped, and it swallowed any prefix length after it. Link-local is said
// first, so removing the zone never leads to the second refusal.
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
	if cfg, _, err := Load(nil, noAuthEnv(), nil); err != nil || len(cfg.TrustedProxies) != 0 {
		t.Errorf("default trusted proxies = %v (err %v), want none", cfg.TrustedProxies, err)
	}
	for _, tc := range []struct{ name, value, want string }{
		{"a hostname", "proxy.internal", `BYWARD_TRUSTED_PROXIES: "proxy.internal" is not a CIDR or an IP address`},
		{"a mapped /8", "::ffff:10.0.0.0/8", `BYWARD_TRUSTED_PROXIES: "::ffff:10.0.0.0/8" is an IPv4-mapped prefix shorter than /96: it maps no IPv4 prefix and would trust IPv6 addresses; give the IPv4 prefix instead (::ffff:10.0.0.0/104 is 10.0.0.0/8)`},
		{"a mapped /95", "::ffff:10.0.0.0/95", `BYWARD_TRUSTED_PROXIES: "::ffff:10.0.0.0/95" is an IPv4-mapped prefix shorter than /96: it maps no IPv4 prefix and would trust IPv6 addresses; give the IPv4 prefix instead (::ffff:10.0.0.0/104 is 10.0.0.0/8)`},
		// Parsed as an address, everything after % is the zone, the prefix length included.
		{"a zoned prefix", "2001:db8::1%eth0/64", `BYWARD_TRUSTED_PROXIES: "2001:db8::1%eth0/64" has an IPv6 zone: give the proxy's routable address or CIDR, without a zone`},
		{"a zoned address", "2001:db8::1%eth0", `BYWARD_TRUSTED_PROXIES: "2001:db8::1%eth0" has an IPv6 zone: give the proxy's routable address or CIDR, without a zone`},
		{"a zoned mapped address", "::ffff:10.0.0.1%eth0", `BYWARD_TRUSTED_PROXIES: "::ffff:10.0.0.1%eth0" has an IPv6 zone: give the proxy's routable address or CIDR, without a zone`},
		{"a zoned link-local prefix", "fe80::1%eth0/64", `BYWARD_TRUSTED_PROXIES: "fe80::1%eth0/64" is link-local: a link-local proxy cannot be trusted, as its address names a host only together with an interface; give the proxy's routable address or CIDR`},
		{"a zoned link-local address", "fe80::1%eth0", `BYWARD_TRUSTED_PROXIES: "fe80::1%eth0" is link-local: a link-local proxy cannot be trusted, as its address names a host only together with an interface; give the proxy's routable address or CIDR`},
		{"a link-local address", "fe80::1", `BYWARD_TRUSTED_PROXIES: "fe80::1" is link-local: a link-local proxy cannot be trusted, as its address names a host only together with an interface; give the proxy's routable address or CIDR`},
		{"the link-local prefix", "fe80::/10", `BYWARD_TRUSTED_PROXIES: "fe80::/10" is link-local: a link-local proxy cannot be trusted, as its address names a host only together with an interface; give the proxy's routable address or CIDR`},
		{"the last link-local address", "febf:ffff:ffff:ffff:ffff:ffff:ffff:ffff", `BYWARD_TRUSTED_PROXIES: "febf:ffff:ffff:ffff:ffff:ffff:ffff:ffff" is link-local: a link-local proxy cannot be trusted, as its address names a host only together with an interface; give the proxy's routable address or CIDR`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, _, err := Load(nil, noAuthEnv("BYWARD_TRUSTED_PROXIES="+tc.value), nil); err == nil || err.Error() != tc.want {
				t.Errorf("err = %v\nwant %s", err, tc.want)
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
		if err != nil || c.StaticClientsFileNamed != tc.named {
			t.Fatalf("env %q: named = %v (%v), want %v", tc.env, c.StaticClientsFileNamed, err, tc.named)
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
		{"a relative counter beside a relative keys directory", []string{"BYWARD_KEYS_DIR=keys", "BYWARD_STORE_COUNTER_FILE=writes"}, `BYWARD_STORE_COUNTER_FILE: want an absolute path (no paths relative to the working directory, ADR-0007 §6), got a relative one`, ""},
		{"counter inside the state directory", []string{"BYWARD_STORE_COUNTER_FILE=/var/lib/byward/state/writes"}, "is inside BYWARD_STORE_DIR", ""},
		{"keys inside the state directory", []string{"BYWARD_KEYS_DIR=/var/lib/byward/state/keys"}, "keep the keys directory outside the state directory", ""},
		{"grace not a duration", []string{"BYWARD_REFRESH_GRACE=soon"}, "BYWARD_REFRESH_GRACE: want a duration", ""},
		{"grace negative", []string{"BYWARD_REFRESH_GRACE=-1s"}, "want 0s to 60s", ""},
		{"grace over a minute", []string{"BYWARD_REFRESH_GRACE=61s"}, "want 0s to 60s", ""},
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
	if c, err = load(t, nil, "BYWARD_CIMD=false"); err != nil || c.CIMD {
		t.Fatalf("CIMD off: %v, %v", c.CIMD, err)
	}
	// Host lists with CIMD off would silently do nothing.
	if _, err := load(t, nil, "BYWARD_CIMD=false", "BYWARD_CIMD_TRUSTED_HOSTS=claude.ai"); !isConfigError(err) || !strings.Contains(err.Error(), "no effect while BYWARD_CIMD is false") {
		t.Fatalf("err = %v", err)
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
	// a.0xg, a.0xag).
	for _, host := range []string{"app.de", "app.cafe", "123.example", "0x7f.example", "app.0x7g", "a.0xg", "a.0xag", "app.1example"} {
		if _, err := load(t, nil, "BYWARD_CLIENT_DENYLIST="+host); err != nil {
			t.Errorf("%q refused: %v", host, err)
		}
	}
	if c, err = load(t, nil, "BYWARD_DCR=false"); err != nil {
		t.Fatal(err)
	}
	if c.DCR {
		t.Fatal("DCR on with BYWARD_DCR=false")
	}
}

// #319: one reduction of a BYWARD_ALLOWED_HOSTS entry or a Host header to a host name, for the
// internal listener's Host check, the no-auth loopback check and the TLS certificate names.
func TestAnAllowedHostEntryOrHostHeaderReducesToItsLowerCaseHostName(t *testing.T) {
	for entry, want := range map[string]string{
		"mcp.example.com":      "mcp.example.com",
		"mcp.example.com:8443": "mcp.example.com",
		"MCP.Example.COM:8443": "mcp.example.com",
		"[::1]":                "::1",
		"[::1]:8443":           "::1",
		"::1":                  "::1",
		"[FE80::1]:8443":       "fe80::1",
		"127.0.0.1:8080":       "127.0.0.1",
		"localhost":            "localhost",
	} {
		if got := Hostname(entry); got != want {
			t.Errorf("Hostname(%q) = %q, want %q", entry, got, want)
		}
	}
}

// #334: a name with any ASCII character outside RFC 3986's unreserved set (a control character, a sub-delim,
// a %-escape, "@", "?", "#", "\\" ...) is refused as a host name, with or without a port. ":", the
// brackets, "/" and the space belong to the form check and are covered there; "," separates the
// list's entries.
func TestAnAllowedHostNameRefusesEveryCharacterAHostNameCannotHave(t *testing.T) {
	const unreserved = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~"
	for c := byte(1); c < 0x80; c++ {
		if strings.IndexByte(unreserved+":[]/, ", c) >= 0 {
			continue
		}
		for _, entry := range []string{"a" + string(c) + "b", "a" + string(c) + "b:8443"} {
			_, err := load(t, nil, "BYWARD_ALLOWED_HOSTS="+entry)
			if err == nil || !strings.Contains(err.Error(), "is not a host[:port]: a host name") {
				t.Errorf("BYWARD_ALLOWED_HOSTS=%s: %v, want it refused as a host name", entry, err)
			}
		}
	}
}

// #344: every host setting that follows the name rule still loads underscores, xn-- names and
// mixed case, each on its own, stored in lower case where the setting stores it so.
func TestHostSettingsLoadUnderscoresIDNANamesAndMixedCase(t *testing.T) {
	for _, host := range []string{"my_svc.example", "xn--bcher-kva.example", "Mixed-Case.Example"} {
		lower := strings.ToLower(host)
		for setting, stored := range map[string]func(*Config) []string{
			"BYWARD_PUBLIC_URL=https://" + host + "/mcp": func(c *Config) []string { return []string{c.PublicURL.Hostname()} },
			"BYWARD_CIMD_TRUSTED_HOSTS=" + host:          func(c *Config) []string { return c.CIMDTrustedHosts },
			"BYWARD_CIMD_ALLOWED_HOSTS=" + host:          func(c *Config) []string { return c.CIMDAllowedHosts },
			"BYWARD_ALLOWED_HOSTS=" + host:               func(c *Config) []string { return c.AllowedHosts },
			"BYWARD_CLIENT_DENYLIST=" + host:             func(c *Config) []string { return c.ClientDenylist },
		} {
			t.Run(setting, func(t *testing.T) {
				c, err := load(t, nil, setting)
				if err != nil {
					t.Fatal(err)
				}
				want := lower
				if strings.HasPrefix(setting, "BYWARD_PUBLIC_URL=") || strings.HasPrefix(setting, "BYWARD_CLIENT_DENYLIST=") {
					want = host // url.Parse keeps the host as given; the denylist keeps its entries as given
				}
				if got := stored(c); !slices.Equal(got, []string{want}) {
					t.Errorf("stored %v, want [%s]", got, want)
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
