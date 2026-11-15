package config

import (
	"net/textproto"
	"strings"
	"testing"
)

// The upstream may read _ as - (invariant 16), so every setting naming a header the proxy sets
// refuses a reserved header in either spelling, one family of the reserved checks at a time.
func TestAReservedHeaderIsRefusedInEitherSpellingByEverySettingThatSetsOne(t *testing.T) {
	settings := []struct {
		env   string
		extra []string
	}{
		{"BYWARD_ASSERTION_HEADER", nil},
		{"BYWARD_OBO_HEADER", nil},
		{"BYWARD_UPSTREAM_CREDENTIAL_HEADER", []string{"BYWARD_UPSTREAM_CREDENTIAL_FILE=" + credFile}},
	}
	// One per family: the reserved names, MCP's own request headers (all of them: each would replace
	// the client's at the upstream), then each reserved prefix, Mcp-Param-* (MCP 2026-07-28) included.
	reserved := []string{"Host", "Mcp-Session-Id", "Mcp-Protocol-Version", "Mcp-Method", "Mcp-Name", "Last-Event-ID",
		"X-Forwarded-For", "Proxy-Authorization", "Sec-Fetch-Mode", "Access-Control-Allow-Origin", "Mcp-Param-Region"}
	for _, s := range settings {
		for _, h := range reserved {
			for _, name := range []string{h, strings.ReplaceAll(h, "-", "_")} {
				t.Run(s.env+"="+name, func(t *testing.T) {
					_, err := loadCred(t, nil, "k-123", append(s.extra, s.env+"="+name)...)
					// The operator's own spelling, as config names it back.
					want := s.env + ": " + textproto.CanonicalMIMEHeaderKey(name) + " is a header the proxy, the transport or MCP relies on"
					if err == nil || !strings.Contains(err.Error(), want) {
						t.Fatalf("err = %v, want %q", err, want)
					}
				})
			}
		}
	}
}

// Only the reserved families are refused: a header of the operator's own that merely resembles one
// (no trailing dash, or the family inside another name) loads, canonical, for every setting.
func TestAHeaderThatOnlyResemblesAReservedOneIsAccepted(t *testing.T) {
	settings := []struct {
		env   string
		extra []string
		got   func(*Config) string
	}{
		{"BYWARD_ASSERTION_HEADER", nil, func(c *Config) string { return c.AssertionHeader }},
		{"BYWARD_OBO_HEADER", nil, func(c *Config) string { return c.OBOHeader }},
		{"BYWARD_UPSTREAM_CREDENTIAL_HEADER", []string{"BYWARD_UPSTREAM_CREDENTIAL_FILE=" + credFile}, func(c *Config) string { return c.UpstreamCredentialHeader }},
	}
	for _, s := range settings {
		for _, name := range []string{"mcp-params", "x-mcp-param-region", "x-tenant-param-id", "x-mcp-method"} {
			t.Run(s.env+"="+name, func(t *testing.T) {
				c, err := loadCred(t, nil, "k-123", append(s.extra, s.env+"="+name)...)
				if want := textproto.CanonicalMIMEHeaderKey(name); err != nil || s.got(c) != want {
					t.Fatalf("err = %v, want %s loaded as %s", err, name, want)
				}
			})
		}
	}
}

// A header name is an RFC 9110 token: a separator or a character outside ASCII is refused by every
// setting that names a header, not only a space or an empty value.
func TestAHeaderNameThatIsNotATokenIsRefusedByEverySettingThatSetsOne(t *testing.T) {
	for _, s := range []struct {
		env   string
		extra []string
	}{
		{"BYWARD_ASSERTION_HEADER", nil},
		{"BYWARD_OBO_HEADER", nil},
		{"BYWARD_UPSTREAM_CREDENTIAL_HEADER", []string{"BYWARD_UPSTREAM_CREDENTIAL_FILE=" + credFile}},
	} {
		for _, name := range []string{"X-Identity:", "X(Identity)", "X/Identity", "X-Idé"} {
			t.Run(s.env+"="+name, func(t *testing.T) {
				_, err := loadCred(t, nil, "k-123", append(s.extra, s.env+"="+name)...)
				if want := s.env + ": want a header name"; err == nil || !strings.Contains(err.Error(), want) {
					t.Fatalf("err = %v, want %q", err, want)
				}
			})
		}
	}
}
