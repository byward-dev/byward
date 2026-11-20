package config

import (
	"net/textproto"
	"strings"
	"testing"
)

// headerSettings are the settings that name a header the proxy sets on upstream requests (they all
// go through upstreamHeader), with what each needs to load and the header it loads into.
var headerSettings = []struct {
	env     string
	extra   []string
	got     func(*Config) string
	example string // the operator's own header that its errors suggest
}{
	{"BYWARD_ASSERTION_HEADER", nil, func(c *Config) string { return c.AssertionHeader }, "X-Byward-Identity"},
	{"BYWARD_OBO_HEADER", nil, func(c *Config) string { return c.OBOHeader }, "X-Byward-Downstream-Token"},
	{"BYWARD_UPSTREAM_CREDENTIAL_HEADER", []string{"BYWARD_UPSTREAM_CREDENTIAL_FILE=" + credFile}, func(c *Config) string { return c.UpstreamCredentialHeader }, "X-Api-Key"},
}

// The upstream may read _ as - (invariant 16), so every setting naming a header the proxy sets
// refuses a reserved header in either spelling, one family of the reserved checks at a time.
func TestAReservedHeaderIsRefusedInEitherSpellingByEverySettingThatSetsOne(t *testing.T) {
	// One per family: the reserved names, MCP's own request headers (all of them: each would replace
	// the client's at the upstream), then each reserved prefix, Mcp-Param-* (MCP 2026-07-28) included.
	// A reserved name is shown as the upstream reads it; a family only by its prefix, since what follows
	// the prefix is the operator's text.
	reserved := []struct{ h, shown string }{{"Host", "Host"}, {"Mcp-Session-Id", "Mcp-Session-Id"},
		{"Mcp-Protocol-Version", "Mcp-Protocol-Version"}, {"Mcp-Method", "Mcp-Method"}, {"Mcp-Name", "Mcp-Name"},
		{"Last-Event-ID", "Last-Event-Id"}, {"X-Forwarded-For", "a header starting X-Forwarded-"},
		{"Proxy-Authorization", "a header starting Proxy-"}, {"Sec-Fetch-Mode", "a header starting Sec-"},
		{"Access-Control-Allow-Origin", "a header starting Access-Control-"}, {"Mcp-Param-Region", "a header starting Mcp-Param-"}}
	for _, s := range headerSettings {
		for _, r := range reserved {
			for _, name := range []string{r.h, strings.ReplaceAll(r.h, "-", "_")} {
				t.Run(s.env+"="+name, func(t *testing.T) {
					_, err := loadCred(t, nil, "k-123", append(s.extra, s.env+"="+name)...)
					want := s.env + ": want a header name such as Authorization or " + s.example + "; got " + r.shown +
						": the proxy, the transport or MCP relies on it; use Authorization or a header of your own"
					if err == nil || !strings.Contains(err.Error(), want) {
						t.Fatalf("err = %v, want %q", err, want)
					}
				})
			}
		}
	}
}

// Only the reserved families are refused: a header of the operator's own that merely resembles one
// (no trailing dash, the family inside another name, or only part of the family's name) loads,
// canonical, for every setting.
func TestAHeaderThatOnlyResemblesAReservedOneIsAccepted(t *testing.T) {
	for _, s := range headerSettings {
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
	for _, s := range headerSettings {
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

// Two header settings that name the same header are refused by their names alone: the header is
// never shown, since an accepted name can be any token.
func TestAHeaderClashNeverShowsTheHeader(t *testing.T) {
	const header = "X-" + canaryText
	for name, env := range map[string][]string{
		"the credential and the assertion":         {"BYWARD_UPSTREAM_CREDENTIAL_FILE=" + credFile, "BYWARD_UPSTREAM_CREDENTIAL_HEADER=" + header, "BYWARD_ASSERTION_HEADER=" + strings.ToLower(header)},
		"the On-Behalf-Of token and the assertion": {"BYWARD_OBO_SCOPES=https://graph.microsoft.com/User.Read", "BYWARD_OBO_HEADER=" + header, "BYWARD_ASSERTION_HEADER=" + strings.ToLower(header)},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := loadCred(t, nil, "k-123", env...)
			if !isConfigError(err) || !strings.Contains(err.Error(), "the same header") && !strings.Contains(err.Error(), "names the header that already carries") || holdsCanary(err.Error()) {
				t.Fatalf("err = %v, want the clash refused by the settings' names and the header never shown", err)
			}
		})
	}
}
