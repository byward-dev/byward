package config

import (
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
	// One per family: the reserved names, then each reserved prefix.
	reserved := []string{"Mcp-Session-Id", "X-Forwarded-For", "Proxy-Authorization", "Sec-Fetch-Mode", "Access-Control-Allow-Origin"}
	for _, s := range settings {
		for _, h := range reserved {
			for _, name := range []string{h, strings.ReplaceAll(h, "-", "_")} {
				t.Run(s.env+"="+name, func(t *testing.T) {
					_, err := loadCred(t, nil, "k-123", append(s.extra, s.env+"="+name)...)
					if err == nil || !strings.Contains(err.Error(), s.env+": ") || !strings.Contains(err.Error(), "relies on") {
						t.Fatalf("err = %v; want %s=%s refused as a header the proxy, the transport or MCP relies on", err, s.env, name)
					}
				})
			}
		}
	}
}
