package config

import (
	"strings"
	"testing"
)

// The upstream-env help names exactly the locale variables a stdio upstream inherits:
// upstream/stdio passes LANG, LC_ALL, LC_CTYPE and LC_MESSAGES by name, never every LC_* (L162).
func TestTheUpstreamEnvHelpNamesTheInheritedLocaleVariables(t *testing.T) {
	for _, s := range registry {
		if s.Name != "upstream-env" {
			continue
		}
		if !strings.Contains(s.Help, "LANG, LC_ALL, LC_CTYPE and LC_MESSAGES") || strings.Contains(s.Help, "LC_*") {
			t.Fatalf("upstream-env help %q; want LANG, LC_ALL, LC_CTYPE and LC_MESSAGES named, and no LC_*", s.Help)
		}
		return
	}
	t.Fatal("no upstream-env setting")
}
