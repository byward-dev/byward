package config

import (
	"strings"
	"testing"
)

// The upstream-env help, as byward --help shows it, names the locale variables a stdio upstream
// inherits, as upstream/stdio passes them: LANG, LC_ALL, LC_CTYPE and LC_MESSAGES by name, not every
// LC_* (L162). docs/reference/settings.md follows the same text (TestReferenceIsCurrent).
func TestTheUpstreamEnvHelpNamesTheInheritedLocaleVariables(t *testing.T) {
	usage := Usage()
	_, entry, ok := strings.Cut(usage, "--upstream-env-file")
	if !ok {
		t.Fatalf("no --upstream-env-file in the help:\n%s", usage)
	}
	entry, _, _ = strings.Cut(entry, "\n  --")
	if !strings.Contains(entry, "LANG, LC_ALL, LC_CTYPE and LC_MESSAGES") || strings.Contains(entry, "LC_*") {
		t.Fatalf("upstream-env help %q; want LANG, LC_ALL, LC_CTYPE and LC_MESSAGES named, and no LC_*", entry)
	}
}
