package config

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

var envName = regexp.MustCompile(`\bBYWARD_[A-Z][A-Z0-9_]*\*?`)

// Setting names written out by hand in messages (errors, warnings, logs) must name real settings:
// after a rename or a removed setting, a stale name would point operators at nothing.
func TestEveryBYWARDNameInTheCodeIsASetting(t *testing.T) {
	known := map[string]bool{}
	for _, s := range registry {
		known[s.Env()] = true
		known[s.Env()+"_FILE"] = true // secrets are read from a file
	}
	// Not settings, but fixed names: identity the proxy sets for stdio upstreams (ADR-0016), the
	// switches that regenerate generated docs and goldens, and prefixes.
	extra := regexp.MustCompile(`^BYWARD_(ENTRA_\*|SUBJECT|ISSUER|EMAIL|NAME|TENANT|OBJECT_ID|USER_KEY|UPDATE_REFERENCE|UPDATE_GOLDEN|[A-Z_]*_)$`)
	for _, root := range []string{"../../cmd", "../../internal"} {
		err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return err
			}
			src, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			for _, name := range envName.FindAllString(string(src), -1) {
				if !known[name] && !extra.MatchString(name) {
					t.Errorf("%s names %s, which is not a setting", path, name)
				}
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
}

// The stdio upstream reserves the settings prefix for identity it sets itself; it keeps its own copy.
func TestTheStdioReservedPrefixIsTheSettingsPrefix(t *testing.T) {
	src, err := os.ReadFile("../upstream/stdio/command.go")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(src), `reservedEnv = "`+envPrefix+`"`) {
		t.Fatalf("internal/upstream/stdio reservedEnv is not %q", envPrefix)
	}
}
