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

// Setting names written out by hand in messages (errors, warnings, logs) and in the operator docs
// must name real settings: after a rename or a removed setting, a stale name would point operators
// at nothing. ADRs are left out: they name planned settings.
func TestEveryBYWARDNameInTheCodeAndDocsIsASetting(t *testing.T) {
	known := map[string]bool{}
	for _, s := range registry {
		known[s.Env()] = true
		if s.Secret {
			known[s.Env()+"_FILE"] = true
		}
	}
	// Not settings, but fixed names: identity the proxy sets for stdio upstreams (ADR-0016), the
	// switch that regenerates the settings reference, the image build argument, the ENTRA_* and
	// OIDC_* families, and the real-Entra lane's repository variables (docs/how-to/real-entra-lane.md).
	extra := regexp.MustCompile(`^BYWARD_(ENTRA_\*|OIDC_\*|SUBJECT|ISSUER|EMAIL|UPDATE_REFERENCE|IMAGE|CI_ENTRA_TENANT|CI_ENTRA_CLIENT_ID)$`)
	check := func(path string) {
		src, err := os.ReadFile(path) //nolint:gosec // G304: reads this repository's own files
		if err != nil {
			t.Fatal(err)
		}
		for _, name := range envName.FindAllString(string(src), -1) {
			if !known[name] && !extra.MatchString(name) {
				t.Errorf("%s names %s, which is not a setting", path, name)
			}
		}
	}
	walk := func(root, suffix string) {
		err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
			if err == nil && !d.IsDir() && strings.HasSuffix(path, suffix) && !strings.HasSuffix(path, "_test.go") {
				check(path)
			}
			return err
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	walk("../../cmd", ".go")
	walk("../../internal", ".go")
	walk("../../docs/how-to", ".md")
	walk("../../docs/reference", ".md")
	for _, f := range []string{"README.md", "SECURITY.md", "CONTRIBUTING.md", "AGENTS.md"} {
		check("../../" + f)
	}
}
