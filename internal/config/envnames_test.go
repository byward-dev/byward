package config

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

var (
	envName = regexp.MustCompile(`\bBYWARD_[A-Z][A-Z0-9_]*\*?`)
	// settingLiteral is a setting named in code as Setting{Name: "…"}, optionally with its _FILE
	// variable appended to Env() by hand.
	settingLiteral = regexp.MustCompile(`Setting\{Name: *"([^"]*)"\}(\.Env\(\) *\+ *"_FILE")?`)
)

// Setting names written out by hand in messages (errors, warnings, logs) and in the operator docs
// must name real settings: after a rename or a removed setting, a stale name would point operators
// at nothing. In code that includes Setting{Name: "…"}, whose Env() checks nothing, and a _FILE
// variable, which only a secret setting has. ADRs are left out: they name planned settings.
func TestEveryBYWARDNameInTheCodeAndDocsIsASetting(t *testing.T) {
	known := map[string]bool{}
	byName := map[string]Setting{}
	for _, s := range registry {
		known[s.Env()] = true
		byName[s.Name] = s
		if s.Secret {
			known[s.Env()+"_FILE"] = true
		}
	}
	// Not settings, but fixed names: identity and the token socket the proxy sets for stdio
	// upstreams (ADR-0016, ADR-0017), the
	// switch that regenerates the settings reference, the switch of the PostgreSQL test lane
	// (internal/testutil/pgtest), the image build argument, the ENTRA_*, OIDC_*
	// and APP_* families, the real-Entra lane's repository variables (docs/maintainers/real-entra-lane.md)
	// and the fixture privacy test's CI secret (ADR-0024 §13).
	extra := regexp.MustCompile(`^BYWARD_(ENTRA_\*|OIDC_\*|APP_\*|SUBJECT|ISSUER|EMAIL|PRINCIPAL_TYPE|DOWNSTREAM_TOKEN_SOCKET|UPDATE_REFERENCE|POSTGRES|IMAGE|CI_ENTRA_TENANT|CI_ENTRA_CLIENT_ID|FORBIDDEN_IDENTIFIERS)$`)
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
		for _, m := range settingLiteral.FindAllStringSubmatch(string(src), -1) {
			s, ok := byName[m[1]]
			switch {
			case !ok:
				t.Errorf("%s names Setting %q, which is not a setting", path, m[1])
			case m[2] != "" && !s.Secret:
				t.Errorf("%s names %s_FILE, but %s is not a secret setting", path, s.Env(), m[1])
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
