package config

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
)

var (
	envName = regexp.MustCompile(`\bBYWARD_[A-Z][A-Z0-9_]*\*?`)
	// settingLiteral is a setting named in code as Setting{Name: "…"}, with any string-literal suffix
	// appended to Env() by hand; settingLiteralProblem says which are wrong.
	settingLiteral = regexp.MustCompile(`Setting\{Name: *"([^"]*)"\}(?:\.Env\(\)\s*\+\s*(?:"([^"]*)"|\x60([^\x60]*)\x60))?`) // \x60 is a backtick
)

// Setting names written out by hand in code (messages and environment lookups) and in the operator
// docs must name real settings: after a rename or a removed setting, a stale name would point
// operators at nothing or read a variable nobody sets. In code that includes Setting{Name: "…"},
// whose Env() checks nothing, and a _FILE variable, which only a secret setting has. ADRs are left
// out: they name planned settings.
func TestEveryBYWARDNameInTheCodeAndDocsIsASetting(t *testing.T) {
	known := map[string]bool{}
	byName := map[string]Setting{}
	literals := 0 // Setting literals seen in the code
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
		found, problems := settingLiteralProblems(byName, string(src))
		literals += found
		for _, problem := range problems {
			t.Errorf("%s %s", path, problem)
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
	if literals == 0 { // a pattern that matches nothing would turn the check off unnoticed
		t.Fatal("no Setting{Name: \"…\"} found in the code")
	}
}

// settingLiteralProblems reads every Setting literal in src: how many there are, and what is wrong
// with them.
func settingLiteralProblems(byName map[string]Setting, src string) (found int, problems []string) {
	for _, m := range settingLiteral.FindAllStringSubmatch(src, -1) {
		found++
		if problem := settingLiteralProblem(byName, m[1], m[2]+m[3]); problem != "" {
			problems = append(problems, problem)
		}
	}
	return found, problems
}

// settingLiteralProblem is what is wrong with Setting{Name: name}.Env() + suffix (suffix "" for
// none), or "".
func settingLiteralProblem(byName map[string]Setting, name, suffix string) string {
	s, ok := byName[name]
	switch {
	case !ok:
		return fmt.Sprintf("names Setting %q, which is not a setting", name)
	case suffix != "" && suffix != "_FILE":
		return fmt.Sprintf("names %s%s, but a setting's only other variable is _FILE", s.Env(), suffix)
	case suffix != "" && !s.Secret:
		return fmt.Sprintf("names %s_FILE, but %s is not a secret setting", s.Env(), name)
	}
	return ""
}

// The pattern reads a Setting literal, and any suffix after Env(), in every form gofmt writes and
// as a raw string, and nothing that is not one.
func TestTheSettingLiteralPatternReadsEveryGofmtForm(t *testing.T) {
	for src, want := range map[string][]string{
		`Setting{Name: "x"}`:                        {"x", ""},
		`config.Setting{Name: "x"}.Env()`:           {"x", ""},
		`Setting{Name: "x"}.Env()+"_FILE"`:          {"x", "_FILE"},
		`Setting{Name: "x"}.Env() + "_FILE"`:        {"x", "_FILE"},
		"Setting{Name: \"x\"}.Env() +\n\t\"_FILE\"": {"x", "_FILE"},
		`Setting{Name: "x"}.Env() + "_FILES"`:       {"x", "_FILES"},
		"Setting{Name: \"x\"}.Env() + `_FILE`":      {"x", "_FILE"},   // a raw string
		"Setting{Name: \"x\"}.Env() + \"_FILE`x\"":  {"x", "_FILE`x"}, // quotes pair: a backtick inside is part of the string
		`Settings{Name: "x"}`:                       nil,
		`Setting{Name: x}`:                          nil,
	} {
		m := settingLiteral.FindStringSubmatch(src)
		if (want == nil) != (m == nil) || (m != nil && (m[1] != want[0] || m[2]+m[3] != want[1])) {
			var got []string
			if m != nil {
				got = []string{m[1], m[2] + m[3]}
			}
			t.Errorf("%q: read %q, want %q", src, got, want)
		}
	}
}

// The guard refuses an unknown name, a suffix other than _FILE, and _FILE on a setting that is not
// secret.
func TestTheSettingLiteralGuardRefusesWhatNoSettingReads(t *testing.T) {
	byName := map[string]Setting{"plain": {Name: "plain"}, "secret": {Name: "secret", Secret: true}}
	for _, tc := range []struct{ name, suffix, want string }{
		{"plain", "", ""},
		{"secret", "_FILE", ""},
		{"missing", "", `names Setting "missing", which is not a setting`},
		{"plain", "_FILE", "names BYWARD_PLAIN_FILE, but plain is not a secret setting"},
		{"secret", "_FILES", "names BYWARD_SECRET_FILES, but a setting's only other variable is _FILE"},
	} {
		if got := settingLiteralProblem(byName, tc.name, tc.suffix); got != tc.want {
			t.Errorf("%s%s: %q, want %q", tc.name, tc.suffix, got, tc.want)
		}
	}
	// The guard reads source end to end: each literal, with its suffix, reaches the decision.
	src := "a := Setting{Name: \"plain\"}.Env() + \"_FILE\"\nb := Setting{Name: \"secret\"}.Env() + \"_FILE\"\nc := Setting{Name: \"missing\"}"
	found, problems := settingLiteralProblems(byName, src)
	want := []string{"names BYWARD_PLAIN_FILE, but plain is not a secret setting", `names Setting "missing", which is not a setting`}
	if found != 3 || !slices.Equal(problems, want) {
		t.Errorf("read %d literals with problems %q, want 3 with %q", found, problems, want)
	}
}
