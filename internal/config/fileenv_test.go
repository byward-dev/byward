package config

import (
	"go/ast"
	"go/token"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// A secret's file variable is its variable with _FILE, from the registry (#506).
func TestASecretsFileVariableIsItsVariableWithFILE(t *testing.T) {
	for name, want := range map[string]string{
		"oidc-client-key":     "BYWARD_OIDC_CLIENT_KEY_FILE",
		"entra-client-secret": "BYWARD_ENTRA_CLIENT_SECRET_FILE",
		"upstream-credential": "BYWARD_UPSTREAM_CREDENTIAL_FILE",
	} {
		if got := SecretFileEnv(name); got != want {
			t.Errorf("SecretFileEnv(%q) = %q, want %q", name, got, want)
		}
	}
}

// A name built for a setting that is not a secret, or that the registry does not hold, panics: the
// message would otherwise name a variable byward does not read (#506).
func TestAFileVariableOfANonSecretOrUnknownSettingPanics(t *testing.T) {
	for _, tc := range []struct{ name, want string }{
		{"listen", "config: listen is not a secret, so it has no _FILE variable"},
		{"entra-client-secrets", "config: no setting entra-client-secrets"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			defer func() {
				if r := recover(); r != tc.want {
					t.Fatalf("recovered %v, want %q", r, tc.want)
				}
			}()
			SecretFileEnv(tc.name)
		})
	}
}

// The only "_FILE" suffix in the production code, alone or in a format ("%s_FILE"), is FileEnv's: every
// other file variable is asked of the registry, never built by hand (#506).
func TestOnlyFileEnvBuildsAFileVariable(t *testing.T) {
	var found []string
	eachProductionGoFile(t, func(rel string, _ *token.FileSet, f *ast.File) {
		ast.Inspect(f, func(n ast.Node) bool {
			if lit, ok := n.(*ast.BasicLit); ok && lit.Kind == token.STRING && buildsAFileVariable(lit.Value) {
				found = append(found, rel+": "+lit.Value)
			}
			return true
		})
	})
	if want := []string{`internal/config/registry.go: "_FILE"`}; !slices.Equal(found, want) {
		t.Fatalf("string literals building a file variable = %q, want only FileEnv's %q", found, want)
	}
}

// fileFormat is a format verb, any flags and index included ("%s", "%[1]q"), followed by _FILE.
var fileFormat = regexp.MustCompile(`%[^%a-zA-Z]*[a-zA-Z]_FILE`)

// buildsAFileVariable reports whether the string literal lit, as written (quoted or raw), is the _FILE
// suffix, starts with it, or formats it after a verb.
func buildsAFileVariable(lit string) bool {
	v, err := strconv.Unquote(lit)
	if err != nil {
		return false
	}
	return strings.HasPrefix(v, "_FILE") || fileFormat.MatchString(v)
}

// --help names each secret by its file flag and file variable, never by its own variable, which
// byward refuses outside --dev (#506).
func TestHelpNamesASecretByItsFile(t *testing.T) {
	u := Usage()
	for _, want := range []string{"\n  --upstream-credential-file / BYWARD_UPSTREAM_CREDENTIAL_FILE\n", "\n  --oidc-client-key-file / BYWARD_OIDC_CLIENT_KEY_FILE\n"} {
		if !strings.Contains(u, want) {
			t.Errorf("--help lacks the line %q", strings.TrimSpace(want))
		}
	}
	if strings.Contains(u, " / BYWARD_UPSTREAM_CREDENTIAL\n") {
		t.Error("--help names the upstream credential by its own variable, not its file's")
	}
}

// Secrets given inline are refused together, and the hint names the first one's file variable, in
// registry order (#506).
func TestInlineSecretsAreRefusedWithTheFirstOnesFileVariable(t *testing.T) {
	v, err := resolve(registry, nil, []string{"BYWARD_ENTRA_CLIENT_SECRET=a", "BYWARD_UPSTREAM_CREDENTIAL=b"}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	const want = "BYWARD_UPSTREAM_CREDENTIAL, BYWARD_ENTRA_CLIENT_SECRET: secrets must come from a file (BYWARD_UPSTREAM_CREDENTIAL_FILE)"
	if _, err := checkInlineSecrets(v, false); !isConfigError(err) || err.Error() != want {
		t.Fatalf("got %v, want the configuration error %q", err, want)
	}
}
