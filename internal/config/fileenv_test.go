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
		if got := lookup(name).FileEnv(); got != want {
			t.Errorf("FileEnv of %q = %q, want %q", name, got, want)
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
			lookup(tc.name).FileEnv()
		})
	}
}

// A secret's file variable and file flag are asked of the registry, never built by hand (#506): the only
// string literals in the production code that build one (the "_FILE" or "-file" suffix, alone, leading,
// or after a format verb) are FileEnv's and FileFlag's, and flagHint's two, which hint a path
// setting's own -file name (--tls-cert for --tls-cert-file); a secret's hint comes from FileFlag.
func TestOnlyFileEnvAndFileFlagBuildASecretsFileName(t *testing.T) {
	var found []string
	eachProductionGoFile(t, func(rel string, _ *token.FileSet, f *ast.File) {
		for _, d := range f.Decls {
			where := rel
			if fn, ok := d.(*ast.FuncDecl); ok {
				where += " " + fn.Name.Name
			}
			ast.Inspect(d, func(n ast.Node) bool {
				if lit, ok := n.(*ast.BasicLit); ok && lit.Kind == token.STRING && buildsAFileName(lit.Value) {
					found = append(found, where+": "+lit.Value)
				}
				return true
			})
		}
	})
	want := []string{
		`internal/config/registry.go FileEnv: "_FILE"`,
		`internal/config/registry.go FileFlag: "-file"`,
		`internal/config/registry.go flagHint: "-file"`,
		`internal/config/registry.go flagHint: "-file?)"`,
	}
	if !slices.Equal(found, want) {
		t.Fatalf("string literals building a file variable or flag = %q, want only %q", found, want)
	}
}

// fileSuffixAfterVerb is a format verb, any flags and index included ("%s", "%[1]q"), followed by
// _FILE or -file.
var fileSuffixAfterVerb = regexp.MustCompile(`%[^%a-zA-Z]*[a-zA-Z](_FILE|-file)`)

// buildsAFileName reports whether the string literal lit, as written (quoted or raw), is the _FILE or
// -file suffix, starts with one, or formats one after a verb.
func buildsAFileName(lit string) bool {
	v, err := strconv.Unquote(lit)
	if err != nil {
		return false
	}
	return strings.HasPrefix(v, "_FILE") || strings.HasPrefix(v, "-file") || fileSuffixAfterVerb.MatchString(v)
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

// A secret's file flag is its name with -file; a setting that is not a secret has none, and asking
// panics (#506).
func TestASecretsFileFlagIsItsNameWithFileAndPanicsForANonSecret(t *testing.T) {
	if got := lookup("oidc-client-key").FileFlag(); got != "oidc-client-key-file" {
		t.Errorf("FileFlag = %q, want oidc-client-key-file", got)
	}
	defer func() {
		if r, want := recover(), "config: listen is not a secret, so it has no -file flag"; r != want {
			t.Fatalf("recovered %v, want %q", r, want)
		}
	}()
	lookup("listen").FileFlag()
}
