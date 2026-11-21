package config

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"slices"
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
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	var found []string
	fset := token.NewFileSet()
	err = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if path != root && (strings.HasPrefix(d.Name(), ".") || slices.Contains(skippedDirs, d.Name())) {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		f, err := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
		if err != nil {
			return err
		}
		ast.Inspect(f, func(n ast.Node) bool {
			if lit, ok := n.(*ast.BasicLit); ok && lit.Kind == token.STRING && (lit.Value == `"_FILE"` || strings.Contains(lit.Value, "%s_FILE")) {
				rel, _ := filepath.Rel(root, fset.Position(lit.Pos()).Filename)
				found = append(found, filepath.ToSlash(rel)+": "+lit.Value)
			}
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{`internal/config/registry.go: "_FILE"`}; !slices.Equal(found, want) {
		t.Fatalf("string literals building a file variable = %q, want only FileEnv's %q", found, want)
	}
}
