package config

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"maps"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
)

// pathFields are the Config fields that hold a path the proxy reads or writes, and their settings
// (security invariant 2, #587).
var pathFields = map[string]string{
	"TLSCertFile":             "tls-cert-file",
	"TLSKeyFile":              "tls-key-file",
	"EntraFederatedTokenFile": "entra-federated-token-file",
	"DataDir":                 "data-dir",
	"KeysDir":                 "keys-dir",
	"AssertionKeysDir":        "assertion-keys-dir",
	"StaticClientsFile":       "static-clients-file",
	"StoreDir":                "store-dir",
	"StoreCounterFile":        "store-counter-file",
}

// fileOpeners are the calls that read, write or stat what a path names, as package.Name: the os
// package's, and the loaders the wiring hands a configured path to.
var fileOpeners = []string{
	"os.Open", "os.OpenFile", "os.ReadFile", "os.WriteFile", "os.Stat", "os.Lstat", "os.ReadDir", "os.MkdirAll",
	"os.Mkdir", "os.Chmod", "os.Remove", "os.CreateTemp",
	"token.LoadKeyRing", "assertion.LoadKeys", "registration.LoadStatic", "idp.AssertionFile", "secretfile.Check",
	"sqlite.CheckPaths", "sqlite.Open", "servingcert.Load", "servingcert.Read",
}

// fileOptionTypes are the composite literals, as package.Type, the wiring hands a path to a loader in.
var fileOptionTypes = []string{"servingcert.Files", "sqlite.Options"}

// The marked settings are exactly the settings of pathFields: a path setting is marked, and a
// marked setting is one whose field holds a path.
func TestThePathSettingsAreExactlyThese(t *testing.T) {
	var marked []string
	for _, s := range registry {
		if s.Path {
			marked = append(marked, s.Name)
		}
		if s.Path && s.Secret() {
			t.Errorf("%s: a secret is a path through its file, not through Path", s.Name)
		}
	}
	if want := slices.Sorted(maps.Values(pathFields)); !slices.Equal(slices.Sorted(slices.Values(marked)), want) {
		t.Fatalf("settings marked Path = %v, want %v", slices.Sorted(slices.Values(marked)), want)
	}
	for field := range pathFields {
		if f, ok := reflect.TypeFor[Config]().FieldByName(field); !ok || f.Type.Kind() != reflect.String {
			t.Errorf("Config.%s: no such string field", field)
		}
	}
}

// PathSettings lists each Path setting's variable and each secret's _FILE variable, and nothing
// else: the leak test needs a scenario for each.
func TestPathSettingsAreThePathAndSecretFileVariables(t *testing.T) {
	var want []string
	for _, s := range registry {
		if s.Path {
			want = append(want, s.Env())
		}
		if s.Secret() {
			want = append(want, s.Env()+"_FILE")
		}
	}
	if got := PathSettings(); !slices.Equal(got, want) || len(got) == 0 {
		t.Fatalf("PathSettings() = %v, want %v", got, want)
	}
}

// Every Config field the proxy hands to a file opener, outside this package, holds a path setting:
// a new path setting, or a new loader for an existing one, is listed in pathFields and marked Path.
// The scan is syntactic: it sees a field selected inside a call to one of fileOpeners, or in one of
// fileOptionTypes' literals, by package name. It cannot see a field copied into a variable, or
// passed to a function not listed, before it is opened, nor a package imported under another name;
// the leak test's scenarios cover what the proxy prints then.
func TestEveryConfigFieldTheProxyOpensIsAPathSetting(t *testing.T) {
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	stringFields := map[string]bool{}
	ct := reflect.TypeFor[Config]()
	for i := range ct.NumField() {
		if f := ct.Field(i); f.Type.Kind() == reflect.String {
			stringFields[f.Name] = true
		}
	}
	opened := map[string]string{} // field → where
	fset := token.NewFileSet()
	err = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, path)
		rel = filepath.ToSlash(rel)
		if d.IsDir() {
			if path != root && (strings.HasPrefix(d.Name(), ".") || slices.Contains(skippedDirs, d.Name())) {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") || strings.HasPrefix(rel, "internal/config/") {
			return nil
		}
		f, err := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
		if err != nil {
			return err
		}
		ast.Inspect(f, func(n ast.Node) bool {
			var args []ast.Expr
			switch n := n.(type) {
			case *ast.CallExpr:
				if slices.Contains(fileOpeners, calledName(n.Fun)) {
					args = n.Args
				}
			case *ast.CompositeLit:
				if slices.Contains(fileOptionTypes, calledName(n.Type)) {
					args = n.Elts
				}
			}
			for _, a := range args {
				ast.Inspect(a, func(m ast.Node) bool {
					if sel, ok := m.(*ast.SelectorExpr); ok && stringFields[sel.Sel.Name] {
						opened[sel.Sel.Name] = fset.Position(sel.Pos()).String()
					}
					return true
				})
			}
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(opened) == 0 {
		t.Fatal("the scan found no Config field handed to a file opener, so it checked nothing")
	}
	for field, where := range opened {
		if _, ok := pathFields[field]; !ok {
			t.Errorf("%s: Config.%s is handed to a file opener but is no path setting; mark its setting Path and list it in pathFields (#587)", where, field)
		}
	}
}

// calledName is a call's function or a literal's type as package.Name, such as os.Open or
// servingcert.Files; "" for anything else (a method, a local function).
func calledName(e ast.Expr) string {
	if sel, ok := e.(*ast.SelectorExpr); ok {
		if pkg, ok := sel.X.(*ast.Ident); ok {
			return pkg.Name + "." + sel.Sel.Name
		}
	}
	return ""
}
