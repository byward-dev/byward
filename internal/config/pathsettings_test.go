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
// (security invariant 2, #587). The pairing documents which setting fills a field; the tests use the
// fields and the settings each as a set.
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

// notOpened are the pathFields the proxy never hands to a file opener itself: the data directory is
// only where the other paths default to.
var notOpened = []string{"DataDir"}

// fileOpeners are the calls that read, write or stat what a path names, as package.Name: the os
// package's, and the loaders the wiring hands a configured path to.
var fileOpeners = []string{
	"os.Open", "os.OpenFile", "os.ReadFile", "os.WriteFile", "os.Stat", "os.Lstat", "os.ReadDir", "os.MkdirAll",
	"os.Mkdir", "os.Chmod", "os.Remove", "os.CreateTemp",
	"token.LoadKeyRing", "assertion.LoadKeys", "registration.LoadStatic", "idp.AssertionFile",
	"sqlite.CheckPaths", "sqlite.Open", "servingcert.Load", "servingcert.Read",
}

// fileOptionTypes are the composite literals, as package.Type, the wiring hands a path to a loader in.
var fileOptionTypes = []string{"servingcert.Files", "sqlite.Options"}

// The path shape is given to exactly the settings of pathFields, each of whose fields is a string
// field of Config. shapesOfSettings lists the path settings too; this ties them to their fields.
func TestThePathSettingsAreTheSettingsOfThePathFields(t *testing.T) {
	var pathShaped []string
	for _, s := range registry {
		if s.HoldsPath() {
			pathShaped = append(pathShaped, s.Name)
		}
	}
	if want := slices.Sorted(maps.Values(pathFields)); !slices.Equal(slices.Sorted(slices.Values(pathShaped)), want) {
		t.Fatalf("settings with the path shape = %v, want pathFields' settings %v (and shapesOfSettings' path row)", slices.Sorted(slices.Values(pathShaped)), want)
	}
	for _, field := range slices.Sorted(maps.Keys(pathFields)) {
		if f, ok := reflect.TypeFor[Config]().FieldByName(field); !ok || f.Type.Kind() != reflect.String {
			t.Errorf("Config.%s: no such string field", field)
		}
	}
}

// A setting named as a path (*-dir, *-file) has the path shape unless it is a secret, and a Config
// string field named as one (*Dir, *File) is in pathFields: a new path setting is marked even when
// the scan below cannot see the loader it is handed to.
func TestASettingOrFieldNamedAsAPathIsAPathSetting(t *testing.T) {
	for _, s := range registry {
		if named := strings.HasSuffix(s.Name, "-dir") || strings.HasSuffix(s.Name, "-file"); named && !s.Secret() && !s.HoldsPath() {
			t.Errorf("%s is named as a path but does not have the path shape (#587)", s.Name)
		}
	}
	ct := reflect.TypeFor[Config]()
	for i := range ct.NumField() {
		f := ct.Field(i)
		if named := strings.HasSuffix(f.Name, "Dir") || strings.HasSuffix(f.Name, "File"); named && f.Type.Kind() == reflect.String {
			if _, ok := pathFields[f.Name]; !ok {
				t.Errorf("Config.%s is named as a path but is not in pathFields (#587)", f.Name)
			}
		}
	}
}

// PathVariables lists each path setting's variable and each secret's _FILE variable, in registry
// order, and nothing else: the leak test needs a scenario for each.
func TestPathVariablesAreThePathAndSecretFileVariables(t *testing.T) {
	want := []string{
		"BYWARD_UPSTREAM_CREDENTIAL_FILE", "BYWARD_UPSTREAM_ENV_FILE", "BYWARD_TLS_CERT_FILE", "BYWARD_TLS_KEY_FILE",
		"BYWARD_ENTRA_CLIENT_SECRET_FILE", "BYWARD_ENTRA_CLIENT_CERTIFICATE_FILE", "BYWARD_ENTRA_FEDERATED_TOKEN_FILE",
		"BYWARD_OIDC_CLIENT_SECRET_FILE", "BYWARD_OIDC_CLIENT_KEY_FILE", "BYWARD_DATA_DIR", "BYWARD_KEYS_DIR",
		"BYWARD_ASSERTION_KEYS_DIR", "BYWARD_STATIC_CLIENTS_FILE", "BYWARD_STORE_DIR", "BYWARD_STORE_POSTGRES_DSN_FILE",
		"BYWARD_STORE_COUNTER_FILE",
	}
	if got := PathVariables(); !slices.Equal(got, want) {
		t.Fatalf("PathVariables() = %v, want %v", got, want)
	}
}

// scanFileOpeners scans the production code outside this package for the Config string fields
// selected inside a call to one of fileOpeners, or in one of fileOptionTypes' literals, matched by
// package name. It returns where it last saw each field and which entries of the two lists matched.
// The scan is syntactic: it matches fields by name, so a field of the same name on another type
// counts too, as does a field in a data argument. It cannot see a field copied into a variable, or
// passed to a function not listed, before it is opened, nor a package imported under another name;
// a loader in the scanned file's own package, called unqualified, cannot be listed, so it belongs in its
// own package;
// TestASettingOrFieldNamedAsAPathIsAPathSetting and the leak test cover those.
func scanFileOpeners(t *testing.T) (opened map[string]string, matched map[string]bool) {
	t.Helper()
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
	opened, matched = map[string]string{}, map[string]bool{}
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
				if name := qualifiedName(n.Fun); slices.Contains(fileOpeners, name) {
					matched[name], args = true, n.Args
				}
			case *ast.CompositeLit:
				if name := qualifiedName(n.Type); slices.Contains(fileOptionTypes, name) {
					matched[name], args = true, n.Elts
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
	return opened, matched
}

// The scan still sees what it is meant to: each of the project's loaders in fileOpeners (the os
// package's come and go with ordinary refactors) and each of fileOptionTypes matches somewhere, and
// every path field but notOpened is seen handed to one. A renamed or moved loader fails here instead
// of blinding TestEveryConfigFieldTheProxyOpensIsAPathSetting.
func TestTheFileOpenerScanSeesEveryLoaderAndPathField(t *testing.T) {
	opened, matched := scanFileOpeners(t)
	for _, name := range slices.Concat(fileOpeners, fileOptionTypes) {
		if !matched[name] && !strings.HasPrefix(name, "os.") {
			t.Errorf("%s: no call or literal in the code the scan reads matches it; a loader was renamed or removed, so update fileOpeners or fileOptionTypes", name)
		}
	}
	for _, field := range slices.Sorted(maps.Keys(pathFields)) {
		if _, ok := opened[field]; !ok && !slices.Contains(notOpened, field) {
			t.Errorf("Config.%s: no listed file opener is handed it; add its loader, new or renamed, to fileOpeners or fileOptionTypes", field)
		}
	}
}

// Every Config field the proxy hands to a file opener, outside this package, holds a path setting
// (scanFileOpeners): a new path setting, or a new loader for an existing one, is listed in
// pathFields and given the path shape.
func TestEveryConfigFieldTheProxyOpensIsAPathSetting(t *testing.T) {
	opened, _ := scanFileOpeners(t)
	for _, field := range slices.Sorted(maps.Keys(opened)) {
		if _, ok := pathFields[field]; !ok {
			t.Errorf("%s: Config.%s is handed to a file opener but is no path setting; give its setting the path shape and list it in pathFields (#587)", opened[field], field)
		}
	}
}

// qualifiedName is a selector on an identifier as ident.Name, such as os.Open or servingcert.Files,
// read as package.Name since the scan has no types; "" for anything else (a longer chain, a local
// function).
func qualifiedName(e ast.Expr) string {
	if sel, ok := e.(*ast.SelectorExpr); ok {
		if pkg, ok := sel.X.(*ast.Ident); ok {
			return pkg.Name + "." + sel.Sel.Name
		}
	}
	return ""
}
