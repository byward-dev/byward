package config

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"maps"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// devReader is how many .Dev selectors a production file has, and the relaxation config records
// for them with --dev; "" where config itself decides beside its Relaxations entries, or where the
// field is not Config.Dev.
type devReader struct {
	reads      int
	relaxation string
}

// devReaders are the production files that select a .Dev field (security invariant 12).
var devReaders = map[string]devReader{
	"internal/config/config.go":           {4, ""}, // the setting, and the relaxations it records
	"internal/config/config_idp.go":       {1, ""}, // OIDCLoopbackHTTP, beside its relaxation
	"internal/config/config_store.go":     {1, ""}, // the PostgreSQL relaxation
	"internal/servingcert/fileid_unix.go": {1, ""}, // syscall.Stat_t.Dev, the device of the certificate file
	"internal/server/wire_parts.go":       {1, "secret file permissions are not checked"},
	"internal/server/wire_store.go":       {1, "the PostgreSQL store accepts a connection without verify-full TLS"},
	"internal/server/doctor.go":           {1, "the PostgreSQL store accepts a connection without verify-full TLS"},
}

// --dev relaxes nothing that is not logged (#355): only the files above select a .Dev field, each
// as many times as listed, and each one's relaxation is recorded with --dev. A new reader relaxes
// something the startup log may not name; decide it in config beside its relaxation instead, as
// OIDCLoopbackHTTP is. The scan is syntactic, so it also catches Config.Dev reached through a field (w.cfg.Dev) in a
// file that does not import this package.
func TestOnlyKnownCodeReadsDevelopmentMode(t *testing.T) {
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	found, named := map[string]int{}, map[string]int{}
	fset := token.NewFileSet()
	err = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, path)
		rel = filepath.ToSlash(rel)
		if d.IsDir() {
			if path != root && (strings.HasPrefix(d.Name(), ".") || d.Name() == "testdata") {
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
			if sel, ok := n.(*ast.SelectorExpr); ok && sel.Sel.Name == "Dev" {
				if _, known := devReaders[rel]; !known {
					t.Errorf("%s: selects a .Dev field; if it is Config.Dev, decide the relaxation in config beside its Relaxations entry, otherwise list it in devReaders (#355)", fset.Position(sel.Pos()))
				}
				found[rel]++
			}
			// The setting by name reaches --dev without the field (Values.Effective, v.get).
			if lit, ok := n.(*ast.BasicLit); ok && lit.Kind == token.STRING {
				if name, err := strconv.Unquote(lit.Value); err == nil && (name == "dev" || name == "BYWARD_DEV") {
					named[rel]++
				}
			}
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	// Only config names the setting: the registry entry, and reading and checking its value.
	if want := map[string]int{"internal/config/settings.go": 1, "internal/config/config.go": 3}; !maps.Equal(named, want) {
		t.Errorf("files naming the dev setting %v, want %v: read --dev through Config, decided in config beside its relaxation (#355)", named, want)
	}
	c, err := loadDSN(t, []string{"--dev"}, "BYWARD_STORE_POSTGRES_DSN_FILE="+dsnFile)
	if err != nil {
		t.Fatal(err)
	}
	for rel, r := range devReaders {
		switch {
		case found[rel] > r.reads:
			t.Errorf("%s selects .Dev %d times, want %d: a new reader relaxes what the log may not name; decide it in config beside its relaxation (#355)", rel, found[rel], r.reads)
		case found[rel] < r.reads:
			t.Errorf("%s selects .Dev %d times, want %d: lower its count in devReaders, or remove it", rel, found[rel], r.reads)
		}
		if r.relaxation != "" && !slices.Contains(c.Relaxations, r.relaxation) {
			t.Errorf("%s: --dev records no relaxation %q (it records %q)", rel, r.relaxation, c.Relaxations)
		}
	}
}
