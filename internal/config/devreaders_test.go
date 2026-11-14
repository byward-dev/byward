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

// devReaders are the production files outside this package that select a .Dev field, each paired
// with the relaxation config records for it with --dev (security invariant 12); "" for a .Dev that
// is not Config.Dev.
var devReaders = map[string]string{
	"internal/servingcert/fileid_unix.go": "", // syscall.Stat_t.Dev, the device of the certificate file
	"internal/server/wire_parts.go":       "secret file permissions are not checked",
	"internal/server/wire_store.go": "the PostgreSQL store accepts a connection without verify-full TLS",
	"internal/server/doctor.go":     "the PostgreSQL store accepts a connection without verify-full TLS",
}

// --dev relaxes nothing that is not logged (#355): outside config, only the files above select a
// .Dev field, and each one's relaxation is recorded with --dev. A new reader relaxes something the
// startup log may not name; decide it in config beside its relaxation instead, as OIDCLoopbackHTTP
// is. The scan is syntactic, so it also catches Config.Dev reached through a field (w.cfg.Dev) in a
// file that does not import this package.
func TestOnlyKnownCodeReadsDevelopmentMode(t *testing.T) {
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	found := map[string]bool{}
	fset := token.NewFileSet()
	err = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, path)
		rel = filepath.ToSlash(rel)
		if d.IsDir() {
			if path != root && (strings.HasPrefix(d.Name(), ".") || d.Name() == "testdata" || rel == "internal/config") {
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
					t.Errorf("%s: reads Config.Dev; decide the relaxation in config beside its Relaxations entry (#355)", fset.Position(sel.Pos()))
				}
				found[rel] = true
			}
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	c, err := loadDSN(t, []string{"--dev"}, "BYWARD_STORE_POSTGRES_DSN_FILE="+dsnFile)
	if err != nil {
		t.Fatal(err)
	}
	for rel, relaxation := range devReaders {
		if !found[rel] {
			t.Errorf("%s no longer selects .Dev: remove it from devReaders", rel)
		}
		if relaxation != "" && !slices.Contains(c.Relaxations, relaxation) {
			t.Errorf("%s: --dev records no relaxation %q (it records %q)", rel, relaxation, c.Relaxations)
		}
	}
}
