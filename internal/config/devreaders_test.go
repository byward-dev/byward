package config

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// devReaders are the production files outside this package that read Config.Dev, each paired with
// the relaxation config records whenever --dev is set (security invariant 12).
var devReaders = map[string]string{
	"internal/server/wire_parts.go": "secret file permissions are not checked",
	"internal/server/wire_store.go": "the PostgreSQL store accepts a connection without verify-full TLS",
	"internal/server/doctor.go":     "the PostgreSQL store accepts a connection without verify-full TLS",
}

// --dev relaxes nothing that is not logged (#355): outside config, only the files above read
// Config.Dev. A new reader relaxes something the startup log may not name; decide it in config
// beside its relaxation instead, as OIDCLoopbackHTTP is. The scan is syntactic: a file that
// imports this package and selects .Dev.
func TestOnlyKnownCodeReadsDevelopmentMode(t *testing.T) {
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	const self = "github.com/byward-dev/byward/internal/config"
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
		imports := false
		for _, im := range f.Imports {
			if p, _ := strconv.Unquote(im.Path.Value); p == self {
				imports = true
			}
		}
		if !imports {
			return nil
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
	for rel := range devReaders {
		if !found[rel] {
			t.Errorf("%s no longer reads Config.Dev: remove it from devReaders", rel)
		}
	}
}
