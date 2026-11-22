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

// skippedDirs hold no source of the proxy: test data, and dependency or build output.
var skippedDirs = []string{"testdata", "vendor", "node_modules", "bin", "dist", "build"}

// eachProductionGoFile parses every non-test .go file of the repository, but in dot directories and
// skippedDirs, and calls visit with its path relative to the repository root (slash-separated) and
// the file set its positions are in. Test helpers outside _test.go files, as in internal/testutil, are
// read too. The source scans of this package share it.
func eachProductionGoFile(t *testing.T, visit func(rel string, fset *token.FileSet, f *ast.File)) {
	t.Helper()
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
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
		rel, _ := filepath.Rel(root, path)
		visit(filepath.ToSlash(rel), fset, f)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
