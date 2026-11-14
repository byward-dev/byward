package doctor

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/byward-dev/byward/internal/testutil/reftable"
)

// The checks table in the commands reference lists every check, in order, with its class from the
// code; what each one passes on is written by hand.
func TestTheChecksReferenceIsCurrent(t *testing.T) {
	var names []string
	class := map[string]Class{}
	for _, c := range Checks() {
		names = append(names, c.Name())
		class[c.Name()] = c.Class()
	}
	reftable.Sync(t, "../../docs/reference/commands.md", "### Checks", 1, names, func(name string, old []string) []string {
		passes := reftable.Todo
		if len(old) > 2 {
			passes = old[2]
		}
		return []string{"`" + string(class[name]) + "`", name, passes}
	})
}

// Every check has its own name, so a report and the reference name each one once.
func TestEveryCheckHasItsOwnName(t *testing.T) {
	seen := map[string]bool{}
	for _, c := range Checks() {
		if seen[c.Name()] {
			t.Errorf("two checks are named %q", c.Name())
		}
		seen[c.Name()] = true
	}
}

// A result gets its class and name only from a declared check, so the reference, generated from
// Checks, names every check doctor can report. No production code outside checks.go builds a
// Result literal that sets them.
func TestOnlyADeclaredCheckNamesAResult(t *testing.T) {
	root := moduleRoot(t)
	fset := token.NewFileSet()
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if path != root && (strings.HasPrefix(d.Name(), ".") || d.Name() == "build" || d.Name() == "dist" || d.Name() == "testdata") {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") || filepath.ToSlash(path) == filepath.ToSlash(filepath.Join(root, "internal/doctor/checks.go")) {
			return nil
		}
		f, err := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
		if err != nil {
			return err
		}
		inDoctor := f.Name.Name == "doctor"
		check := func(lit *ast.CompositeLit) {
			for _, e := range lit.Elts {
				kv, keyed := e.(*ast.KeyValueExpr)
				if !keyed {
					t.Errorf("%s: a Result literal without field names; use a Check's Result or NewResult", fset.Position(lit.Pos()))
					return
				}
				if k, _ := kv.Key.(*ast.Ident); k != nil && (k.Name == "Name" || k.Name == "Class") {
					t.Errorf("%s: a Result literal sets %s; declare the check in internal/doctor/checks.go and use its Result or NewResult", fset.Position(kv.Pos()), k.Name)
				}
			}
		}
		ast.Inspect(f, func(n ast.Node) bool {
			lit, ok := n.(*ast.CompositeLit)
			switch {
			case !ok:
			case isResultType(lit.Type, inDoctor):
				check(lit)
			case isResultSlice(lit.Type, inDoctor):
				// []Result{{...}}: the elements' type is left out.
				for _, e := range lit.Elts {
					if el, ok := e.(*ast.CompositeLit); ok && el.Type == nil {
						check(el)
					}
				}
			}
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// isResultType reports whether a composite literal's type is doctor.Result (Result inside the
// package).
func isResultType(e ast.Expr, inDoctor bool) bool {
	switch x := e.(type) {
	case *ast.Ident:
		return inDoctor && x.Name == "Result"
	case *ast.SelectorExpr:
		pkg, ok := x.X.(*ast.Ident)
		return ok && pkg.Name == "doctor" && x.Sel.Name == "Result"
	}
	return false
}

// isResultSlice reports whether a composite literal's type is a slice or array of Result.
func isResultSlice(e ast.Expr, inDoctor bool) bool {
	a, ok := e.(*ast.ArrayType)
	return ok && isResultType(a.Elt, inDoctor)
}

// moduleRoot is the directory holding go.mod, found upward from the test's directory.
func moduleRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("no go.mod above the test directory")
		}
		dir = parent
	}
}
