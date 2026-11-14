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
	table := reftable.Table{Path: "../../docs/reference/commands.md", Heading: "### Checks", KeyCol: 1, Package: "./internal/doctor/"}
	table.Sync(t, names, func(name string, old []string) []string {
		row := []string{"`" + string(class[name]) + "`", name, reftable.Todo}
		if len(old) == len(row) {
			row[2] = old[2]
		}
		return row
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
// Checks, names every check doctor can report. Outside checks.go, no production code builds a
// Result literal that sets them (in a slice, array or map with the element type left out too, and
// under any import name), nor assigns them to a variable that holds a result. Without type
// information it cannot follow a result through a field, a function or another variable; review
// catches those.
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
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") || path == filepath.Join(root, "internal", "doctor", "checks.go") {
			return nil
		}
		f, err := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
		if err != nil {
			return err
		}
		for _, problem := range resultNamers(f) {
			t.Errorf("%s: %s; declare the check in internal/doctor/checks.go and use its Result or NewResult", fset.Position(problem.pos), problem.what)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// namer is a place in a file that gives a Result its class or name.
type namer struct {
	pos  token.Pos
	what string
}

// resultNamers finds, in one parsed file, every Result literal that sets Class or Name or has no
// field names, and every assignment of Class or Name to a variable that holds a result.
func resultNamers(f *ast.File) []namer {
	doctorName := ""
	if f.Name.Name == "doctor" {
		doctorName = "."
	}
	for _, imp := range f.Imports {
		if strings.Trim(imp.Path.Value, `"`) == "github.com/byward-dev/byward/internal/doctor" {
			doctorName = "doctor"
			if imp.Name != nil {
				doctorName = imp.Name.Name
			}
		}
	}
	if doctorName == "" {
		return nil
	}
	isResult := func(e ast.Expr) bool {
		if s, ok := e.(*ast.StarExpr); ok {
			e = s.X
		}
		switch x := e.(type) {
		case *ast.Ident:
			return doctorName == "." && x.Name == "Result"
		case *ast.SelectorExpr:
			pkg, ok := x.X.(*ast.Ident)
			return ok && pkg.Name == doctorName && x.Sel.Name == "Result"
		}
		return false
	}
	var out []namer
	literal := func(lit *ast.CompositeLit) {
		for _, e := range lit.Elts {
			kv, keyed := e.(*ast.KeyValueExpr)
			if !keyed {
				out = append(out, namer{lit.Pos(), "a Result literal without field names"})
				return
			}
			if k, _ := kv.Key.(*ast.Ident); k != nil && (k.Name == "Name" || k.Name == "Class") {
				out = append(out, namer{kv.Pos(), "a Result literal sets " + k.Name})
			}
		}
	}
	// elided checks the elements of a slice, array or map of Result whose type is left out.
	elided := func(lit *ast.CompositeLit) {
		for _, e := range lit.Elts {
			if kv, ok := e.(*ast.KeyValueExpr); ok {
				e = kv.Value
			}
			if u, ok := e.(*ast.UnaryExpr); ok {
				e = u.X
			}
			if el, ok := e.(*ast.CompositeLit); ok && el.Type == nil {
				literal(el)
			}
		}
	}
	// holders are the variables given a result: from a Result literal or a Check's Result or NewResult.
	holders := map[string]bool{}
	ast.Inspect(f, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.CompositeLit:
			switch t := x.Type.(type) {
			case *ast.ArrayType:
				if isResult(t.Elt) {
					elided(x)
				}
			case *ast.MapType:
				if isResult(t.Value) {
					elided(x)
				}
			default:
				if isResult(x.Type) {
					literal(x)
				}
			}
		case *ast.AssignStmt:
			for i, lhs := range x.Lhs {
				if i < len(x.Rhs) && givesResult(x.Rhs[i], isResult) {
					if id, ok := lhs.(*ast.Ident); ok {
						holders[id.Name] = true
					}
				}
			}
		}
		return true
	})
	ast.Inspect(f, func(n ast.Node) bool {
		a, ok := n.(*ast.AssignStmt)
		if !ok {
			return true
		}
		for _, lhs := range a.Lhs {
			sel, ok := lhs.(*ast.SelectorExpr)
			if !ok || (sel.Sel.Name != "Name" && sel.Sel.Name != "Class") {
				continue
			}
			if id, ok := sel.X.(*ast.Ident); ok && holders[id.Name] {
				out = append(out, namer{sel.Pos(), "an assignment sets a result's " + sel.Sel.Name})
			}
		}
		return true
	})
	return out
}

// givesResult reports whether e is a Result literal, or a call of a Check's Result or NewResult.
func givesResult(e ast.Expr, isResult func(ast.Expr) bool) bool {
	if u, ok := e.(*ast.UnaryExpr); ok {
		e = u.X
	}
	switch x := e.(type) {
	case *ast.CompositeLit:
		return isResult(x.Type)
	case *ast.CallExpr:
		sel, ok := x.Fun.(*ast.SelectorExpr)
		return ok && (sel.Sel.Name == "Result" || sel.Sel.Name == "NewResult")
	}
	return false
}

// Each way of naming a result outside a declared check is found, and the ways the code names one
// through a check are not.
func TestTheGuardFindsEveryWayToNameAResult(t *testing.T) {
	const imp = "package p\nimport \"github.com/byward-dev/byward/internal/doctor\"\n"
	for _, tc := range []struct {
		name, src string
		found     int
	}{
		{"a literal sets Name", imp + `var r = doctor.Result{Name: "x"}`, 1},
		{"a literal sets Class only", imp + `var r = doctor.Result{Class: doctor.ClassIdP}`, 1},
		{"a literal without field names", imp + `var r = doctor.Result{doctor.ClassIdP, "x", doctor.Pass, "", ""}`, 1},
		{"a pointer literal", imp + `var r = &doctor.Result{Name: "x"}`, 1},
		{"a slice with the type left out", imp + `var r = []doctor.Result{{Name: "x"}}`, 1},
		{"a slice of pointers with the type left out", imp + `var r = []*doctor.Result{{Name: "x"}}`, 1},
		{"an array with the type left out", imp + `var r = [1]doctor.Result{{Name: "x"}}`, 1},
		{"a map with the type left out", imp + `var r = map[string]doctor.Result{"a": {Name: "x"}}`, 1},
		{"another import name", "package p\nimport d \"github.com/byward-dev/byward/internal/doctor\"\n" + `var r = d.Result{Name: "x"}`, 1},
		{"inside package doctor", "package doctor\n" + `var r = Result{Name: "x"}`, 1},
		{"a name set after NewResult", imp + `func f() { r := doctor.CheckUpstream.NewResult(); r.Name = "x" }`, 1},
		{"a class set after Result", imp + `func f() { r := doctor.CheckUpstream.Result(doctor.Pass, "", ""); r.Class = doctor.ClassIdP }`, 1},
		{"a check's Result", imp + `func f() doctor.Result { r := doctor.CheckUpstream.NewResult(); r.Status, r.Message = doctor.Pass, "m"; return r }`, 0},
		{"another type's Name", imp + `type s struct{ Name string }; func f() { v := s{Name: "x"}; v.Name = "y"; _ = doctor.Pass }`, 0},
		{"no doctor import", "package p\n" + `type Result struct{ Name string }; var r = Result{Name: "x"}`, 0},
	} {
		f, err := parser.ParseFile(token.NewFileSet(), "x.go", tc.src, parser.SkipObjectResolution)
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if got := resultNamers(f); len(got) != tc.found {
			t.Errorf("%s: found %d, want %d (%v)", tc.name, len(got), tc.found, got)
		}
	}
}

// Checks hands out a copy: changing it changes no later list.
func TestChecksIsACopy(t *testing.T) {
	first := Checks()
	first[0] = CheckAuthentication
	_ = append(first[:1], CheckAuthentication)
	if again := Checks(); again[0] != CheckTLSCertificateExpiry || again[1] != CheckTLSCertificateNames {
		t.Fatalf("Checks() starts %v, %v after a caller changed its copy", again[0].Name(), again[1].Name())
	}
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
