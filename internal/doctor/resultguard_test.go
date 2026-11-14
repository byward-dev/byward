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
)

// A result gets its class and name only from a declared check, so the reference, generated from
// Checks, names every check doctor can report. Outside checks.go, no production code builds a
// Result literal that sets them (in a slice, array or map with the element type left out too, and
// under any import name), nor sets them on a variable declared or assigned as a result. Without
// type information it cannot follow a result through a field, a function or another variable;
// review catches those.
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
		for _, n := range namingsOf(f) {
			t.Errorf("%s: %s; declare the check in internal/doctor/checks.go and use its Result or NewResult", fset.Position(n.pos), n.what)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// finding is a place in a file that gives a Result its class or name.
type finding struct {
	pos  token.Pos
	what string
}

// namingsOf finds, in one parsed file, every Result literal that sets Class or Name or has no field
// names, and every assignment of Class or Name to a variable declared or assigned as a result.
func namingsOf(f *ast.File) []finding {
	doctorImport := ""
	if f.Name.Name == "doctor" {
		doctorImport = "."
	}
	for _, imp := range f.Imports {
		if strings.Trim(imp.Path.Value, `"`) == "github.com/byward-dev/byward/internal/doctor" {
			doctorImport = "doctor"
			if imp.Name != nil {
				doctorImport = imp.Name.Name
			}
		}
	}
	if doctorImport == "" {
		return nil
	}
	isResult := func(e ast.Expr) bool {
		if s, ok := e.(*ast.StarExpr); ok {
			e = s.X
		}
		switch x := e.(type) {
		case *ast.Ident:
			return doctorImport == "." && x.Name == "Result"
		case *ast.SelectorExpr:
			pkg, ok := x.X.(*ast.Ident)
			return ok && pkg.Name == doctorImport && x.Sel.Name == "Result"
		}
		return false
	}
	// givesResult reports whether e is a Result literal, or a call of a Check's Result or NewResult.
	givesResult := func(e ast.Expr) bool {
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
	var out []finding
	scanLiteral := func(lit *ast.CompositeLit) {
		for _, e := range lit.Elts {
			kv, keyed := e.(*ast.KeyValueExpr)
			if !keyed {
				out = append(out, finding{lit.Pos(), "a Result literal without field names"})
				return
			}
			if k, _ := kv.Key.(*ast.Ident); k != nil && (k.Name == "Name" || k.Name == "Class") {
				out = append(out, finding{kv.Pos(), "a Result literal sets " + k.Name})
			}
		}
	}
	// scanElided scans the elements of a slice, array or map of Result whose type is left out.
	scanElided := func(lit *ast.CompositeLit) {
		for _, e := range lit.Elts {
			if kv, ok := e.(*ast.KeyValueExpr); ok {
				e = kv.Value
			}
			if el, ok := e.(*ast.CompositeLit); ok && el.Type == nil {
				scanLiteral(el)
			}
		}
	}
	// holders are the variables declared as a result or given one.
	holders := map[string]bool{}
	ast.Inspect(f, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.CompositeLit:
			switch t := x.Type.(type) {
			case *ast.ArrayType:
				if isResult(t.Elt) {
					scanElided(x)
				}
			case *ast.MapType:
				if isResult(t.Value) {
					scanElided(x)
				}
			default:
				if isResult(x.Type) {
					scanLiteral(x)
				}
			}
		case *ast.AssignStmt:
			for i, lhs := range x.Lhs {
				if id, ok := lhs.(*ast.Ident); ok && i < len(x.Rhs) && givesResult(x.Rhs[i]) {
					holders[id.Name] = true
				}
			}
		case *ast.ValueSpec:
			for i, id := range x.Names {
				if (x.Type != nil && isResult(x.Type)) || (i < len(x.Values) && givesResult(x.Values[i])) {
					holders[id.Name] = true
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
				out = append(out, finding{sel.Pos(), "an assignment sets a result's " + sel.Sel.Name})
			}
		}
		return true
	})
	return out
}

// Each way the guard can see of naming a result outside a declared check is found, and the ways
// the code names one through a check are not.
func TestTheGuardFindsEachSyntacticWayToNameAResult(t *testing.T) {
	const imp = "package p\nimport \"github.com/byward-dev/byward/internal/doctor\"\n"
	for _, tc := range []struct {
		name, src, found string // found: what the one finding says; "" for none
	}{
		{"a literal sets Name", imp + `var r = doctor.Result{Name: "x"}`, "a Result literal sets Name"},
		{"a literal sets Class only", imp + `var r = doctor.Result{Class: doctor.ClassIdP}`, "a Result literal sets Class"},
		{"a literal without field names", imp + `var r = doctor.Result{doctor.ClassIdP, "x", doctor.Pass, "", ""}`, "without field names"},
		{"a pointer literal", imp + `var r = &doctor.Result{Name: "x"}`, "a Result literal sets Name"},
		{"a slice with the type left out", imp + `var r = []doctor.Result{{Name: "x"}}`, "a Result literal sets Name"},
		{"a slice of pointers with the type left out", imp + `var r = []*doctor.Result{{Name: "x"}}`, "a Result literal sets Name"},
		{"an array with the type left out", imp + `var r = [1]doctor.Result{{Name: "x"}}`, "a Result literal sets Name"},
		{"a map with the type left out", imp + `var r = map[string]doctor.Result{"a": {Name: "x"}}`, "a Result literal sets Name"},
		{"another import name", "package p\nimport d \"github.com/byward-dev/byward/internal/doctor\"\n" + `var r = d.Result{Name: "x"}`, "a Result literal sets Name"},
		{"inside package doctor", "package doctor\n" + `var r = Result{Name: "x"}`, "a Result literal sets Name"},
		{"a name set after NewResult", imp + `func f() { r := doctor.CheckUpstream.NewResult(); r.Name = "x" }`, "an assignment sets a result's Name"},
		{"a class set after Result", imp + `func f() { r := doctor.CheckUpstream.Result(doctor.Pass, "", ""); r.Class = doctor.ClassIdP }`, "an assignment sets a result's Class"},
		{"a name set after a pointer literal", imp + `func f() { r := &doctor.Result{Status: doctor.Pass}; r.Name = "x" }`, "an assignment sets a result's Name"},
		{"a name set after var NewResult", imp + `func f() { var r = doctor.CheckUpstream.NewResult(); r.Name = "x" }`, "an assignment sets a result's Name"},
		{"a name set on a declared result", imp + `func f() { var r doctor.Result; r.Name = "x" }`, "an assignment sets a result's Name"},
		{"a check's Result", imp + `func f() doctor.Result { r := doctor.CheckUpstream.NewResult(); r.Status, r.Message = doctor.Pass, "m"; return r }`, ""},
		{"another type's Name", imp + `type s struct{ Name string }; func f() { v := s{Name: "x"}; v.Name = "y"; _ = doctor.Pass }`, ""},
		{"no doctor import", "package p\n" + `type Result struct{ Name string }; var r = Result{Name: "x"}`, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f, err := parser.ParseFile(token.NewFileSet(), "x.go", tc.src, parser.SkipObjectResolution)
			if err != nil {
				t.Fatal(err)
			}
			got := namingsOf(f)
			switch {
			case tc.found == "" && len(got) != 0:
				t.Fatalf("found %v, want nothing", got)
			case tc.found != "" && (len(got) != 1 || !strings.Contains(got[0].what, tc.found)):
				t.Fatalf("found %v, want one saying %q", got, tc.found)
			}
		})
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
