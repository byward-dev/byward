//go:build linux || darwin

package stdio

import (
	"bytes"
	"encoding/json"
	"errors"
	"go/ast"
	"go/build"
	"go/importer"
	"go/parser"
	"go/token"
	"go/types"
	"io"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"

	"github.com/byward-dev/byward/internal/testutil/reftable"
)

// The stop reasons table in the observability reference lists every stop reason, in the order
// process.go declares them; why each is used is written by hand.
func TestTheStopReasonsReferenceIsCurrent(t *testing.T) {
	table := reftable.Table{Path: "../../../docs/reference/observability.md", Heading: "### stdio upstream stop reasons", Package: "./internal/upstream/stdio/"}
	table.Sync(t, stopReasons(t), func(reason string, old []string) []string {
		row := []string{"`" + reason + "`", reftable.Todo}
		if len(old) == len(row) {
			row[1] = old[1]
		}
		return row
	})
}

// A stop reason made anywhere but process.go's Stop reasons block would compile, since an untyped
// string constant, a literal too, converts to a stopReason implicitly, and could be missing from
// the reference. So in the type-checked production code, every constant stopReason outside the
// block names one of the block's constants, nothing is converted to a stopReason, and no generic
// is instantiated with it (its body could make one from a string).
func TestEveryStopReasonIsOneOfTheConstants(t *testing.T) {
	pkg, err := build.ImportDir(".", 0) // the production files this OS builds: no _test.go
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	var files []*ast.File
	var block *ast.GenDecl
	for _, name := range pkg.GoFiles {
		f, err := parser.ParseFile(fset, name, nil, parser.ParseComments)
		if err != nil {
			t.Fatal(err)
		}
		files = append(files, f)
		if name == "process.go" {
			block = stopReasonsBlock(f)
		}
	}
	if block == nil {
		t.Fatal("no Stop reasons block in process.go")
	}
	// Types gets every expression's type, and its value when it is a constant; Defs and Uses map
	// identifiers to what they declare and use; Instances the type arguments of generic uses.
	info := &types.Info{Types: map[ast.Expr]types.TypeAndValue{}, Defs: map[*ast.Ident]types.Object{}, Uses: map[*ast.Ident]types.Object{}, Instances: map[*ast.Ident]types.Instance{}}
	conf := types.Config{Importer: exportDataImporter(t, fset)}
	checked, err := conf.Check("github.com/byward-dev/byward/internal/upstream/stdio", fset, files, info)
	if err != nil {
		t.Fatal(err)
	}
	reason := checked.Scope().Lookup("stopReason").Type()
	blockConsts := map[types.Object]bool{}
	for _, spec := range block.Specs {
		for _, id := range spec.(*ast.ValueSpec).Names {
			blockConsts[info.Defs[id]] = true
		}
	}
	const fix = "use one of the constants in process.go's Stop reasons block; add a new reason there and to the observability reference"
	for e, tv := range info.Types {
		// tv.IsType: e is a type, such as stopReason itself. The block's own literals are
		// stopReasons too, and a parenthesised expression is checked as its inner one.
		if _, paren := e.(*ast.ParenExpr); paren || tv.IsType() || !types.Identical(tv.Type, reason) || (e.Pos() >= block.Pos() && e.End() <= block.End()) {
			continue
		}
		if call, ok := e.(*ast.CallExpr); ok && info.Types[call.Fun].IsType() {
			t.Errorf("%s: a value is converted to a stopReason: %s", fset.Position(e.Pos()), fix)
			continue
		}
		if id, ok := e.(*ast.Ident); tv.Value == nil || (ok && blockConsts[info.Uses[id]]) {
			continue // not a constant (a variable or parameter), or one of the block's constants
		}
		t.Errorf("%s: the stop reason %s is not one of the constants: %s", fset.Position(e.Pos()), tv.Value, fix)
	}
	for id, inst := range info.Instances {
		for i := range inst.TypeArgs.Len() {
			if types.Identical(inst.TypeArgs.At(i), reason) {
				t.Errorf("%s: %s is instantiated with stopReason: pass one of the Stop reasons constants instead, as its body could make a reason from a string", fset.Position(id.Pos()), id.Name)
			}
		}
	}
}

// stopReasons returns the values of the Stop reasons constant block in process.go, in order.
func stopReasons(t *testing.T) []string {
	t.Helper()
	f, err := parser.ParseFile(token.NewFileSet(), "process.go", nil, parser.ParseComments)
	if err != nil {
		t.Fatal(err)
	}
	block := stopReasonsBlock(f)
	if block == nil {
		t.Fatal("no Stop reasons block in process.go")
	}
	var reasons []string
	for _, spec := range block.Specs {
		for _, v := range spec.(*ast.ValueSpec).Values {
			lit, ok := v.(*ast.BasicLit)
			if !ok || lit.Kind != token.STRING {
				t.Fatalf("a stop reason in process.go is not a plain string")
			}
			r, err := strconv.Unquote(lit.Value)
			if err != nil {
				t.Fatal(err)
			}
			reasons = append(reasons, r)
		}
	}
	return reasons
}

// stopReasonsBlock is f's const block documented "Stop reasons.", or nil.
func stopReasonsBlock(f *ast.File) *ast.GenDecl {
	for _, d := range f.Decls {
		if g, ok := d.(*ast.GenDecl); ok && g.Tok == token.CONST && g.Doc != nil && strings.HasPrefix(g.Doc.Text(), "Stop reasons.") {
			return g
		}
	}
	return nil
}

// exportDataImporter imports this package's dependencies from the export data go list builds:
// about 0.3 s with a warm build cache and 2 s with a cold one, where type-checking them from source
// takes about ten under -race. go test puts its own toolchain first on PATH, so go list is the go
// that runs the test.
func exportDataImporter(t *testing.T, fset *token.FileSet) types.Importer {
	t.Helper()
	out, err := exec.Command("go", "list", "-export", "-deps", "-json=ImportPath,Export", ".").Output()
	if err != nil {
		var exit *exec.ExitError
		if errors.As(err, &exit) {
			t.Fatalf("go list -export: %v\n%s", err, exit.Stderr)
		}
		t.Fatalf("go list -export: %v", err)
	}
	exports := map[string]string{}
	for dec := json.NewDecoder(bytes.NewReader(out)); dec.More(); {
		var p struct{ ImportPath, Export string }
		if err := dec.Decode(&p); err != nil {
			t.Fatal(err)
		}
		exports[p.ImportPath] = p.Export
	}
	return importer.ForCompiler(fset, "gc", func(path string) (io.ReadCloser, error) {
		return os.Open(exports[path]) //nolint:gosec // G304: a path go list reported
	})
}
