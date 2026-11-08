package idp

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// #204: Alerts lists every Alert constant of the package, so metrics export each reason at 0 from
// the start; a reason declared without joining Alerts would appear only at its first alert.
func TestEveryAlertReasonIsExportedFromTheStart(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	var declared []string
	for _, name := range files {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(token.NewFileSet(), name, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, d := range f.Decls {
			if g, ok := d.(*ast.GenDecl); ok && g.Tok == token.CONST {
				for _, s := range g.Specs {
					declared = append(declared, alertConsts(t, s.(*ast.ValueSpec))...)
				}
			}
		}
	}
	for _, v := range declared {
		if !slices.Contains(Alerts, Alert(v)) {
			t.Errorf("the Alert constant %q is not in Alerts", v)
		}
	}
	if len(declared) != len(Alerts) {
		t.Errorf("the package declares %d Alert constants %v, Alerts lists %d", len(declared), declared, len(Alerts))
	}
}

// alertConsts is the values of the Alert constants in v: typed (`X Alert = "x"`) or converted
// (`X = Alert("x")`).
func alertConsts(t *testing.T, v *ast.ValueSpec) []string {
	t.Helper()
	typed := false
	if id, ok := v.Type.(*ast.Ident); ok && id.Name == "Alert" {
		typed = true
	}
	var out []string
	for _, e := range v.Values {
		if c, ok := e.(*ast.CallExpr); ok && !typed {
			if id, ok := c.Fun.(*ast.Ident); !ok || id.Name != "Alert" || len(c.Args) != 1 {
				continue
			}
			e = c.Args[0]
		} else if !typed {
			continue
		}
		lit, ok := e.(*ast.BasicLit)
		if !ok || lit.Kind != token.STRING {
			t.Fatalf("an Alert constant is not declared with a string literal: %#v", e)
		}
		s, err := strconv.Unquote(lit.Value)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, s)
	}
	return out
}
