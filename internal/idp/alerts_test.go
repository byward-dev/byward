package idp

import (
	"go/ast"
	"go/parser"
	"go/token"
	"slices"
	"testing"
)

// #204: Alerts lists every Alert constant, so metrics export each reason at 0 from the start; a
// reason added to errors.go without joining Alerts would appear only at its first alert.
func TestAlertsListsEveryAlertReason(t *testing.T) {
	f, err := parser.ParseFile(token.NewFileSet(), "errors.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, d := range f.Decls {
		g, ok := d.(*ast.GenDecl)
		if !ok || g.Tok != token.CONST {
			continue
		}
		for _, s := range g.Specs {
			v := s.(*ast.ValueSpec)
			if id, ok := v.Type.(*ast.Ident); !ok || id.Name != "Alert" {
				continue
			}
			for _, name := range v.Names {
				n++
				if !slices.ContainsFunc(Alerts, func(a Alert) bool { return string(a) == constValue(t, v, name) }) {
					t.Errorf("the Alert constant %s is not in Alerts", name.Name)
				}
			}
		}
	}
	if n != len(Alerts) {
		t.Errorf("errors.go declares %d Alert constants, Alerts lists %d", n, len(Alerts))
	}
}

// constValue is the string literal name is declared with in v.
func constValue(t *testing.T, v *ast.ValueSpec, name *ast.Ident) string {
	t.Helper()
	i := slices.Index(v.Names, name)
	lit, ok := v.Values[i].(*ast.BasicLit)
	if !ok || lit.Kind != token.STRING {
		t.Fatalf("%s is not declared with a string literal", name.Name)
	}
	return lit.Value[1 : len(lit.Value)-1]
}
