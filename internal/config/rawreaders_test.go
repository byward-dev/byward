package config

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// rawReaders are the functions besides the parsers (parse… and Parse…) that may call raw: the shape's
// display.
var rawReaders = []string{
	"Display", // a value as its shape shows it
}

// A setting's given text is read only by its parser, which turns it into the accepted value or into a
// refusal that never repeats it, and by its shape's display (ADR-0031 §1): Opaque.raw is called only
// in a function named parse… or Parse…, or one listed in rawReaders; it is never taken as a value or
// a method expression, and no file but opaque.go reaches the text behind an Opaque (its field p). raw
// is unexported, so no other package reads the text at all. The scan is syntactic, so it cannot tell
// which setting a parser reads: a function named parse… that reads another setting's text passes,
// and review catches it; TestNoCommandShowsAHiddenOrARefusedValue (cmd/byward) checks that no refusal
// shows it.
func TestOnlyParsersReadARawValue(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	parsers := 0
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		for _, r := range rawReadsOf(t, f, nil) {
			switch {
			case r.kind == readField && f != "opaque.go":
				t.Errorf("%s: %s reaches an Opaque's text through its field: call raw in the setting's parser", r.pos, r.fn)
			case r.kind == readField:
			case r.kind == readRawValue:
				t.Errorf("%s: %s takes raw as a value: call it, in the setting's parser", r.pos, r.fn)
			case strings.HasPrefix(r.fn, "parse") || strings.HasPrefix(r.fn, "Parse"):
				parsers++
			case !slices.Contains(rawReaders, r.fn):
				t.Errorf("%s: %s calls raw: read a setting's text only in its parser, a function named parse…, which never repeats it in a refusal (ADR-0031 §1)", r.pos, r.fn)
			}
		}
	}
	if parsers < 20 {
		t.Fatalf("found %d raw calls in parsers, want at least 20: the scan has stopped finding them", parsers)
	}
}

// The scan rawReadsOf finds each way of reading a setting's text, and nothing else.
func TestTheRawReadScanFindsEachWayOfReadingAValueAndNothingElse(t *testing.T) {
	cases := []struct {
		name, code string
		want       []rawRead
	}{
		{"raw in a function", `func f(v Value) { v.Given.raw() }`, []rawRead{{fn: "f", kind: readRaw}}},
		{"raw in a method", `func (c *Config) f(v Value) { _ = v.Given.raw() }`, []rawRead{{fn: "f", kind: readRaw}}},
		{"raw in a function literal counts for its function", `func f(v Value) { g := func() string { return v.Given.raw() }; g() }`, []rawRead{{fn: "f", kind: readRaw}}},
		{"raw in a package-level var", `var x = v.Given.raw()`, []rawRead{{fn: "x", kind: readRaw}}},
		{"raw taken as a value", `func f(v Value) { g := v.Given.raw; g() }`, []rawRead{{fn: "f", kind: readRawValue}}},
		{"raw as a method expression", `func f(v Value) { Opaque.raw(v.Given) }`, []rawRead{{fn: "f", kind: readRawValue}}},
		{"the text behind an Opaque", `func f(v Value) { _ = *v.Given.p }`, []rawRead{{fn: "f", kind: readField}}},
		{"a Raw field is not a read", `func f(c Cert) { _ = c.Raw }`, nil},
		{"raw with an argument counts as a method expression", `func f(x X) { x.raw(1) }`, []rawRead{{fn: "f", kind: readRawValue}}},
		{"raw as a method expression through a pointer", `func f(o Opaque) { (*Opaque).raw(&o) }`, []rawRead{{fn: "f", kind: readRawValue}}},
		{"raw called in parentheses", `func f(v Value) { (v.Given.raw)() }`, []rawRead{{fn: "f", kind: readRaw}}},
		{"a setting's parser is no read", `func f(v *Values) { parseText(v.value("dcr")) }`, nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var got []rawRead
			for _, r := range rawReadsOf(t, "x.go", "package config\n"+c.code+"\n") {
				r.pos = token.Position{}
				got = append(got, r)
			}
			if !slices.Equal(got, c.want) {
				t.Errorf("got %+v, want %+v", got, c.want)
			}
		})
	}
}

// What a rawRead is.
const (
	readRaw      = "a call of raw"
	readRawValue = "raw taken as a value, or as a method expression"
	readField    = "the field p"
)

// rawRead is a read of a setting's text found by rawReadsOf.
type rawRead struct {
	pos  token.Position
	fn   string // the enclosing function, or the package-level var
	kind string
}

// rawReadsOf scans the Go file name (its source src, or read from the disk if src is nil) for reads of
// a setting's text, in its functions and package-level vars: calls of raw with no arguments, raw used
// any other way, and the field p.
func rawReadsOf(t *testing.T, name string, src any) []rawRead {
	t.Helper()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, name, src, parser.SkipObjectResolution)
	if err != nil {
		t.Fatal(err)
	}
	var out []rawRead
	scan := func(owner string, n ast.Node) {
		called := map[*ast.SelectorExpr]bool{}
		ast.Inspect(n, func(n ast.Node) bool {
			switch n := n.(type) {
			case *ast.CallExpr:
				if f, ok := ast.Unparen(n.Fun).(*ast.SelectorExpr); ok && f.Sel.Name == "raw" {
					called[f] = true
					kind := readRaw
					if len(n.Args) != 0 { // a method expression: Opaque.raw(o), (*Opaque).raw(&o)
						kind = readRawValue
					}
					out = append(out, rawRead{pos: fset.Position(n.Pos()), fn: owner, kind: kind})
				}
			case *ast.SelectorExpr:
				switch {
				case n.Sel.Name == "raw" && !called[n]:
					out = append(out, rawRead{pos: fset.Position(n.Pos()), fn: owner, kind: readRawValue})
				case n.Sel.Name == "p":
					out = append(out, rawRead{pos: fset.Position(n.Pos()), fn: owner, kind: readField})
				}
			}
			return true
		})
	}
	for _, d := range f.Decls {
		switch d := d.(type) {
		case *ast.FuncDecl:
			scan(d.Name.Name, d)
		case *ast.GenDecl:
			for _, spec := range d.Specs {
				if vs, ok := spec.(*ast.ValueSpec); ok {
					scan(vs.Names[0].Name, vs)
				}
			}
		}
	}
	return out
}
