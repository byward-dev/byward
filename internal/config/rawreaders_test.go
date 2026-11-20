package config

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

// rawReaders are the functions besides the parsers (parse… and Parse…) that may call raw: the shape's
// display, and, until #512, the readers of the settings in readAsText.
var rawReaders = []string{
	"Display",            // a value as its shape shows it
	"get",                // readAsText's settings (#512)
	"upstreamCredential", // the upstream credential, a secret; moved by #512
}

// byName are the functions that read the setting they are given by name through get: the place of
// that name among their arguments, and how many they take. A literal name given to one must be in
// readAsText too (#512).
var byName = map[string]struct{ at, args int }{"get": {0, 1}, "boolean": {0, 1}, "upstreamHeader": {1, 3}}

// namingOnly are the Values methods that take a setting's name but read no text.
var namingOnly = []string{"value", "empty", "given", "holds", "display", "emptySecretFile"}

// byVariable are the functions that give a byName function a setting name that is not a literal (#512).
// A setting written in one may be read there; get panics on one outside readAsText, in every load.
var byVariable = []string{"boolean", "upstreamHeader", "gate", "paths", "upstream"}

// A setting's given text is read only by its parser, which turns it into the accepted value or into a
// refusal that never repeats it, and by its shape's display (ADR-0031 §1): Opaque.raw is called only
// in a function named parse… or Parse…, or one listed in rawReaders; it is never taken as a value or
// a method expression, and no file but opaque.go reaches the text behind an Opaque (its field p).
// Until #512, get reads the settings in readAsText as text (and panics on any other): a literal name
// given to get, or to a function that reads its setting through get (byName), must be on that list;
// only the functions in byVariable give one a name that is not a literal (get panics, in every load,
// on any setting outside the list, however the name reaches it); and every setting on the list is
// still read so, so the list only shrinks. raw is unexported, so no other package reads the text at all. The scan is syntactic, so it
// cannot tell which setting a parser reads: a function named parse… that reads another setting's text
// passes, and review catches it.
func TestOnlyParsersReadARawValue(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	names := map[string]bool{}
	for _, s := range registry {
		names[s.Name] = true
	}
	for n := range readAsText {
		if !names[n] {
			t.Errorf("readAsText names %s, which is not a setting", n)
		}
	}
	read := map[string]bool{}
	parsers, gets := 0, 0
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
				t.Errorf("%s: %s takes raw or a byName function as a value: call it, in the setting's parser", r.pos, r.fn)
			case r.kind == readRaw && (strings.HasPrefix(r.fn, "parse") || strings.HasPrefix(r.fn, "Parse")):
				parsers++
			case r.kind == readRaw && !slices.Contains(rawReaders, r.fn):
				t.Errorf("%s: %s calls raw: read a setting's text only in its parser, a function named parse…, which never repeats it in a refusal (ADR-0031 §1)", r.pos, r.fn)
			case r.kind == readRaw:
			case r.kind == readNamed && slices.Contains(byVariable, r.fn) && readAsText[r.name]:
				// A setting named in such a function may be read through get there; one with a parser of
				// its own may be named too (for a message), and get panics on it if it is read.
				read[r.name] = true
			case r.kind == readNamed:
			case r.name == "" && !slices.Contains(byVariable, r.fn):
				t.Errorf("%s: %s calls %s with a setting name that is not a literal: name it, or read the setting through a parser", r.pos, r.fn, r.reader)
			case r.name != "" && !readAsText[r.name]:
				t.Errorf("%s: %s reads %s through %s, but it has a parser of its own: read it through that (v.value)", r.pos, r.fn, r.name, r.reader)
			default:
				read[r.name] = true
				gets++
			}
		}
	}
	for n := range readAsText {
		if !read[n] {
			t.Errorf("readAsText names %s, which nothing reads through get any more: remove it from the list", n)
		}
	}
	if parsers < 10 || gets < 10 {
		t.Fatalf("found %d raw calls in parsers and %d reads by name, want at least 10 of each: the scan has stopped finding them", parsers, gets)
	}
}

// The scan rawReadsOf finds each way of reading a setting's text, and nothing else.
func TestTheRawReadScanFindsEachWayOfReadingAValueAndNothingElse(t *testing.T) {
	cases := []struct {
		name, code string
		want       []rawRead
		named      bool // the string literals count too
	}{
		{"raw in a function", `func f(v Value) { v.Given.raw() }`, []rawRead{{fn: "f", kind: readRaw}}, false},
		{"raw in a method", `func (c *Config) f(v Value) { _ = v.Given.raw() }`, []rawRead{{fn: "f", kind: readRaw}}, false},
		{"raw in a function literal counts for its function", `func f(v Value) { g := func() string { return v.Given.raw() }; g() }`, []rawRead{{fn: "f", kind: readRaw}}, false},
		{"raw in a package-level var", `var x = v.Given.raw()`, []rawRead{{fn: "x", kind: readRaw}}, false},
		{"raw taken as a value", `func f(v Value) { g := v.Given.raw; g() }`, []rawRead{{fn: "f", kind: readRawValue}}, false},
		{"raw as a method expression", `func f(v Value) { Opaque.raw(v.Given) }`, []rawRead{{fn: "f", kind: readRawValue}}, false},
		{"the text behind an Opaque", `func f(v Value) { _ = *v.Given.p }`, []rawRead{{fn: "f", kind: readField}}, false},
		{"get by name", `func f(v *Values) { v.get("listen") }`, []rawRead{{fn: "f", kind: readByName, reader: "get", name: "listen"}}, false},
		{"get by a variable", `func f(v *Values, n string) { v.get(n) }`, []rawRead{{fn: "f", kind: readByName, reader: "get"}}, false},
		{"a boolean by name", `func f(v *Values) { v.boolean("dcr") }`, []rawRead{{fn: "f", kind: readByName, reader: "boolean", name: "dcr"}}, false},
		{"a header by name", `func f(v *Values) { upstreamHeader(v, "obo-header", "X") }`, []rawRead{{fn: "f", kind: readByName, reader: "upstreamHeader", name: "obo-header"}}, false},
		{"a Raw field is not a read", `func f(c Cert) { _ = c.Raw }`, nil, false},
		{"raw with an argument counts as a method expression", `func f(x X) { x.raw(1) }`, []rawRead{{fn: "f", kind: readRawValue}}, false},
		{"raw as a method expression through a pointer", `func f(o Opaque) { (*Opaque).raw(&o) }`, []rawRead{{fn: "f", kind: readRawValue}}, false},
		{"raw called in parentheses", `func f(v Value) { (v.Given.raw)() }`, []rawRead{{fn: "f", kind: readRaw}}, false},
		{"get taken as a value", `func f(v *Values) { g := v.get; g("listen") }`, []rawRead{{fn: "f", kind: readRawValue}}, false},
		{"get taken as a value through a field", `func f(c *Config) { g := c.Values.get; g("listen") }`, []rawRead{{fn: "f", kind: readRawValue}}, false},
		{"get as a method expression", `func f(v *Values) { (*Values).get(v, "listen") }`, []rawRead{{fn: "f", kind: readRawValue}}, false},
		{"get with a name built by concatenation", `func f(v *Values) { v.get("up" + "stream-url") }`, []rawRead{{fn: "f", kind: readByName, reader: "get"}}, false},
		{"a setting named in a table", `func f() { _ = []string{"dcr"} }`, []rawRead{{fn: "f", kind: readNamed, name: "dcr"}}, true},
		{"a setting only named is no read", `func f(v *Values) { _ = Setting{Name: "dcr"}; v.empty("dcr") }`, nil, true},
		{"a setting only named, in parentheses, is no read", `func f(v *Values) { (v.empty)("dcr") }`, nil, true},
		{"get with two arguments is another method", `func f(m M) { m.get("a", "b") }`, nil, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var got []rawRead
			for _, r := range rawReadsOf(t, "x.go", "package config\n"+c.code+"\n") {
				if r.kind != readNamed || c.named {
					r.pos = token.Position{}
					got = append(got, r)
				}
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
	readRawValue = "raw or a byName function taken as a value, or raw as a method expression"
	readField    = "the field p"
	readByName   = "a call that reads a setting through get"
	readNamed    = "a string literal, which may name a setting"
)

// rawRead is a read of a setting's text found by rawReadsOf.
type rawRead struct {
	pos    token.Position
	fn     string // the enclosing function, or the package-level var
	kind   string
	reader string // for readByName: the function called
	name   string // for readByName: the setting name, when it is a string literal
}

// rawReadsOf scans the Go file name (its source src, or read from the disk if src is nil) for reads of
// a setting's text, in its functions and package-level vars: calls of raw with no arguments, raw used
// any other way, the field p, and calls of the byName functions with their arguments.
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
		// A setting's name that only names it, as Setting{Name: …} or an argument of a Values method
		// that reads no text, is not a read.
		mentions := map[*ast.BasicLit]bool{}
		ast.Inspect(n, func(n ast.Node) bool {
			switch n := n.(type) {
			case *ast.KeyValueExpr:
				if k, ok := n.Key.(*ast.Ident); ok && k.Name == "Name" {
					if lit, ok := n.Value.(*ast.BasicLit); ok {
						mentions[lit] = true
					}
				}
			case *ast.CallExpr:
				if f, ok := ast.Unparen(n.Fun).(*ast.SelectorExpr); ok && slices.Contains(namingOnly, f.Sel.Name) {
					for _, a := range n.Args {
						if lit, ok := a.(*ast.BasicLit); ok {
							mentions[lit] = true
						}
					}
				}
			}
			return true
		})
		ast.Inspect(n, func(n ast.Node) bool {
			switch n := n.(type) {
			case *ast.CallExpr:
				var fun string
				switch f := ast.Unparen(n.Fun).(type) {
				case *ast.SelectorExpr:
					fun = f.Sel.Name
					called[f] = true
					if fun == "raw" {
						kind := readRaw
						if len(n.Args) != 0 { // a method expression: Opaque.raw(o), (*Opaque).raw(&o)
							kind = readRawValue
						}
						out = append(out, rawRead{pos: fset.Position(n.Pos()), fn: owner, kind: kind})
						return true
					}
				case *ast.Ident:
					fun = f.Name
				}
				if f, ok := ast.Unparen(n.Fun).(*ast.SelectorExpr); ok && fun == "get" {
					if _, star := ast.Unparen(f.X).(*ast.StarExpr); star { // (*Values).get(v, name)
						out = append(out, rawRead{pos: fset.Position(n.Pos()), fn: owner, kind: readRawValue})
						return true
					}
				}
				if b, ok := byName[fun]; ok && len(n.Args) == b.args {
					r := rawRead{pos: fset.Position(n.Pos()), fn: owner, kind: readByName, reader: fun}
					if lit, ok := n.Args[b.at].(*ast.BasicLit); ok && lit.Kind == token.STRING {
						r.name, _ = strconv.Unquote(lit.Value)
					}
					out = append(out, r)
				}
			case *ast.SelectorExpr:
				_, byNameFunc := byName[n.Sel.Name]
				switch {
				case (n.Sel.Name == "raw" || byNameFunc && n.Sel.Name != "get") && !called[n]:
					out = append(out, rawRead{pos: fset.Position(n.Pos()), fn: owner, kind: readRawValue})
				case n.Sel.Name == "get" && !called[n]:
					out = append(out, rawRead{pos: fset.Position(n.Pos()), fn: owner, kind: readRawValue})
				case n.Sel.Name == "p":
					out = append(out, rawRead{pos: fset.Position(n.Pos()), fn: owner, kind: readField})
				}
			case *ast.BasicLit:
				if name, err := strconv.Unquote(n.Value); n.Kind == token.STRING && err == nil && !mentions[n] {
					out = append(out, rawRead{pos: fset.Position(n.Pos()), fn: owner, kind: readNamed, name: name})
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
