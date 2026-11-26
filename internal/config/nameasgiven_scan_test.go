package config

import (
	"go/ast"
	"go/parser"
	"go/token"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// A variableNaming is a place in a function that names a setting by its variable whatever the
// source: a call of Setting.Env, EnvToSet or FileEnv, or a string literal that spells a setting's
// variable.
type variableNaming struct {
	fn, what string
}

// variableRef finds a variable's name in a string. It is not envnames_test.go's envName, which also
// matches the docs' family form (BYWARD_GATE_*): code spells whole names only.
var variableRef = regexp.MustCompile(`BYWARD_[A-Z0-9_]+`)

// variableMethods are Setting's methods that give a variable's name.
var variableMethods = []string{"Env", "EnvToSet", "FileEnv"}

// variableNamingsOf scans the function bodies of the Go source src (read from file when src is nil)
// for variableNamings. variables are the names a string literal must not spell. Package-level
// declarations, such as the registry's help text, are not scanned.
func variableNamingsOf(t *testing.T, file string, src any, variables map[string]bool) []variableNaming {
	t.Helper()
	f, err := parser.ParseFile(token.NewFileSet(), file, src, parser.SkipObjectResolution)
	if err != nil {
		t.Fatal(err)
	}
	var found []variableNaming
	for _, d := range f.Decls {
		fd, ok := d.(*ast.FuncDecl)
		if !ok || fd.Body == nil {
			continue
		}
		ast.Inspect(fd.Body, func(n ast.Node) bool {
			switch n := n.(type) {
			case *ast.CallExpr:
				if sel, ok := ast.Unparen(n.Fun).(*ast.SelectorExpr); ok && len(n.Args) == 0 && slices.Contains(variableMethods, sel.Sel.Name) {
					found = append(found, variableNaming{fd.Name.Name, "Setting." + sel.Sel.Name})
				}
			case *ast.BasicLit:
				if n.Kind != token.STRING {
					return true
				}
				s, err := strconv.Unquote(n.Value)
				if err != nil {
					t.Fatal(err)
				}
				for _, v := range variableRef.FindAllString(s, -1) {
					if variables[v] {
						found = append(found, variableNaming{fd.Name.Name, v})
					}
				}
			}
			return true
		})
	}
	return found
}

// reported says whether the scan reports n, found in file: always for a string literal, and for a
// Setting method call unless allowed lists its function, by "file:function".
func reported(allowed map[string]string, file string, n variableNaming) bool {
	_, ok := allowed[file+":"+n.fn]
	return !ok || !strings.HasPrefix(n.what, "Setting.")
}

// No refusal in internal/config names a setting by its variable whatever the source (#623): it names
// it through Value.nameAsGiven (NameAsGiven, refusedForm, refusedMeaning, listsNothing), so a setting
// given by flag is named by its flag. A Setting method that gives a variable is called only in the
// functions listed here, by file and function, each for its reason, and no string literal in a
// function spells a setting's variable. A listed function that no longer calls one fails too, so the
// list stays exact.
func TestNoRefusalNamesASettingByItsVariableWhateverTheSource(t *testing.T) {
	allowed := map[string]string{
		"registry.go:PathVariables":          "lists the variables that hold a path",
		"registry.go:FileEnv":                "builds a secret's file variable from its variable",
		"registry.go:EnvToSet":               "is the variable an operator is told to set",
		"registry.go:nameAsGiven":            "names a setting by its file setting or variable, and one left at its default or built without a source by the variable to set",
		"registry.go:resolve":                "reads the environment, names two forms both given there, and the two ways to give the command beside a command after --",
		"config_upstream.go:offModeSettings": "names the other mode's selector as advice, the variable to set",
		"registry.go:knownVariables":         "lists the variables byward reads",
		"config_parse.go:checkInlineSecrets": "names an inline secret, which only the environment gives, and its file variable to set",
		"quickstart.go:EnvFile":              "writes the quickstart's env file",
		"settings.go:Usage":                  "lists each setting's variable in --help",
		"settings.go:reference":              "lists each setting's variable in the settings reference",
	}
	variables := knownVariables(registry)
	seen := map[string]bool{}
	for _, f := range packageGoFiles(t) {
		for _, n := range variableNamingsOf(t, f, nil, variables) {
			if !reported(allowed, f, n) {
				seen[f+":"+n.fn] = true
				continue
			}
			t.Errorf("%s: %s names a setting with %s whatever the source: name it with NameAsGiven, or the value's name (Value.nameAsGiven)", f, n.fn, n.what)
		}
	}
	for key, why := range allowed {
		if !seen[key] {
			t.Errorf("%s is allowed a variable from a Setting (it %s), but the scan finds none there: remove it from the list", key, why)
		}
	}
}

// The scan variableNamingsOf finds each way of naming a setting by its variable, and nothing else.
func TestTheNamingScanFindsAVariableNamedWhateverTheSourceAndNothingElse(t *testing.T) {
	variables := map[string]bool{"BYWARD_LISTEN": true}
	for _, tc := range []struct {
		name, code string
		want       []variableNaming
	}{
		{"Setting.Env", `func f(s Setting) string { return s.Env() }`, []variableNaming{{"f", "Setting.Env"}}},
		{"Setting.EnvToSet", `func f(s Setting) string { return s.EnvToSet() }`, []variableNaming{{"f", "Setting.EnvToSet"}}},
		{"Setting.FileEnv", `func f(s Setting) string { return s.FileEnv() }`, []variableNaming{{"f", "Setting.FileEnv"}}},
		{"Setting.Env in a function literal", `func f() { g := func() string { return Setting{Name: "listen"}.Env() }; g() }`, []variableNaming{{"f", "Setting.Env"}}},
		{"a format string spelling a setting's variable", `func f() error { return errorf("BYWARD_LISTEN: must be loopback") }`, []variableNaming{{"f", "BYWARD_LISTEN"}}},
		{"a raw format string", "func f() error { return errorf(`%s and BYWARD_LISTEN`, x) }", []variableNaming{{"f", "BYWARD_LISTEN"}}},
		{"an argument of a format string", `func f() error { return errorf("%s: no", "BYWARD_LISTEN") }`, []variableNaming{{"f", "BYWARD_LISTEN"}}},
		{"fmt.Errorf", `func f() error { return fmt.Errorf("BYWARD_LISTEN: no") }`, []variableNaming{{"f", "BYWARD_LISTEN"}}},
		{"a concatenation", `func f(p string) error { return errorf(p + "BYWARD_LISTEN") }`, []variableNaming{{"f", "BYWARD_LISTEN"}}},
		{"a call over several lines", "func f() error {\n\treturn errorf(\"%s: no\",\n\t\t\"BYWARD_LISTEN\")\n}", []variableNaming{{"f", "BYWARD_LISTEN"}}},
		{"a variable that is not a setting's", `func f() error { return errorf("BYWARD_SUBJECT is set") }`, nil},
		{"a package-level declaration", `var help = "set BYWARD_LISTEN"`, nil},
		{"the name as given", `func f(v *Values) error { return errorf("%s: no", v.NameAsGiven("listen")) }`, nil},
		{"Env with an argument is another method", `func f(c C) string { return c.Env("x") }`, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := variableNamingsOf(t, "x.go", "package config\n"+tc.code, variables); !slices.Equal(got, tc.want) {
				t.Errorf("namings = %v, want %v", got, tc.want)
			}
		})
	}
}

// The allowlist lets a listed function call a Setting method that gives a variable, and nothing else:
// a string literal spelling a variable is reported even there, and so is a call in another function.
func TestTheNamingAllowlistAllowsOnlyAListedFunctionsSettingCalls(t *testing.T) {
	allowed := map[string]string{"registry.go:resolve": "reads the environment"}
	for _, tc := range []struct {
		name string
		file string
		n    variableNaming
		want bool
	}{
		{"a listed function's Setting call", "registry.go", variableNaming{"resolve", "Setting.Env"}, false},
		{"a listed function's string literal", "registry.go", variableNaming{"resolve", "BYWARD_LISTEN"}, true},
		{"another function's Setting call", "registry.go", variableNaming{"parse", "Setting.Env"}, true},
		{"the listed function's name in another file", "config.go", variableNaming{"resolve", "Setting.Env"}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := reported(allowed, tc.file, tc.n); got != tc.want {
				t.Errorf("reported = %v, want %v", got, tc.want)
			}
		})
	}
}
