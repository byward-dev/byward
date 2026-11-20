package config

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// A setting is read as a boolean exactly when the registry marks it Bool, and every boolean reads
// alike: one message for a value that is not true or false, and a bare --name that reads as true,
// as --dev does (without Bool, the flag package would want an argument). Driven by the registry, so
// a new setting is covered with no edit here, unless base does not reach its read (env below). A setting read as a boolean behind a condition without being Bool is
// TestEveryBooleanReadIsOfABoolFlag's.
func TestBooleanSettingsAreExactlyTheBoolFlags(t *testing.T) {
	// The whole environment a setting needs for its read to run, as in the path test below (base when
	// absent); every read today runs on base.
	env := map[string][]string{}
	bools := 0
	for _, s := range registry {
		if s.Secret() {
			continue // read from a file; never read as a boolean
		}
		if s.Bool {
			bools++
		}
		t.Run(s.Name, func(t *testing.T) {
			e, ok := env[s.Name]
			if !ok {
				e = append([]string{}, base...)
			}
			_, _, err := Load(nil, append(e, s.Env()+"=maybe"), baseFiles)
			want := s.Env() + ": want true or false; got a value (5 characters, not shown): it is neither true nor false"
			if read := err != nil && strings.Contains(err.Error(), want); read != s.Bool {
				hint := "mark it Bool"
				if s.Bool {
					hint = "its read gives another message, or base does not reach it (give it the environment that does in env)"
				}
				t.Fatalf("read as a boolean %v, marked Bool %v (err %v): %s", read, s.Bool, err, hint)
			}
			if !s.Bool {
				return
			}
			v, err := resolve(registry, []string{"--" + s.Name}, base, baseFiles, nil)
			if err != nil {
				t.Fatalf("a bare --%s is refused: %v", s.Name, err)
			}
			if b, err := v.boolean(s.Name); err != nil || !b {
				t.Fatalf("a bare --%s reads as %v (err %v), want true", s.Name, b, err)
			}
		})
	}
	if bools == 0 {
		t.Fatal("no boolean setting found")
	}
}

// Every boolean read in the package's code, whether or not the default load reaches it, is of a
// Bool setting: every read goes through Values.boolean, the one caller of parseBool, which is the one
// place the package parses a boolean. A read behind a condition (a stdio upstream, another IdP), a
// direct call of parseBool, a second parser with its own message, or a value compared with "true" by
// hand, would escape
// TestBooleanSettingsAreExactlyTheBoolFlags. The scan reads source text.
func TestEveryBooleanReadIsOfABoolFlag(t *testing.T) {
	byName := map[string]Setting{}
	for _, s := range registry {
		byName[s.Name] = s
	}
	read := regexp.MustCompile(`\.boolean\("([^"]+)"\)`)
	parse := regexp.MustCompile(`\bParseBool\(`)                                                      // a call as written, "ParseBool(": a bare mention passes
	parser, declared := regexp.MustCompile(`\bparseBool\(`), regexp.MustCompile(`\bfunc parseBool\(`) // its calls: every mention but its declaration
	// Any value compared with "true" or "false" by hand is a boolean read outside Values.boolean too.
	compare := regexp.MustCompile(`[!=]=\s*"(true|false)"|"(true|false)"\s*[!=]=`)
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	reads, parses, parserCalls := 0, 0, 0
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		src, err := os.ReadFile(f) //nolint:gosec // G304: reads this package's own files
		if err != nil {
			t.Fatal(err)
		}
		if n := len(parse.FindAllString(string(src), -1)); n > 0 {
			parses += n
			if f != "parsers.go" {
				t.Errorf("%s parses a boolean outside parsers.go, where parseBool lives", f)
			}
		}
		if n := len(parser.FindAllString(string(src), -1)) - len(declared.FindAllString(string(src), -1)); n > 0 {
			parserCalls += n
			if f != "registry.go" {
				t.Errorf("%s calls parseBool: read a boolean with Values.boolean, so this test sees its setting", f)
			}
		}
		if compare.MatchString(string(src)) {
			t.Errorf("%s compares a value with true or false by hand; read it with Values.boolean", f)
		}
		for _, m := range read.FindAllStringSubmatch(string(src), -1) {
			reads++
			if s, ok := byName[m[1]]; !ok || !s.Bool {
				t.Errorf("%s reads %s as a boolean, but the registry does not mark it Bool", f, m[1])
			}
		}
	}
	if reads == 0 {
		t.Fatal("no boolean read found: has Values.boolean been renamed?")
	}
	if parses != 1 || parserCalls != 1 {
		t.Errorf("the package parses a boolean in %d places and calls parseBool in %d, want 1 of each (parseBool, called by Values.boolean)", parses, parserCalls)
	}
}

// Every path setting (a non-secret setting named *-dir or *-file) refuses a path relative to the
// working directory, with one message (ADR-0007 §6). Driven by the registry, so a new path setting
// is covered with no edit here, unless it needs a companion setting to reach its check.
func TestEveryPathSettingRefusesARelativePath(t *testing.T) {
	// What each setting needs set beside it for its own check to run.
	env := map[string][]string{
		"tls-cert-file":              append(append([]string{}, base...), "BYWARD_TLS_KEY_FILE=/run/tls/tls.key"),
		"tls-key-file":               append(append([]string{}, base...), "BYWARD_TLS_CERT_FILE=/run/tls/tls.crt"),
		"entra-federated-token-file": withoutSecret(),
	}
	paths := 0
	for _, s := range registry {
		if s.Secret() || !strings.HasSuffix(s.Name, "-dir") && !strings.HasSuffix(s.Name, "-file") {
			continue
		}
		paths++
		t.Run(s.Name, func(t *testing.T) {
			e, ok := env[s.Name]
			if !ok {
				e = append([]string{}, base...)
			}
			_, _, err := Load(nil, append(e, s.Env()+"=rel"), baseFiles)
			want := s.Env() + ": want an absolute path; got a relative one: no path is relative to the working directory (ADR-0007 §6)"
			if !isConfigError(err) || !strings.Contains(err.Error(), want) {
				t.Fatalf("err = %v, want %q", err, want)
			}
		})
	}
	if paths == 0 {
		t.Fatal("no path setting found")
	}
}
