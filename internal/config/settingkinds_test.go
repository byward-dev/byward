package config

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// A setting is read as a boolean exactly when the registry marks it Bool, and every boolean reads
// alike: one message for a value that is not true or false, and a bare --name that reads as true,
// as --dev does (without Bool, the flag package would want an argument). Driven by the registry, so
// a new setting is covered with no edit here, unless its read needs a companion setting to run
// (env below). A setting read as a boolean behind a condition without being Bool is
// TestEveryBooleanReadIsOfABoolFlag's.
func TestBooleanSettingsAreExactlyTheBoolFlags(t *testing.T) {
	// What a setting needs set beside it for its read to run; every read today runs on the default load.
	env := map[string][]string{}
	bools := 0
	for _, s := range registry {
		if s.Secret {
			continue // read from a file; never read as a boolean
		}
		if s.Bool {
			bools++
		}
		t.Run(s.Name, func(t *testing.T) {
			_, err := load(t, nil, append(env[s.Name], s.Env()+"=maybe")...)
			want := s.Env() + `: want true or false, got "maybe"`
			if read := err != nil && strings.Contains(err.Error(), want); read != s.Bool {
				t.Fatalf("read as a boolean %v, marked Bool %v (err %v); a read the default load does not reach needs its companion setting in env", read, s.Bool, err)
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
// Bool setting, and Values.boolean is the only reader (the package parses a boolean in one place): a
// read behind a condition (a stdio upstream, another IdP), or a second reader with its own message,
// would escape TestBooleanSettingsAreExactlyTheBoolFlags.
func TestEveryBooleanReadIsOfABoolFlag(t *testing.T) {
	byName := map[string]Setting{}
	for _, s := range registry {
		byName[s.Name] = s
	}
	read := regexp.MustCompile(`\.boolean\("([^"]+)"\)`)
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	reads, parses := 0, 0
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		src, err := os.ReadFile(f) //nolint:gosec // G304: reads this package's own files
		if err != nil {
			t.Fatal(err)
		}
		if n := strings.Count(string(src), "ParseBool"); n > 0 {
			parses += n
			if f != "registry.go" {
				t.Errorf("%s parses a boolean outside Values.boolean", f)
			}
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
	if parses != 1 {
		t.Errorf("the package parses a boolean in %d places, want 1 (Values.boolean)", parses)
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
		if s.Secret || !strings.HasSuffix(s.Name, "-dir") && !strings.HasSuffix(s.Name, "-file") {
			continue
		}
		paths++
		t.Run(s.Name, func(t *testing.T) {
			e, ok := env[s.Name]
			if !ok {
				e = append([]string{}, base...)
			}
			_, _, err := Load(nil, append(e, s.Env()+"=rel"), baseFiles)
			want := fmt.Sprintf("%s: want an absolute path (no paths relative to the working directory, ADR-0007 §6), got %q", s.Env(), "rel")
			if !isConfigError(err) || !strings.Contains(err.Error(), want) {
				t.Fatalf("err = %v, want %q", err, want)
			}
		})
	}
	if paths == 0 {
		t.Fatal("no path setting found")
	}
}
