package config

import (
	"fmt"
	"strings"
	"testing"
)

// A setting is read as a boolean exactly when the registry marks it Bool, and every boolean reads
// alike: one message for a value that is not true or false, and a bare --name meaning true, as
// --dev does (without Bool, the flag package would want an argument). Driven by the registry, so a
// new setting is covered with no edit here.
func TestBooleanSettingsAreExactlyTheBoolFlags(t *testing.T) {
	bools := 0
	for _, s := range registry {
		if s.Secret {
			continue // read from a file; never a boolean
		}
		t.Run(s.Name, func(t *testing.T) {
			_, err := load(t, nil, s.Env()+"=maybe")
			want := s.Env() + `: want true or false, got "maybe"`
			if read := err != nil && strings.Contains(err.Error(), want); read != s.Bool {
				t.Fatalf("read as a boolean %v, marked Bool %v (err %v)", read, s.Bool, err)
			}
			if !s.Bool {
				return
			}
			bools++
			if _, err := load(t, []string{"--" + s.Name}); err != nil && strings.Contains(err.Error(), "needs an argument") {
				t.Fatalf("a bare --%s is refused: %v", s.Name, err)
			}
		})
	}
	if bools == 0 {
		t.Fatal("no boolean setting found")
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
