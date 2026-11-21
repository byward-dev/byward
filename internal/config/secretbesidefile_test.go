package config

import (
	"slices"
	"testing"
)

// fileForm is one way to give a secret's file: the _FILE variable or the --<name>-file flag.
type fileForm struct {
	how, from string // how names the form for any secret; from is this secret's, as errors name it
	args, env []string
}

// secretFileForms are the two ways to give s's file at path, each with nothing else set.
func secretFileForms(s Setting, path string) []fileForm {
	return []fileForm{
		{"_FILE", s.Env() + "_FILE", nil, []string{s.Env() + "_FILE=" + path}},
		{"--<name>-file", "--" + s.Name + "-file", []string{"--" + s.Name + "-file=" + path}, nil},
	}
}

// A secret given inline, not empty, beside its file is refused for every secret setting, whether the
// file comes from the _FILE variable or the --<name>-file flag (#590; before it, the file won in
// silence). The refusal names both settings and never shows the value, and comes before the file is
// read: the file is missing here, so a read first would report that instead.
func TestASecretGivenInlineBesideItsFileIsRefused(t *testing.T) {
	secrets := 0
	for _, s := range registry {
		if !s.Secret() {
			continue
		}
		secrets++
		for _, f := range secretFileForms(s, "/run/secrets/x") {
			t.Run(s.Env()+"=value beside "+f.from, func(t *testing.T) {
				_, err := resolve(registry, f.args, append(f.env, s.Env()+"="+canaryText), baseFiles, nil)
				want := s.Env() + " and " + f.from + " are both set; give one of them"
				if !isConfigError(err) || err.Error() != want || holdsCanary(err.Error()) {
					t.Fatalf("err = %v, want %q", err, want)
				}
			})
		}
	}
	if secrets == 0 {
		t.Fatal("the registry has no secret settings")
	}
}

// Development mode accepts an inline secret, never one beside its file, in either form: the pair is
// refused with --dev on or off. The base environment names the Entra client secret's file, which each
// form replaces.
func TestDevStillRefusesASecretGivenInlineBesideItsFile(t *testing.T) {
	s := lookup("entra-client-secret")
	others := without(s.Env() + "_FILE")(slices.Clone(base))
	for _, f := range secretFileForms(s, "/run/secrets/entra") {
		for _, dev := range []string{"BYWARD_DEV=false", "BYWARD_DEV=true"} {
			env := append(append(slices.Clone(others), f.env...), dev, s.Env()+"=pasted")
			_, _, err := Load(f.args, env, baseFiles)
			if want := s.Env() + " and " + f.from + " are both set; give one of them"; !isConfigError(err) || err.Error() != want {
				t.Errorf("%s, %s: err = %v, want %q", f.from, dev, err, want)
			}
		}
	}
}
