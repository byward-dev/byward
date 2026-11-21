package config

import (
	"reflect"
	"slices"
	"strings"
	"testing"
)

// emptyModes are the two upstream modes' smallest configurations, for the empty-value walks.
var emptyModes = []struct {
	name string
	env  []string
}{
	{"an HTTP upstream", base},
	{"a stdio upstream", stdioBase(`BYWARD_UPSTREAM_COMMAND=["/usr/bin/server"]`)},
}

// A variable set to nothing is the same as unset, for every setting in either mode (#428): env
// templates list every variable, often empty. A setting that gives empty a meaning of its own says so
// in EmptyMeans, and is pinned below.
func TestEverySettingSetToNothingLoadsAsIfUnset(t *testing.T) {
	for _, m := range emptyModes {
		want, _, err := Load(nil, m.env, baseFiles)
		if err != nil {
			t.Fatalf("%s: %v", m.name, err)
		}
		for _, s := range registry {
			if s.EmptyMeans != "" || slices.ContainsFunc(m.env, func(kv string) bool { return strings.HasPrefix(kv, s.Env()+"=") }) {
				continue
			}
			got, _, err := Load(nil, append(slices.Clone(m.env), s.Env()+"="), baseFiles)
			if err != nil {
				t.Errorf("%s, %s=: %v, want it loaded as if unset", m.name, s.Env(), err)
				continue
			}
			if !reflect.DeepEqual(got, want) {
				t.Errorf("%s, %s=: the configuration differs from the one without it", m.name, s.Env())
			}
		}
	}
}

// The settings that give empty a meaning of their own are exactly these: a new one is a decision,
// not an accident, so it fails here until it is added with its own test.
func TestOnlyTheInternalListenerGivesEmptyAMeaningOfItsOwn(t *testing.T) {
	var got []string
	for _, s := range registry {
		if s.EmptyMeans != "" {
			got = append(got, s.Name+"="+s.EmptyMeans)
		}
	}
	if want := []string{"internal-listen=off"}; !slices.Equal(got, want) {
		t.Fatalf("settings giving empty a meaning = %v, want %v", got, want)
	}
	c, err := load(t, nil, "BYWARD_INTERNAL_LISTEN=")
	if err != nil || c.InternalListen != "" {
		t.Fatalf("BYWARD_INTERNAL_LISTEN=: listen %q, err %v; want it off", c.InternalListen, err)
	}
}

// A secret's variable set to nothing beside its _FILE variable is unset, so the secret is read from
// the file and is no inline secret.
func TestASecretSetToNothingBesideItsFileIsReadFromTheFile(t *testing.T) {
	read := func(string) ([]byte, error) { return []byte("from-the-file"), nil }
	for _, s := range registry {
		if !s.Secret() {
			continue
		}
		v, err := resolve(registry, nil, []string{s.Env() + "=", s.Env() + "_FILE=/run/secrets/x"}, read, nil)
		if err != nil {
			t.Errorf("%s= with %s_FILE: %v", s.Env(), s.Env(), err)
			continue
		}
		if val := v.value(s.Name); val.Source != SourceFile || val.Given.raw() != "from-the-file" {
			t.Errorf("%s= with %s_FILE: source %s, want the file", s.Env(), s.Env(), val.Source)
		}
		if _, err := checkInlineSecrets(v, false); err != nil {
			t.Errorf("%s= with %s_FILE: %v, want no inline secret", s.Env(), s.Env(), err)
		}
	}
}
