package config

import (
	"errors"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"testing"
)

// emptyModes are the smallest configurations of each upstream mode and IdP family, for the
// empty-value walks.
var emptyModes = []struct {
	name  string
	env   []string
	files readFileFunc
}{
	{"an HTTP upstream", base, baseFiles},
	{"a stdio upstream", stdioBase(`BYWARD_UPSTREAM_COMMAND=["/usr/bin/server"]`), baseFiles},
	{"an oidc IdP", oidcBase, oidcFiles},
}

// loadsAlike fails t unless the two loads end the same way: the same error, or equal configurations.
func loadsAlike(t *testing.T, what string, got, want *Config, gotErr, wantErr error) {
	t.Helper()
	if errText(gotErr) != errText(wantErr) {
		t.Errorf("%s: err %v, want %v", what, gotErr, wantErr)
		return
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("%s: the configuration differs in %v", what, fieldsThatDiffer(got, want))
	}
}

func errText(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

// fieldsThatDiffer names the Config fields where a and b differ.
func fieldsThatDiffer(a, b *Config) []string {
	if a == nil || b == nil {
		return []string{fmt.Sprintf("one is nil (%v, %v)", a == nil, b == nil)}
	}
	va, vb := reflect.ValueOf(*a), reflect.ValueOf(*b)
	var out []string
	for i := range va.NumField() {
		if !reflect.DeepEqual(va.Field(i).Interface(), vb.Field(i).Interface()) {
			out = append(out, va.Type().Field(i).Name)
		}
	}
	return out
}

// withoutVar drops env's entries for the variable name.
func withoutVar(env []string, name string) []string {
	return slices.DeleteFunc(slices.Clone(env), func(kv string) bool { return strings.HasPrefix(kv, name+"=") })
}

// A variable set to nothing is the same as unset, for every setting in each mode (#428): env
// templates list every variable, often empty. A setting the mode needs is still required. A
// setting that keeps empty as given says so in EmptyIsGiven, and is pinned below.
func TestEverySettingSetToNothingLoadsAsIfUnset(t *testing.T) {
	for _, m := range emptyModes {
		if _, _, err := Load(nil, m.env, m.files); err != nil {
			t.Fatalf("%s: %v", m.name, err)
		}
		for _, s := range registry {
			if s.EmptyIsGiven {
				continue
			}
			unset := withoutVar(m.env, s.Env())
			want, _, wantErr := Load(nil, unset, m.files)
			got, _, gotErr := Load(nil, append(slices.Clone(unset), s.Env()+"="), m.files)
			loadsAlike(t, m.name+", "+s.Env()+"=", got, want, gotErr, wantErr)
		}
	}
}

// The settings that keep empty as given are exactly these: a new one is a decision, not an
// accident, so it fails here until it is added with its own test.
func TestOnlyTheInternalListenerKeepsEmptyAsGiven(t *testing.T) {
	var got []string
	for _, s := range registry {
		if s.EmptyIsGiven {
			got = append(got, s.Name)
		}
	}
	if want := []string{"internal-listen"}; !slices.Equal(got, want) {
		t.Fatalf("settings keeping empty as given = %v, want %v", got, want)
	}
	c, err := load(t, nil, "BYWARD_INTERNAL_LISTEN=")
	if err != nil {
		t.Fatalf("BYWARD_INTERNAL_LISTEN=: %v, want the internal listener off", err)
	}
	if c.InternalListen != "" {
		t.Errorf("BYWARD_INTERNAL_LISTEN=: listen %q, want it off", c.InternalListen)
	}
}

// resolve reads EmptyIsGiven from the setting it resolves, whatever the setting's name.
func TestResolveKeepsEmptyAsGivenOnlyForASettingThatSaysSo(t *testing.T) {
	reg := []Setting{
		{Name: "kept", shape: asGivenShape, Default: "d", EmptyIsGiven: true},
		{Name: "dropped", shape: asGivenShape, Default: "d"},
	}
	v, err := resolve(reg, nil, []string{"BYWARD_KEPT=", "BYWARD_DROPPED="}, baseFiles, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name   string
		source Source
		value  string
	}{
		{"kept", SourceEnv, ""},
		{"dropped", SourceDefault, "d"},
	} {
		if val := v.value(tc.name); val.Source != tc.source || val.Given.raw() != tc.value {
			t.Errorf("BYWARD_%s=: source %s, value %q; want %s, %q", strings.ToUpper(tc.name), val.Source, val.Given.raw(), tc.source, tc.value)
		}
	}
}

// A secret's variable set to nothing beside its _FILE variable loads as the _FILE variable alone:
// the secret is read from the file, and is no inline secret.
func TestASecretSetToNothingBesideItsFileLoadsAsTheFileAlone(t *testing.T) {
	const path = "/run/secrets/the-file"
	loaded := 0
	for _, m := range emptyModes {
		files := func(p string) ([]byte, error) {
			if p == path {
				return []byte("from-the-file\n"), nil
			}
			return m.files(p)
		}
		for _, s := range registry {
			if !s.Secret() {
				continue
			}
			fileOnly := append(withoutVar(withoutVar(m.env, s.Env()), s.Env()+"_FILE"), s.Env()+"_FILE="+path)
			want, _, wantErr := Load(nil, fileOnly, files)
			got, _, gotErr := Load(nil, append(slices.Clone(fileOnly), s.Env()+"="), files)
			loadsAlike(t, m.name+", "+s.Env()+"= with "+s.Env()+"_FILE", got, want, gotErr, wantErr)
			var ce *configError
			if gotErr != nil && errors.As(gotErr, &ce) && strings.Contains(gotErr.Error(), "secrets must come from a file") {
				t.Errorf("%s, %s= with %s_FILE: %v, want no inline secret", m.name, s.Env(), s.Env(), gotErr)
			}
			if gotErr == nil {
				loaded++
			}
		}
	}
	if loaded == 0 {
		t.Fatal("no secret loaded from its file in any mode, so the walk compared only errors")
	}
}
