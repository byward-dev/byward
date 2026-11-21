package config

import (
	"os"
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
	{"an oidc IdP", oidcBase, oidcSecretFiles},
}

// oidcSecretFiles serves oidcBase's secret and nothing from the host.
func oidcSecretFiles(p string) ([]byte, error) {
	if p == "/run/secrets/oidc" {
		return oidcFiles(p)
	}
	return nil, os.ErrNotExist
}

// loadsAlike fails t unless the two loads end the same way: the same error, or equal configurations.
func loadsAlike(t *testing.T, what string, got, want *Config, gotErr, wantErr error) {
	t.Helper()
	if errText(gotErr) != errText(wantErr) {
		t.Errorf("%s: err %v, want %v", what, gotErr, wantErr)
		return
	}
	if got == nil || want == nil {
		return // both refused alike
	}
	diff := configDiff(*got, *want)
	for _, f := range diff {
		t.Errorf("%s: Config.%s", what, f)
	}
	if len(diff) == 0 && !reflect.DeepEqual(*got, *want) { // a backstop, so a broken configDiff cannot hide a difference
		t.Errorf("%s: the configuration differs, though configDiff names no field", what)
	}
}

func errText(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

// A variable set to nothing is the same as unset, for every setting in each mode (#428): env
// templates list every variable, often empty. A setting the mode needs is still required. The
// internal listener, where empty turns it off, is the one exception, pinned below; the walk names it
// rather than reading EmptyIsGiven, so a setting given that field by mistake fails here.
func TestEverySettingSetToNothingLoadsAsIfUnset(t *testing.T) {
	for _, m := range emptyModes {
		if _, _, err := Load(nil, m.env, m.files); err != nil {
			t.Fatalf("%s: %v", m.name, err)
		}
		for _, s := range registry {
			if s.Name == "internal-listen" {
				continue
			}
			unset := without(s.Env())(slices.Clone(m.env))
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
}

// The internal listener set to nothing is off.
func TestTheInternalListenerSetToNothingIsOff(t *testing.T) {
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
// the secret is read from the file, and is no inline secret (which the _FILE variable alone never is).
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
			fileOnly := append(without(s.Env(), s.Env()+"_FILE")(slices.Clone(m.env)), s.Env()+"_FILE="+path)
			want, _, wantErr := Load(nil, fileOnly, files)
			got, _, gotErr := Load(nil, append(slices.Clone(fileOnly), s.Env()+"="), files)
			loadsAlike(t, m.name+", "+s.Env()+"= with "+s.Env()+"_FILE", got, want, gotErr, wantErr)
			if gotErr == nil {
				loaded++
			}
		}
	}
	if loaded == 0 {
		t.Fatal("no secret loaded from its file in any mode, so the walk compared only errors")
	}
}

// A flag set to nothing on the command line is deliberate, so it is refused as given, unlike a
// variable set to nothing (#428). An empty claims flag never quietly means none: that would change
// what the upstream is told.
func TestAFlagSetToNothingIsRefusedAsGiven(t *testing.T) {
	for _, tc := range []struct{ flag, want string }{
		{"--listen=", "BYWARD_LISTEN: want host:port such as 127.0.0.1:8080; got nothing"},
		{"--scope=", "BYWARD_SCOPE: want one scope token, such as mcp; got nothing"},
		{"--data-dir=", "BYWARD_DATA_DIR: want an absolute path; got nothing"},
		{"--assertion-claims=", "BYWARD_ASSERTION_CLAIMS: want claims from roles, groups, email or name, or none; got nothing"},
	} {
		if _, err := load(t, []string{tc.flag}); !isConfigError(err) || err.Error() != tc.want {
			t.Errorf("%s: %v, want the error %q", tc.flag, err, tc.want)
		}
	}
}
