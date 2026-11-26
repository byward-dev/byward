package config

import (
	"slices"
	"strings"
	"testing"
)

// emptyModes are the smallest configurations of each upstream mode and IdP family, and of no
// authentication, for the empty-value walks.
var emptyModes = []struct {
	name  string
	env   []string
	files readFileFunc
}{
	{"an HTTP upstream", base, baseFiles},
	{"a stdio upstream", stdioBase(stdioCommand), baseFiles},
	{"an oidc IdP", oidcBase, filesPlusEmptyAndBlank},
	{"no authentication", anon, filesPlusEmptyAndBlank},
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

// A secret's variable set to nothing beside its file, the _FILE variable or the --<name>-file flag,
// loads as the file alone: the secret is read from the file, and is no inline secret. It keeps an
// empty variable harmless now that an inline secret beside its file is refused (#590).
func TestASecretSetToNothingBesideItsFileLoadsAsTheFileAlone(t *testing.T) {
	const path = "/run/secrets/the-file"
	loaded := map[string]int{} // by how the file is given
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
			unset := without(s.Env(), s.Env()+"_FILE")(slices.Clone(m.env))
			for _, f := range secretFileForms(s, path) {
				env := append(slices.Clone(unset), f.env...)
				want, _, wantErr := Load(f.args, env, files)
				got, _, gotErr := Load(f.args, append(slices.Clone(env), s.Env()+"="), files)
				loadsAlike(t, m.name+", "+s.Env()+"= beside "+f.from, got, want, gotErr, wantErr)
				if gotErr == nil {
					loaded[f.how]++
				}
			}
		}
	}
	for _, f := range secretFileForms(Setting{}, "") {
		if loaded[f.how] == 0 {
			t.Errorf("no secret loaded from a file given as %s in any mode, so those rows compared only errors", f.how)
		}
	}
}

// A flag set to nothing on the command line is deliberate, so it is refused as given, unlike a
// variable set to nothing (#428), and its refusal names the flag (#623). An empty claims flag never
// quietly means none: that would change what the upstream is told. An empty credential header flag
// is given too, so with no credential it is refused as a header with nothing to send. (A flag set to
// nothing for a family that is off is refused by that family's check:
// TestEveryOffCheckRefusesAFlagSetToNothingAndTakesAVariableSetToNothingAsUnset.)
func TestAFlagSetToNothingIsRefusedAsGiven(t *testing.T) {
	for _, tc := range []struct{ flag, want string }{
		{"--listen=", "--listen: want host:port such as 127.0.0.1:8080; got nothing"},
		{"--scope=", "--scope: want one scope token, such as mcp; got nothing"},
		{"--data-dir=", "--data-dir: want an absolute path, one starting with /; got nothing"},
		{"--store-postgres-dsn-file=", "--store-postgres-dsn-file: want the path of a file holding the secret, such as /run/secrets/store-postgres-dsn; got nothing"},
		// The flag wins over BYWARD_ENTRA_CLIENT_SECRET_FILE, which base sets, and is still refused.
		{"--entra-client-secret-file=", "--entra-client-secret-file: want the path of a file holding the secret, such as /run/secrets/entra-client-secret; got nothing"},
		{"--assertion-claims=", "--assertion-claims: want claims from roles, groups, email or name, or none; got nothing"},
		{"--assertion-header=", "--assertion-header: want a header name such as Authorization or X-Byward-Identity; got nothing"},
		{"--upstream-credential-header=", "--upstream-credential-header is set, but there is no credential: set BYWARD_UPSTREAM_CREDENTIAL_FILE too, or remove it"},
	} {
		if _, err := load(t, []string{tc.flag}); !isConfigError(err) || err.Error() != tc.want {
			t.Errorf("%s: %v, want the error %q", tc.flag, err, tc.want)
		}
	}
}

// Every check that refuses a family's settings while the family is off refuses one given as a flag
// set to nothing, which is deliberate, and takes one set to nothing as a variable as unset, as env
// templates list every variable (#428, #596). A setting of each check (both of the SQLite store's
// beside PostgreSQL, which it checks apart); the upstream mode's check is walked over every setting in
// TestEverySettingOfAnUpstreamGroupIsRefusedWithTheOtherMode and
// TestEverySettingWithAStdioHintIsRefusedWithOnlyItsHintBesideStdio.
func TestEveryOffCheckRefusesAFlagSetToNothingAndTakesAVariableSetToNothingAsUnset(t *testing.T) {
	stdio := stdioBase(stdioCommand)
	postgres := append(slices.Clone(base), "BYWARD_STORE_POSTGRES_DSN_FILE="+dsnFile)
	for _, tc := range []struct {
		check, setting string
		env            []string
		want           string
	}{
		{"the other IdP family", "oidc-scopes", base, "--oidc-scopes cannot be used with BYWARD_IDP=entra"},
		{"app tokens off", "app-roles", base, "--app-roles set while BYWARD_APP_TOKENS=off"},
		{"On-Behalf-Of's header beside a stdio upstream", "obo-header", stdio, "--obo-header: a stdio upstream gets its downstream token from its token socket"},
		{"the plain identity headers beside a stdio upstream", "identity-headers", stdio, "--identity-headers is for an HTTP upstream; a stdio upstream gets the user in its environment"},
		{"the SQLite store beside PostgreSQL", "store-dir", postgres, "give one store, PostgreSQL or a SQLite state directory, not both"},
		{"the SQLite counter file beside PostgreSQL", "store-counter-file", postgres, "--store-counter-file: the counter file belongs to the SQLite store"},
		{"authentication beside --insecure-no-auth", "gate-roles", anon, "BYWARD_INSECURE_NO_AUTH cannot be combined with --gate-roles"},
		{"a stdio setting beside an HTTP upstream", "stdio-max-processes", base, "--stdio-max-processes is set, but the upstream is HTTP: it applies only to a stdio upstream"},
	} {
		t.Run(tc.check, func(t *testing.T) {
			if _, _, err := Load([]string{"--" + tc.setting + "="}, tc.env, filesPlusEmptyAndBlank); !isConfigError(err) || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("--%s=: %v, want an error containing %q", tc.setting, err, tc.want)
			}
			env := Setting{Name: tc.setting}.Env() + "="
			if _, _, err := Load(nil, append(slices.Clone(tc.env), env), filesPlusEmptyAndBlank); err != nil {
				t.Errorf("%s: %v, want it unset", env, err)
			}
		})
	}
}
