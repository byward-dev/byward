package config

import (
	"maps"
	"slices"
	"strings"
	"testing"
)

// stdioHints are the stdio hints as an operator reads them, NAME standing for the setting as given:
// each setting with a StdioHint must have one here, so its text is pinned as written.
var stdioHints = map[string]string{
	"upstream-credential": "NAME is for an HTTP upstream; give a stdio upstream its credential with BYWARD_UPSTREAM_ENV_FILE",
	"identity-headers":    "NAME is for an HTTP upstream; a stdio upstream gets the user in its environment (BYWARD_SUBJECT, docs/how-to/stdio-upstream.md)",
	"obo-header":          "NAME: a stdio upstream gets its downstream token from its token socket (BYWARD_DOWNSTREAM_TOKEN_SOCKET), not a header; leave NAME unset",
	"store-postgres-dsn":  "NAME: the PostgreSQL store is for several replicas, and a stdio upstream's processes live on one (ADR-0007 §4); use the SQLite store",
}

// pinnedHint is the pinned stdio hint of setting, naming it as given.
func pinnedHint(setting, given string) string {
	return strings.ReplaceAll(stdioHints[setting], "NAME", given)
}

// givenForms are the two ways to give s the value: its variable and its flag, or for a secret its file
// variable and its file flag, with that value as the file's path.
func givenForms(s Setting, value string) []fileForm {
	if s.Secret() {
		return secretFileForms(s, value)
	}
	return []fileForm{
		{"variable", s.Env(), nil, []string{s.Env() + "=" + value}},
		{"flag", "--" + s.Name, []string{"--" + s.Name + "=" + value}, nil},
	}
}

// failIfOpened is a readFile that serves base's files and fails t if path is opened.
func failIfOpened(t *testing.T, path string) readFileFunc {
	return func(p string) ([]byte, error) {
		if p == path {
			t.Errorf("read %s: a refused secret's file must not be opened", p)
		}
		return baseFiles(p)
	}
}

// Every setting with a StdioHint is refused beside a stdio upstream with its pinned hint alone, named
// as given, by its variable and by its flag: given a value its parser refuses, which is not parsed, or
// for a secret a missing file, which is never opened; and as a flag set to nothing (#596). Its
// variable set to nothing is unset (#428), so the proxy loads. The cases come from stdioHints, so a
// hint dropped from the registry fails as the wrong refusal; every setting with a StdioHint must be
// pinned there.
func TestEverySettingWithAStdioHintIsRefusedWithOnlyItsHintBesideStdio(t *testing.T) {
	const missing = "/run/secrets/missing"
	for _, s := range registry {
		if _, pinned := stdioHints[s.Name]; s.StdioHint != "" && !pinned {
			t.Errorf("%s: pin its StdioHint's text in stdioHints", s.Name)
		}
	}
	names := slices.Sorted(maps.Keys(stdioHints))
	if len(names) < 4 {
		t.Fatalf("%d stdio hints pinned, want at least the 4 of today", len(names))
	}
	for _, name := range names {
		s := lookup(name)
		bad := "not a value"
		if s.Secret() {
			bad = missing
		} else if _, _, err := Load(nil, append(slices.Clone(base), s.Env()+"="+bad), baseFiles); !isConfigError(err) {
			t.Errorf("%s=%s beside HTTP: err = %v, want its parser to refuse it, so the rows below show it is not parsed", s.Env(), bad, err)
		}
		for _, f := range append(givenForms(s, bad), givenForms(s, "")[1]) { // and the flag set to nothing
			t.Run(name+"/refused/"+strings.Join(append(f.args, f.env...), " "), func(t *testing.T) {
				_, _, err := Load(f.args, stdioBase(append([]string{stdioCommand}, f.env...)...), failIfOpened(t, missing))
				if want := pinnedHint(name, f.from); !isConfigError(err) || err.Error() != want {
					t.Errorf("err = %v, want a config error that is exactly %q", err, want)
				}
			})
		}
		unset := givenForms(s, "")[0] // the variable set to nothing
		t.Run(name+"/unset, loads/"+unset.env[0], func(t *testing.T) {
			if _, _, err := Load(nil, stdioBase(append([]string{stdioCommand}, unset.env...)...), baseFiles); err != nil {
				t.Errorf("err = %v, want it to load", err)
			}
		})
	}
}

// probeValues resolves a registry of the two upstream selectors and probe, with a stdio upstream.
func probeValues(t *testing.T, probe Setting, args, env []string, readFile readFileFunc) *Values {
	t.Helper()
	reg := []Setting{lookup("upstream-url"), lookup("upstream-command"), probe}
	v, err := resolve(reg, args, append([]string{stdioCommand}, env...), readFile, nil)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	return v
}

// A setting is refused beside a stdio upstream with its own hint once it has a StdioHint, with no
// other code: offModeSettings names it as given, a secret's file is never opened, and a parser written
// the usual way, through given, empty, value or emptySecretFile, sees it as not given, so adds no
// error of its own. The probes are in a registry of their own, so the global one is never changed.
func TestASettingGivenAStdioHintIsRefusedBesideStdioWithNoOtherCode(t *testing.T) {
	const missing = "/run/secrets/missing"
	plain := Setting{Name: "probe-setting", shape: asGivenShape, Group: GroupIdentity, StdioHint: "%[1]s: the probe's hint; leave %[1]s unset"}
	secret := Setting{Name: "probe-secret", shape: secretShape, Group: GroupKeysAndStore, StdioHint: "%[1]s is the probe secret's"}
	for _, tc := range []struct {
		name  string
		probe Setting
		args  []string
		env   []string
		want  string
	}{
		{"by its variable", plain, nil, []string{"BYWARD_PROBE_SETTING=x"}, "BYWARD_PROBE_SETTING: the probe's hint; leave BYWARD_PROBE_SETTING unset"},
		{"by its flag", plain, []string{"--probe-setting=x"}, nil, "--probe-setting: the probe's hint; leave --probe-setting unset"},
		{"a secret by its file variable", secret, nil, []string{"BYWARD_PROBE_SECRET_FILE=" + missing}, "BYWARD_PROBE_SECRET_FILE is the probe secret's"},
		{"a secret by its file flag", secret, []string{"--probe-secret-file=" + missing}, nil, "--probe-secret-file is the probe secret's"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			v := probeValues(t, tc.probe, tc.args, tc.env, failIfOpened(t, missing))
			var got []string
			for _, err := range offModeSettings(v) {
				got = append(got, err.Error())
			}
			if !slices.Equal(got, []string{tc.want}) {
				t.Errorf("offModeSettings = %q, want only %q", got, tc.want)
			}
			name := tc.probe.Name
			if v.given(name) || !v.empty(name) || v.value(name).Given.raw() != "" || v.emptySecretFile(name) != nil {
				t.Errorf("given %v, empty %v, value %q, emptySecretFile %v: want it read as not given", v.given(name), v.empty(name), v.value(name).Given.raw(), v.emptySecretFile(name))
			}
		})
	}
}

// A StdioHint is fixed text naming the setting with %[1]s and no other %, so it can never format a
// value; a stdio upstream's own setting, never refused beside stdio, takes none. Each breach stops
// the program at init, naming the setting.
func TestAStdioHintStopsTheProgramUnlessItIsFixedTextNamingASettingOutsideTheStdioGroup(t *testing.T) {
	const notFixed = "config: the stdio hint of probe must name it with %[1]s and have no other verb"
	setting := func(group Group, hint string) Setting {
		return Setting{Name: "probe", shape: asGivenShape, Group: group, StdioHint: hint}
	}
	for _, tc := range []struct {
		name  string
		s     Setting
		panic string // empty: none
	}{
		{"no hint is accepted", setting(GroupIdentity, ""), ""},
		{"a hint naming it once is accepted", setting(GroupIdentity, "%[1]s is for an HTTP upstream"), ""},
		{"a hint naming it twice is accepted", setting(GroupIdentity, "%[1]s: leave %[1]s unset"), ""},
		{"a hint on an HTTP upstream's setting is accepted", setting(GroupHTTPUpstream, "%[1]s is for an HTTP upstream"), ""},
		{"a hint not naming it stops the program", setting(GroupIdentity, "it is for an HTTP upstream"), notFixed},
		{"a plain verb stops the program", setting(GroupIdentity, "%s is for an HTTP upstream"), notFixed},
		{"another verb beside the name stops the program", setting(GroupIdentity, "%[1]s is set to %[2]q"), notFixed},
		{"a value verb beside the name stops the program", setting(GroupIdentity, "%[1]s is %v"), notFixed},
		{"a literal percent stops the program", setting(GroupIdentity, "%[1]s is 100%% for HTTP"), notFixed},
		{"a hint on a stdio upstream's setting stops the program", setting(GroupStdioUpstream, "%[1]s is for a stdio upstream"),
			"config: setting probe is a stdio upstream's, so it takes no stdio hint"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			defer func() {
				r := recover()
				if got, _ := r.(string); (r != nil) != (tc.panic != "") || r != nil && got != tc.panic {
					t.Errorf("checkStdioHints panicked with %#v, want %q (none when empty)", r, tc.panic)
				}
			}()
			checkStdioHints([]Setting{tc.s})
		})
	}
}

// A secret's file is opened once the upstream mode is known, a command after -- included, in registry
// order, and only for a secret that mode reads: a refused one's file is never opened, so a missing one
// gives the refusal, not a read error (#631). With no mode, or both upstreams set, every named file is
// opened, as before.
func TestASecretsFileIsOpenedOnlyWhenItsSettingIsNotRefused(t *testing.T) {
	const missing = "/run/secrets/missing"
	readErr := func(env, setting string) string {
		return env + ": want the path of a file holding the secret, such as /run/secrets/" + setting + "; got a value (20 characters, not shown): it cannot be read: file does not exist"
	}
	const postgresHint = "BYWARD_STORE_POSTGRES_DSN_FILE: the PostgreSQL store is for several replicas, and a stdio upstream's processes live on one (ADR-0007 §4); use the SQLite store"
	for _, tc := range []struct {
		name   string
		args   []string
		env    []string
		opened []string // the secret files opened besides base's
		want   string
	}{
		{"the PostgreSQL store's file beside stdio is not opened", nil, stdioBase(stdioCommand, "BYWARD_STORE_POSTGRES_DSN_FILE="+missing), nil, postgresHint},
		{"the PostgreSQL store's file beside a command after -- is not opened", []string{"--", "/usr/bin/server"}, stdioBase("BYWARD_STORE_POSTGRES_DSN_FILE=" + missing), nil, postgresHint},
		{"the credential's file beside stdio is not opened", nil, stdioBase(stdioCommand, "BYWARD_UPSTREAM_CREDENTIAL_FILE="+missing), nil,
			"BYWARD_UPSTREAM_CREDENTIAL_FILE is for an HTTP upstream; give a stdio upstream its credential with BYWARD_UPSTREAM_ENV_FILE"},
		{"the stdio env file beside HTTP is not opened", nil, append(slices.Clone(base), "BYWARD_UPSTREAM_ENV_FILE="+missing), nil,
			"BYWARD_UPSTREAM_ENV_FILE " + toStdio},
		{"the stdio env file beside stdio is opened", nil, stdioBase(stdioCommand, "BYWARD_UPSTREAM_ENV_FILE="+missing), []string{missing},
			readErr("BYWARD_UPSTREAM_ENV_FILE", "upstream-env")},
		{"beside stdio only the file not refused is opened", nil, stdioBase(stdioCommand, "BYWARD_UPSTREAM_CREDENTIAL_FILE=/run/secrets/refused", "BYWARD_UPSTREAM_ENV_FILE="+missing),
			[]string{missing}, readErr("BYWARD_UPSTREAM_ENV_FILE", "upstream-env")},
		{"the first unreadable file in registry order is the one named", nil,
			append(slices.Clone(base), "BYWARD_ENTRA_CLIENT_SECRET_FILE=/run/secrets/missing-too", "BYWARD_UPSTREAM_CREDENTIAL_FILE="+missing), []string{missing},
			readErr("BYWARD_UPSTREAM_CREDENTIAL_FILE", "upstream-credential")},
		{"with no upstream every file is opened", nil, stdioBase("BYWARD_STORE_POSTGRES_DSN_FILE=" + missing), []string{missing},
			readErr("BYWARD_STORE_POSTGRES_DSN_FILE", "store-postgres-dsn")},
		{"with both upstreams every file is opened", nil, append(slices.Clone(base), stdioCommand, "BYWARD_STORE_POSTGRES_DSN_FILE="+missing), []string{missing},
			readErr("BYWARD_STORE_POSTGRES_DSN_FILE", "store-postgres-dsn")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var opened []string
			_, _, err := Load(tc.args, tc.env, func(p string) ([]byte, error) {
				if strings.HasPrefix(p, "/run/secrets/") && p != "/run/secrets/entra" { // not base's, nor Load's container probes
					opened = append(opened, p)
				}
				return baseFiles(p)
			})
			if !isConfigError(err) || err.Error() != tc.want {
				t.Errorf("err = %v, want a config error that is exactly %q", err, tc.want)
			}
			if !slices.Equal(opened, tc.opened) {
				t.Errorf("opened %q, want %q", opened, tc.opened)
			}
		})
	}
}
