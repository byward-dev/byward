package config

import (
	"fmt"
	"os"
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

// Every setting with a StdioHint is refused beside a stdio upstream with that hint alone, named as
// given, by its variable and by its flag: given a value it could not take, which is not parsed, or for
// a secret a missing file, which is never opened; and as a flag set to nothing (#596). Its variable set
// to nothing is unset (#428), so the proxy loads. The settings are read from the registry, so a new
// one is covered once its text is in stdioHints.
func TestEverySettingWithAStdioHintIsRefusedWithItBesideStdio(t *testing.T) {
	const missing = "/run/secrets/missing"
	files := func(p string) ([]byte, error) {
		if p == missing {
			t.Errorf("read %s: a refused secret's file must not be opened", p)
		}
		return baseFiles(p)
	}
	n := 0
	for _, s := range registry {
		text, pinned := stdioHints[s.Name]
		switch {
		case s.StdioHint == "" && pinned:
			t.Errorf("%s: it has no StdioHint, so take it out of stdioHints", s.Name)
			continue
		case s.StdioHint == "":
			continue
		case !pinned:
			t.Errorf("%s: pin its StdioHint's text in stdioHints", s.Name)
			continue
		}
		n++
		bad := "not a value"
		if s.Secret() {
			bad = missing
		}
		refused := append(givenForms(s, bad), givenForms(s, "")[1]) // and the flag set to nothing
		for _, f := range refused {
			t.Run(s.Name+"/"+strings.Join(append(f.args, f.env...), " "), func(t *testing.T) {
				_, _, err := Load(f.args, stdioBase(append([]string{stdioCommand}, f.env...)...), files)
				if want := strings.ReplaceAll(text, "NAME", f.from); !isConfigError(err) || err.Error() != want {
					t.Errorf("err = %v, want a config error that is exactly %q", err, want)
				}
			})
		}
		unset := givenForms(s, "")[0] // the variable set to nothing
		t.Run(s.Name+"/"+unset.env[0], func(t *testing.T) {
			if _, _, err := Load(nil, stdioBase(append([]string{stdioCommand}, unset.env...)...), files); err != nil {
				t.Errorf("err = %v, want it to load", err)
			}
		})
	}
	if n < len(stdioHints) {
		t.Fatalf("%d settings with a StdioHint checked, want the %d of stdioHints", n, len(stdioHints))
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
// other code: offModeSettings names it as given, and a secret's file is never opened. The probes are
// in a registry of their own, so the global one is never changed.
func TestASettingGivenAStdioHintIsRefusedBesideStdioWithNoOtherCode(t *testing.T) {
	noRead := func(p string) ([]byte, error) {
		t.Errorf("read %s: a refused secret's file must not be opened", p)
		return nil, os.ErrNotExist
	}
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
		{"a secret by its file variable", secret, nil, []string{"BYWARD_PROBE_SECRET_FILE=/run/secrets/missing"}, "BYWARD_PROBE_SECRET_FILE is the probe secret's"},
		{"a secret by its file flag", secret, []string{"--probe-secret-file=/run/secrets/missing"}, nil, "--probe-secret-file is the probe secret's"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var got []string
			for _, err := range offModeSettings(probeValues(t, tc.probe, tc.args, tc.env, noRead)) {
				got = append(got, err.Error())
			}
			if !slices.Equal(got, []string{tc.want}) {
				t.Errorf("offModeSettings = %q, want only %q", got, tc.want)
			}
		})
	}
}

// A StdioHint is fixed text naming the setting with %[1]s and no other %, so it can never format a
// value; a stdio upstream's own setting, never refused beside stdio, takes none. Each breach stops
// the program at init.
func TestAStdioHintThatCouldShowAValueNamesNothingOrIsOnAStdioSettingStopsTheProgram(t *testing.T) {
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
		{"a hint not naming it", setting(GroupIdentity, "it is for an HTTP upstream"), "must name it with %[1]s"},
		{"a plain verb", setting(GroupIdentity, "%s is for an HTTP upstream"), "must name it with %[1]s"},
		{"another verb beside the name", setting(GroupIdentity, "%[1]s is set to %[2]q"), "must name it with %[1]s"},
		{"a value verb beside the name", setting(GroupIdentity, "%[1]s is %v"), "must name it with %[1]s"},
		{"a literal percent", setting(GroupIdentity, "%[1]s is 100%% for HTTP"), "must name it with %[1]s"},
		{"a hint on a stdio upstream's setting", setting(GroupStdioUpstream, "%[1]s is for a stdio upstream"), "takes no stdio hint"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			defer func() {
				r := recover()
				got := ""
				if r != nil {
					got = fmt.Sprint(r)
				}
				if (r != nil) != (tc.panic != "") || !strings.Contains(got, tc.panic) {
					t.Errorf("checkStdioHints panicked with %v, want a panic containing %q (none when empty)", r, tc.panic)
				}
			}()
			checkStdioHints([]Setting{tc.s})
		})
	}
}

// A secret's file is opened once the upstream mode is known, a command after -- included, and only
// for a secret that mode reads: a refused one's file is never opened, so a missing one gives the
// refusal, not a read error (#631). With no mode, or both upstreams set, every named file is opened,
// as before.
func TestASecretsFileIsOpenedOnlyWhenItsSettingIsNotRefused(t *testing.T) {
	const notFound = ": want the path of a file holding the secret, such as /run/secrets/"
	const missing = "/run/secrets/missing"
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
			"BYWARD_UPSTREAM_ENV_FILE is set, but the upstream is HTTP: it applies only to a stdio upstream (BYWARD_UPSTREAM_COMMAND); remove it"},
		{"the stdio env file beside stdio is opened", nil, stdioBase(stdioCommand, "BYWARD_UPSTREAM_ENV_FILE="+missing), []string{missing},
			"BYWARD_UPSTREAM_ENV_FILE" + notFound + "upstream-env; got a value (20 characters, not shown): it cannot be read: file does not exist"},
		{"beside stdio only the file not refused is opened", nil, stdioBase(stdioCommand, "BYWARD_STORE_POSTGRES_DSN_FILE=/run/secrets/refused", "BYWARD_UPSTREAM_ENV_FILE="+missing),
			[]string{missing}, "BYWARD_UPSTREAM_ENV_FILE" + notFound + "upstream-env; got a value (20 characters, not shown): it cannot be read: file does not exist"},
		{"with no upstream every file is opened", nil, stdioBase("BYWARD_STORE_POSTGRES_DSN_FILE=" + missing), []string{missing},
			"BYWARD_STORE_POSTGRES_DSN_FILE" + notFound + "store-postgres-dsn; got a value (20 characters, not shown): it cannot be read: file does not exist"},
		{"with both upstreams every file is opened", nil, append(slices.Clone(base), stdioCommand, "BYWARD_STORE_POSTGRES_DSN_FILE="+missing), []string{missing},
			"BYWARD_STORE_POSTGRES_DSN_FILE" + notFound + "store-postgres-dsn; got a value (20 characters, not shown): it cannot be read: file does not exist"},
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

// Without authentication, a setting refused for the upstream mode that is off is refused once, as off:
// "remove it" is its one error, with no "cannot be combined" error beside it (#631). A setting the
// mode reads is still refused beside --insecure-no-auth.
func TestARefusedSettingBesideNoAuthIsRefusedOnlyForTheModeThatIsOff(t *testing.T) {
	noAuthStdio := func(extra ...string) []string {
		return noAuthEnv(append([]string{"BYWARD_UPSTREAM_URL=", stdioCommand}, extra...)...)
	}
	for _, tc := range []struct {
		name string
		env  []string
		want string
	}{
		{"a hinted setting beside stdio gets only its hint", noAuthStdio("BYWARD_IDENTITY_HEADERS=true"),
			"BYWARD_IDENTITY_HEADERS is for an HTTP upstream; a stdio upstream gets the user in its environment (BYWARD_SUBJECT, docs/how-to/stdio-upstream.md)"},
		{"an HTTP-only setting beside stdio gets only the off-mode refusal", noAuthStdio("BYWARD_ASSERTION_HEADER=X-Byward-Identity"),
			"BYWARD_ASSERTION_HEADER is set, but the upstream is stdio: it applies only to an HTTP upstream (BYWARD_UPSTREAM_URL); remove it"},
		{"the same setting beside HTTP is refused for no-auth", noAuthEnv("BYWARD_IDENTITY_HEADERS=true"),
			"BYWARD_INSECURE_NO_AUTH cannot be combined with BYWARD_IDENTITY_HEADERS: remove one of them"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, _, err := Load(nil, tc.env, nil); !isConfigError(err) || err.Error() != tc.want {
				t.Errorf("err = %v, want a config error that is exactly %q", err, tc.want)
			}
		})
	}
}
