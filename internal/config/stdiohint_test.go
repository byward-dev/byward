package config

import (
	"fmt"
	"os"
	"slices"
	"strings"
	"testing"
)

// Every setting with a StdioHint is refused beside a stdio upstream with that hint alone, named as
// given, by its variable and by its flag. The settings are read from the registry, so a new one is
// covered with no row to add; TestASettingForTheUpstreamModeThatIsOffIsRefused pins each hint's text.
func TestEverySettingWithAStdioHintIsRefusedWithItBesideStdio(t *testing.T) {
	files := func(p string) ([]byte, error) {
		if p == "/run/secrets/hinted" {
			return []byte("x"), nil
		}
		return baseFiles(p)
	}
	n := 0
	for _, s := range registry {
		if s.StdioHint == "" {
			continue
		}
		n++
		env, flag := s.Env()+"=x", "--"+s.Name+"=x"
		envName, flagName := s.Env(), "--"+s.Name
		if s.Secret() {
			env, flag = s.FileEnv()+"=/run/secrets/hinted", "--"+s.FileFlag()+"=/run/secrets/hinted"
			envName, flagName = s.FileEnv(), "--"+s.FileFlag()
		}
		for _, tc := range []struct {
			args []string
			env  []string
			name string
		}{{nil, stdioBase(stdioCommand, env), envName}, {[]string{flag}, stdioBase(stdioCommand), flagName}} {
			_, _, err := Load(tc.args, tc.env, files)
			if want := fmt.Sprintf(s.StdioHint, tc.name); !isConfigError(err) || err.Error() != want {
				t.Errorf("%s given as %s: err = %v, want a config error that is exactly %q", s.Name, tc.name, err, want)
			}
		}
	}
	if n < 4 {
		t.Fatalf("%d settings with a StdioHint, want at least the 4 of today", n)
	}
}

// probeValues resolves a registry of the two upstream selectors and probe, from env, with a stdio
// upstream; readFile must not be reached for a refused secret.
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
// other code: its parser reads only its default, and a secret's file is never opened.
func TestASettingGivenAStdioHintIsRefusedBesideStdioWithNoOtherCode(t *testing.T) {
	noRead := func(p string) ([]byte, error) {
		t.Errorf("read %s: a refused secret's file must not be opened", p)
		return nil, os.ErrNotExist
	}
	plain := Setting{Name: "probe-setting", shape: asGivenShape, Group: GroupIdentity, Default: "the default", StdioHint: "%[1]s: the probe's hint; leave %[1]s unset"}
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
			v := probeValues(t, tc.probe, tc.args, tc.env, noRead)
			var got []string
			for _, err := range offModeSettings(v, true) {
				got = append(got, err.Error())
			}
			if !slices.Equal(got, []string{tc.want}) {
				t.Errorf("offModeSettings = %q, want only %q", got, tc.want)
			}
			if val := v.value(tc.probe.Name); val.Source != SourceDefault || val.Given.raw() != tc.probe.Default {
				t.Errorf("value = %+v, want the default %q: a refused setting is not parsed", val, tc.probe.Default)
			}
		})
	}
}

// A StdioHint is fixed text naming the setting with %[1]s and no other verb, so it can never format a
// value; a stdio upstream's own setting, never refused beside stdio, takes none. Each breach stops
// the program at init.
func TestAStdioHintThatCouldShowAValueOrNamesNothingStopsTheProgram(t *testing.T) {
	setting := func(group Group, hint string) Setting {
		return Setting{Name: "probe", shape: asGivenShape, Group: group, StdioHint: hint}
	}
	for _, tc := range []struct {
		name  string
		s     Setting
		panic string
	}{
		{"no hint", setting(GroupIdentity, ""), ""},
		{"named once", setting(GroupIdentity, "%[1]s is for an HTTP upstream"), ""},
		{"named twice", setting(GroupIdentity, "%[1]s: leave %[1]s unset"), ""},
		{"an HTTP upstream's setting", setting(GroupHTTPUpstream, "%[1]s is for an HTTP upstream"), ""},
		{"not named", setting(GroupIdentity, "it is for an HTTP upstream"), "must name it with %[1]s"},
		{"a plain verb", setting(GroupIdentity, "%s is for an HTTP upstream"), "must name it with %[1]s"},
		{"another verb beside the name", setting(GroupIdentity, "%[1]s is set to %[2]q"), "must name it with %[1]s"},
		{"a value verb beside the name", setting(GroupIdentity, "%[1]s is %v"), "must name it with %[1]s"},
		{"a literal percent", setting(GroupIdentity, "%[1]s is 100%% for HTTP"), "must name it with %[1]s"},
		{"a stdio upstream's setting", setting(GroupStdioUpstream, "%[1]s is for a stdio upstream"), "takes no stdio hint"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			defer func() {
				got, _ := recover().(string)
				if (tc.panic == "") != (got == "") || !strings.Contains(got, tc.panic) {
					t.Errorf("checkStdioHints panicked with %q, want a panic containing %q (none when empty)", got, tc.panic)
				}
			}()
			checkStdioHints([]Setting{tc.s})
		})
	}
}

// A secret's file is opened once the upstream mode is known, and only for a secret that mode reads: a
// refused one's file is never opened, so a missing one gives the refusal, not a read error (#631).
// With no mode, or both upstreams set, every named file is opened, as before.
func TestARefusedSecretsFileIsNeverOpened(t *testing.T) {
	const notFound = ": want the path of a file holding the secret, such as /run/secrets/"
	const missing = "/run/secrets/missing"
	for _, tc := range []struct {
		name   string
		env    []string
		opened []string // the secret files opened besides base's
		want   string
	}{
		{"the PostgreSQL store beside stdio", stdioBase(stdioCommand, "BYWARD_STORE_POSTGRES_DSN_FILE="+missing), nil,
			"BYWARD_STORE_POSTGRES_DSN_FILE: the PostgreSQL store is for several replicas, and a stdio upstream's processes live on one (ADR-0007 §4); use the SQLite store"},
		{"the credential beside stdio", stdioBase(stdioCommand, "BYWARD_UPSTREAM_CREDENTIAL_FILE="+missing), nil,
			"BYWARD_UPSTREAM_CREDENTIAL_FILE is for an HTTP upstream; give a stdio upstream its credential with BYWARD_UPSTREAM_ENV_FILE"},
		{"the stdio env file beside HTTP", append(slices.Clone(base), "BYWARD_UPSTREAM_ENV_FILE="+missing), nil,
			"BYWARD_UPSTREAM_ENV_FILE is set, but the upstream is HTTP: it applies only to a stdio upstream (BYWARD_UPSTREAM_COMMAND); remove it"},
		{"the stdio env file beside stdio is read", stdioBase(stdioCommand, "BYWARD_UPSTREAM_ENV_FILE="+missing), []string{missing},
			"BYWARD_UPSTREAM_ENV_FILE" + notFound + "upstream-env; got a value (20 characters, not shown): it cannot be read: file does not exist"},
		{"a refused file and a read one beside stdio", stdioBase(stdioCommand, "BYWARD_STORE_POSTGRES_DSN_FILE=/run/secrets/refused", "BYWARD_UPSTREAM_ENV_FILE="+missing),
			[]string{missing}, "BYWARD_UPSTREAM_ENV_FILE" + notFound + "upstream-env; got a value (20 characters, not shown): it cannot be read: file does not exist"},
		{"no upstream opens every file", stdioBase("BYWARD_STORE_POSTGRES_DSN_FILE=" + missing), []string{missing},
			"BYWARD_STORE_POSTGRES_DSN_FILE" + notFound + "store-postgres-dsn; got a value (20 characters, not shown): it cannot be read: file does not exist"},
		{"both upstreams open every file", append(slices.Clone(base), stdioCommand, "BYWARD_STORE_POSTGRES_DSN_FILE="+missing), []string{missing},
			"BYWARD_STORE_POSTGRES_DSN_FILE" + notFound + "store-postgres-dsn; got a value (20 characters, not shown): it cannot be read: file does not exist"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var opened []string
			_, _, err := Load(nil, tc.env, func(p string) ([]byte, error) {
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

// A variable set to nothing is unset (#428), beside a stdio upstream too: none of the hinted settings
// so written is refused, and the proxy loads.
func TestAHintedSettingsVariableSetToNothingLoadsBesideStdio(t *testing.T) {
	for _, s := range registry {
		if s.StdioHint == "" {
			continue
		}
		name := s.Env()
		if s.Secret() {
			name = s.FileEnv()
		}
		if _, _, err := Load(nil, stdioBase(stdioCommand, name+"="), baseFiles); err != nil {
			t.Errorf("%s=: err = %v, want it to load", name, err)
		}
	}
}
