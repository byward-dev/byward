package config

import (
	"fmt"
	"maps"
	"os"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"
)

// stdioBase is base with a stdio upstream instead of the HTTP one.
func stdioBase(extra ...string) []string {
	env := slices.DeleteFunc(slices.Clone(base), func(kv string) bool { return strings.HasPrefix(kv, "BYWARD_UPSTREAM_URL=") })
	return append(env, extra...)
}

func stdioFiles(envFile string) readFileFunc {
	return func(p string) ([]byte, error) {
		if p == "/run/secrets/upstream-env" {
			return []byte(envFile), nil
		}
		return baseFiles(p)
	}
}

func TestStdioCommandIsReadFromAfterDoubleDashOrTheEnvironmentWithDefaultCapsAndStreamIdleTimeout(t *testing.T) {
	for name, tc := range map[string]struct {
		args []string
		env  []string
	}{
		"after --":    {[]string{"--listen", "127.0.0.1:7", "--", "/usr/bin/server", "--flag", "-x"}, nil},
		"environment": {nil, []string{`BYWARD_UPSTREAM_COMMAND=["/usr/bin/server","--flag","-x"]`}},
	} {
		t.Run(name, func(t *testing.T) {
			c, _, err := Load(tc.args, stdioBase(tc.env...), baseFiles)
			if err != nil {
				t.Fatal(err)
			}
			if !slices.Equal(c.UpstreamCommand, []string{"/usr/bin/server", "--flag", "-x"}) || c.UpstreamURL != nil {
				t.Fatalf("command %q, URL %v", c.UpstreamCommand, c.UpstreamURL)
			}
			if c.StdioMaxProcesses != 64 || c.StdioMaxPerUser != 8 || c.StdioStreamIdleTimeout != 10*time.Minute {
				t.Fatalf("caps %d/%d, stream idle %s; want the defaults 64/8 and 10m", c.StdioMaxProcesses, c.StdioMaxPerUser, c.StdioStreamIdleTimeout)
			}
		})
	}
}

func TestStdioEnvFileValuesAreParsedAndNeverDisplayed(t *testing.T) {
	envFile := "# comment\nAPI_KEY=sk-live-1=2\n\nEMPTY=\r\nSPACED=a b\n"
	c, _, err := Load([]string{"--", "/usr/bin/server"}, stdioBase("BYWARD_UPSTREAM_ENV_FILE=/run/secrets/upstream-env"), stdioFiles(envFile))
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{"API_KEY": "sk-live-1=2", "EMPTY": "", "SPACED": "a b"}
	if !maps.Equal(c.UpstreamEnv, want) {
		t.Fatalf("env %q, want %q", c.UpstreamEnv, want)
	}
	for _, v := range c.Values.Effective() {
		if strings.Contains(v.Display(), "sk-live") {
			t.Fatalf("%s displays a value from the env file: %q", v.Setting.Env(), v.Display())
		}
		if v.Setting.Name == "upstream-command" && v.Display() != "/usr/bin/server" {
			t.Fatalf("command displays as %q, want its program", v.Display())
		}
	}
}

// A command that takes no arguments loads with LoadEnvironment: a missing or malformed upstream URL
// names the stdio upstream's variable only, never a command after --, which such a command refuses.
// Load, for the proxy and the commands that take --, still names both (#499).
func TestLoadEnvironmentNeverSuggestsACommandAfterDashesWhereLoadDoes(t *testing.T) {
	for _, tc := range []struct {
		name, url, withoutDashes, withDashes string
	}{
		{"no upstream", "", "BYWARD_UPSTREAM_URL is required (or BYWARD_UPSTREAM_COMMAND)",
			"BYWARD_UPSTREAM_URL is required (or BYWARD_UPSTREAM_COMMAND, or a command after --)"},
		{"a malformed upstream URL", "BYWARD_UPSTREAM_URL=ftp://u/mcp", `BYWARD_UPSTREAM_URL: want an absolute http(s) URL, got "ftp://u/mcp" (or BYWARD_UPSTREAM_COMMAND)`,
			`BYWARD_UPSTREAM_URL: want an absolute http(s) URL, got "ftp://u/mcp" (or BYWARD_UPSTREAM_COMMAND, or a command after --)`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			env := stdioBase()
			if tc.url != "" {
				env = append(env, tc.url)
			}
			if _, err := LoadEnvironment(env, baseFiles); !isConfigError(err) || err.Error() != tc.withoutDashes {
				t.Errorf("LoadEnvironment: got %v, want the config error %q", err, tc.withoutDashes)
			}
			if _, _, err := Load(nil, env, baseFiles); !isConfigError(err) || err.Error() != tc.withDashes {
				t.Errorf("Load: got %v, want the config error %q", err, tc.withDashes)
			}
		})
	}
}

// LoadEnvironment loads what Load loads without arguments, the whole Config or the same error: an
// HTTP or a stdio upstream, a container's no-auth relaxation (which needs the host checks), and an
// unknown variable, refused before any setting is validated. Each row also pins one result, so the
// two cannot agree on a wrong one.
func TestLoadEnvironmentLoadsWhatLoadLoadsWithoutArguments(t *testing.T) {
	for _, tc := range []struct {
		name     string
		env      []string
		readFile readFileFunc
		check    func(*Config, error) bool
	}{
		{"HTTP", base, baseFiles, func(c *Config, err error) bool {
			return err == nil && c != nil && c.UpstreamURL.String() == "http://upstream:9000/mcp"
		}},
		{"stdio", stdioBase(`BYWARD_UPSTREAM_COMMAND=["/usr/bin/server","--flag"]`), baseFiles,
			func(c *Config, err error) bool {
				return err == nil && c != nil && slices.Equal(c.UpstreamCommand, []string{"/usr/bin/server", "--flag"})
			}},
		{"no-auth in a container", append(slices.Clone(anon), "BYWARD_LISTEN=0.0.0.0:8080"), fakeHost("/.dockerenv", bridgeNetdev),
			func(c *Config, err error) bool { return err == nil && c != nil && c.InContainer }},
		{"an unknown variable", append(slices.Clone(base), "BYWARD_TYPO=x"), baseFiles,
			func(_ *Config, err error) bool {
				return isConfigError(err) && strings.HasPrefix(err.Error(), "unknown setting BYWARD_TYPO")
			}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, gotErr := LoadEnvironment(tc.env, tc.readFile)
			want, _, wantErr := Load(nil, tc.env, tc.readFile)
			if !tc.check(got, gotErr) {
				t.Fatalf("LoadEnvironment: %+v, %v", got, gotErr)
			}
			if fmt.Sprint(gotErr) != fmt.Sprint(wantErr) {
				t.Errorf("error: LoadEnvironment %v, Load %v", gotErr, wantErr)
			}
			if got == nil || want == nil {
				if got != want {
					t.Errorf("Config: LoadEnvironment %v, Load %v", got, want)
				}
				return
			}
			diff := configDiff(*got, *want)
			for _, f := range diff {
				t.Errorf("Config.%s", f)
			}
			if len(diff) == 0 && !reflect.DeepEqual(*got, *want) { // a backstop, so a broken configDiff cannot hide a drift
				t.Errorf("Config differs, though configDiff names no field: LoadEnvironment %+v %+v, Load %+v %+v", *got, got.Values, *want, want.Values)
			}
		})
	}
}

// configDiff lists each field in which LoadEnvironment's Config (got) differs from Load's (want),
// with both values. A setting in Values is named by its key, whichever side has it, so a mismatch
// reads as the setting, not as two pointer addresses.
func configDiff(got, want Config) []string {
	var out []string
	gv, wv := reflect.ValueOf(got), reflect.ValueOf(want)
	for i := range gv.NumField() {
		name := gv.Type().Field(i).Name
		if name == "Values" {
			out = append(out, valuesDiff(got.Values, want.Values)...)
			continue
		}
		if g, w := gv.Field(i).Interface(), wv.Field(i).Interface(); !reflect.DeepEqual(g, w) {
			out = append(out, fmt.Sprintf("%s: LoadEnvironment %+v, Load %+v", name, g, w))
		}
	}
	return out
}

// valuesDiff is configDiff for the resolved settings: each setting either side has that differs,
// then the setting order or the command after --, when only those differ.
func valuesDiff(got, want *Values) []string {
	if got == nil || want == nil {
		if got != want {
			return []string{fmt.Sprintf("Values: LoadEnvironment nil %v, Load nil %v", got == nil, want == nil)}
		}
		return nil
	}
	var out []string
	keys := slices.AppendSeq(slices.Collect(maps.Keys(got.byKey)), maps.Keys(want.byKey))
	slices.Sort(keys)
	for _, k := range slices.Compact(keys) {
		g, gok := got.byKey[k]
		w, wok := want.byKey[k]
		if gok != wok || !reflect.DeepEqual(g, w) {
			out = append(out, fmt.Sprintf("Values[%s]: LoadEnvironment %s, Load %s", k, shownSetting(g, gok), shownSetting(w, wok)))
		}
	}
	if len(out) == 0 && !reflect.DeepEqual(*got, *want) {
		out = append(out, "Values: the setting order or the command after -- differs")
	}
	return out
}

// shownSetting shows what the operator gave for a setting, without its registry entry: the value, where it
// came from and the file it was read from, or that the setting is absent.
func shownSetting(v Value, present bool) string {
	if !present {
		return "absent"
	}
	return fmt.Sprintf("%q from %v, path %q", v.Raw, v.Source, v.Path)
}

func TestInvalidStdioSettingsAreRejectedNamingTheSetting(t *testing.T) {
	for name, tc := range map[string]struct {
		args    []string
		env     []string
		envFile string
		want    string
	}{
		"no upstream":             {nil, nil, "", "BYWARD_UPSTREAM_URL is required (or BYWARD_UPSTREAM_COMMAND, or a command after --)"},
		"URL and command":         {[]string{"--", "/bin/x"}, []string{"BYWARD_UPSTREAM_URL=http://u/mcp"}, "", "both set"},
		"flag and --":             {[]string{"--upstream-command", `["/bin/x"]`, "--", "/bin/y"}, nil, "", "either after -- or with --upstream-command"},
		"environment and --":      {[]string{"--", "/bin/y"}, []string{`BYWARD_UPSTREAM_COMMAND=["/bin/x"]`}, "", "either after -- or with --upstream-command / BYWARD_UPSTREAM_COMMAND"},
		"nothing after --":        {[]string{"--"}, nil, "", "no command after --"},
		"not JSON":                {nil, []string{"BYWARD_UPSTREAM_COMMAND=/bin/x --flag"}, "", "BYWARD_UPSTREAM_COMMAND: want a JSON array"},
		"empty array":             {nil, []string{"BYWARD_UPSTREAM_COMMAND=[]"}, "", "BYWARD_UPSTREAM_COMMAND: want a JSON array"},
		"empty program":           {nil, []string{`BYWARD_UPSTREAM_COMMAND=[""]`}, "", "BYWARD_UPSTREAM_COMMAND: want a JSON array"},
		"env file line without =": {[]string{"--", "/bin/x"}, []string{"BYWARD_UPSTREAM_ENV_FILE=/run/secrets/upstream-env"}, "A=1\nsecret-without-equals", "BYWARD_UPSTREAM_ENV_FILE: line 2: want KEY=VALUE"},
		"env duplicate":           {[]string{"--", "/bin/x"}, []string{"BYWARD_UPSTREAM_ENV_FILE=/run/secrets/upstream-env"}, "A=1\nA=2", "line 2: A is set twice"},
		"inline env":              {[]string{"--", "/bin/x"}, []string{"BYWARD_UPSTREAM_ENV=A=1"}, "", "secrets must come from a file"},
		"cap zero":                {[]string{"--", "/bin/x"}, []string{"BYWARD_STDIO_MAX_PROCESSES=0"}, "", "BYWARD_STDIO_MAX_PROCESSES: want a whole number"},
		"user cap over total":     {[]string{"--", "/bin/x"}, []string{"BYWARD_STDIO_MAX_PROCESSES=4", "BYWARD_STDIO_MAX_PROCESSES_PER_USER=5"}, "", "must not exceed BYWARD_STDIO_MAX_PROCESSES"},
		"stream idle under 1m":    {[]string{"--", "/bin/x"}, []string{"BYWARD_STDIO_STREAM_IDLE_TIMEOUT=59s"}, "", "BYWARD_STDIO_STREAM_IDLE_TIMEOUT: want 0 or at least 1m"},
		"stream idle negative":    {[]string{"--", "/bin/x"}, []string{"BYWARD_STDIO_STREAM_IDLE_TIMEOUT=-10m"}, "", "BYWARD_STDIO_STREAM_IDLE_TIMEOUT: want 0 or at least 1m"},
		"stream idle no duration": {[]string{"--", "/bin/x"}, []string{"BYWARD_STDIO_STREAM_IDLE_TIMEOUT=ten"}, "", "BYWARD_STDIO_STREAM_IDLE_TIMEOUT: want a duration such as 10m"},
	} {
		t.Run(name, func(t *testing.T) {
			_, _, err := Load(tc.args, stdioBase(tc.env...), stdioFiles(tc.envFile))
			if !isConfigError(err) || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("got %v, want a config error containing %q", err, tc.want)
			}
		})
	}
}

func TestStreamIdleTimeoutAcceptsZeroAndDurationsOfAMinuteOrMore(t *testing.T) {
	for raw, want := range map[string]time.Duration{"0": 0, "0s": 0, "1m": time.Minute, "2h": 2 * time.Hour} {
		t.Run(raw, func(t *testing.T) {
			c, _, err := Load([]string{"--", "/bin/x"}, stdioBase("BYWARD_STDIO_STREAM_IDLE_TIMEOUT="+raw), baseFiles)
			if err != nil {
				t.Fatal(err)
			}
			if c.StdioStreamIdleTimeout != want {
				t.Fatalf("got %s, want %s", c.StdioStreamIdleTimeout, want)
			}
		})
	}
}

func TestStdioUpstreamWithoutAuthenticationLoadsAndIsLoggedAsARelaxation(t *testing.T) {
	c, _, err := Load([]string{"--", "/bin/x"}, []string{"BYWARD_PUBLIC_URL=http://127.0.0.1:8080/mcp", "BYWARD_INSECURE_NO_AUTH=true"}, os.ReadFile)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.ContainsFunc(c.Relaxations, func(r string) bool {
		return strings.Contains(r, "anyone who can reach the proxy starts upstream processes")
	}) {
		t.Fatalf("relaxations %q lack the stdio warning", c.Relaxations)
	}
}

func TestEnvFileErrorsNeverShowItsContent(t *testing.T) {
	for name, envFile := range map[string]string{
		"line without =": "A=1\nsk-live-secret",
		"duplicate key":  "TOKEN=sk-live-secret\nTOKEN=sk-live-secret",
	} {
		t.Run(name, func(t *testing.T) {
			_, _, err := Load([]string{"--", "/bin/x"}, stdioBase("BYWARD_UPSTREAM_ENV_FILE=/run/secrets/upstream-env"), stdioFiles(envFile))
			if !isConfigError(err) || !strings.Contains(err.Error(), "BYWARD_UPSTREAM_ENV_FILE: line 2") {
				t.Fatalf("got %v, want a config error naming the setting and line 2", err)
			}
			if strings.Contains(err.Error(), "sk-live") {
				t.Fatalf("error %q shows the env file's content", err)
			}
		})
	}
}
