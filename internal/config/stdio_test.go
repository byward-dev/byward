package config

import (
	"maps"
	"os"
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

func TestStdioCommandIsReadFromAfterDoubleDashOrTheEnvironmentWithDefaultCaps(t *testing.T) {
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
		if v.Setting.Name == "upstream-command" && v.Display() != `"/usr/bin/server"` {
			t.Fatalf("command displays as %q; arguments stay visible", v.Display())
		}
	}
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
		"env without stdio":       {nil, []string{"BYWARD_UPSTREAM_URL=http://u/mcp", "BYWARD_UPSTREAM_ENV_FILE=/run/secrets/upstream-env"}, "A=1", "BYWARD_UPSTREAM_ENV_FILE is set, but there is no stdio upstream"},
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

func TestStreamIdleTimeoutIsOffAtZeroAndOtherwiseAtLeastAMinute(t *testing.T) {
	for raw, want := range map[string]time.Duration{"0": 0, "0s": 0, "1m": time.Minute, "2h": 2 * time.Hour} {
		c, _, err := Load([]string{"--", "/bin/x"}, stdioBase("BYWARD_STDIO_STREAM_IDLE_TIMEOUT="+raw), baseFiles)
		if err != nil {
			t.Fatalf("%s: %v", raw, err)
		}
		if c.StdioStreamIdleTimeout != want {
			t.Fatalf("%s: got %s, want %s", raw, c.StdioStreamIdleTimeout, want)
		}
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
