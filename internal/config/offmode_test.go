package config

import (
	"strings"
	"testing"
)

// A setting given for the upstream mode that is off is refused at load, named as the operator gave
// it, in both directions and however it was given; before, the HTTP upstream's stdio settings were
// not even parsed (BYWARD_STDIO_MAX_PROCESSES=-5 loaded). The selectors keep their own errors.
func TestASettingForTheUpstreamModeThatIsOffIsRefused(t *testing.T) {
	const toStdio = "is set, but the upstream is HTTP: it applies only to a stdio upstream (BYWARD_UPSTREAM_COMMAND); remove it"
	const toHTTP = "is set, but the upstream is stdio: it applies only to an HTTP upstream (BYWARD_UPSTREAM_URL); remove it"
	stdioCommand := []string{`BYWARD_UPSTREAM_COMMAND=["/usr/bin/server"]`}
	for _, tc := range []struct {
		name  string
		args  []string
		env   []string // beside base (an HTTP upstream), or stdioBase when stdio is set
		stdio bool
		want  string
	}{
		{name: "a malformed process cap", env: []string{"BYWARD_STDIO_MAX_PROCESSES=-5"}, want: "BYWARD_STDIO_MAX_PROCESSES " + toStdio},
		{name: "a malformed per-user cap", env: []string{"BYWARD_STDIO_MAX_PROCESSES_PER_USER=zz"}, want: "BYWARD_STDIO_MAX_PROCESSES_PER_USER " + toStdio},
		{name: "a malformed stream idle timeout", env: []string{"BYWARD_STDIO_STREAM_IDLE_TIMEOUT=abc"}, want: "BYWARD_STDIO_STREAM_IDLE_TIMEOUT " + toStdio},
		{name: "a stdio setting given with its default value", env: []string{"BYWARD_STDIO_MAX_PROCESSES=64"}, want: "BYWARD_STDIO_MAX_PROCESSES " + toStdio},
		{name: "a stdio setting given as a flag", args: []string{"--stdio-max-processes=5"}, want: "--stdio-max-processes " + toStdio},
		{name: "the stdio env file", env: []string{"BYWARD_UPSTREAM_ENV_FILE=/run/secrets/upstream-env"}, want: "BYWARD_UPSTREAM_ENV_FILE " + toStdio},
		{name: "the stdio env file given as a flag", args: []string{"--upstream-env-file=/run/secrets/upstream-env"}, want: "--upstream-env-file " + toStdio},
		{name: "the header timeout with stdio", stdio: true, env: []string{"BYWARD_UPSTREAM_HEADER_TIMEOUT=abc"}, want: "BYWARD_UPSTREAM_HEADER_TIMEOUT " + toHTTP},
		{name: "the strip list with stdio", stdio: true, env: []string{"BYWARD_UPSTREAM_STRIP_HEADERS=X-Api-Url"}, want: "BYWARD_UPSTREAM_STRIP_HEADERS " + toHTTP},
		{name: "the credential header with stdio", stdio: true, env: []string{"BYWARD_UPSTREAM_CREDENTIAL_HEADER=X-Api-Key"}, want: "BYWARD_UPSTREAM_CREDENTIAL_HEADER " + toHTTP},
		{name: "the URL with stdio keeps its both-set error", stdio: true, env: []string{"BYWARD_UPSTREAM_URL=http://u/mcp", "BYWARD_UPSTREAM_STRIP_HEADERS=X-A"},
			want: "BYWARD_UPSTREAM_URL and BYWARD_UPSTREAM_COMMAND are both set: an upstream is either HTTP or stdio"},
		{name: "the credential with both selectors gets only their error", stdio: true, env: []string{"BYWARD_UPSTREAM_URL=http://u/mcp", "BYWARD_UPSTREAM_CREDENTIAL_FILE=" + credFile},
			want: "BYWARD_UPSTREAM_URL and BYWARD_UPSTREAM_COMMAND are both set: an upstream is either HTTP or stdio"},
		{name: "the credential with stdio keeps its hint", stdio: true, env: []string{"BYWARD_UPSTREAM_CREDENTIAL_FILE=" + credFile},
			want: "BYWARD_UPSTREAM_CREDENTIAL_FILE is for an HTTP upstream; give a stdio upstream its credential with BYWARD_UPSTREAM_ENV_FILE"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			env := append(append([]string{}, base...), tc.env...)
			if tc.stdio {
				env = stdioBase(append(stdioCommand, tc.env...)...)
			}
			files := stdioFiles("KEY=value")
			_, _, err := Load(tc.args, env, func(p string) ([]byte, error) {
				if p == credFile {
					return []byte("k-123"), nil
				}
				return files(p)
			})
			if !isConfigError(err) || err.Error() != tc.want { // the whole message: no second, contradicting error
				t.Fatalf("err = %v, want a config error that is exactly %q", err, tc.want)
			}
		})
	}
}

// Every setting of each upstream group is refused with the other mode, read from the registry, so a
// setting added to a group, or moved into one, is covered with no test to edit. The selectors and
// the credential, which keep their own errors, are the only exceptions.
func TestEverySettingOfAnUpstreamGroupIsRefusedWithTheOtherMode(t *testing.T) {
	skipped := map[string]bool{"upstream-url": true, "upstream-command": true, "upstream-credential": true}
	files := func(p string) ([]byte, error) {
		if p == "/run/secrets/off-mode" {
			return []byte("X=y"), nil
		}
		return baseFiles(p)
	}
	n := 0
	for _, s := range registry {
		if s.Group != GroupHTTPUpstream && s.Group != GroupStdioUpstream || skipped[s.Name] {
			continue
		}
		n++
		t.Run(s.Name, func(t *testing.T) {
			given := s.Env() + "=x"
			if s.Secret {
				given = s.Env() + "_FILE=/run/secrets/off-mode"
			}
			env, mode := append(append([]string{}, base...), given), "HTTP"
			if s.Group == GroupHTTPUpstream {
				env, mode = stdioBase(`BYWARD_UPSTREAM_COMMAND=["/usr/bin/server"]`, given), "stdio"
			}
			_, _, err := Load(nil, env, files)
			if want := strings.SplitN(given, "=", 2)[0] + " is set, but the upstream is " + mode; !isConfigError(err) || !strings.Contains(err.Error(), want) {
				t.Fatalf("err = %v, want a config error containing %q", err, want)
			}
		})
	}
	if n < 7 {
		t.Fatalf("%d upstream-mode settings checked, want every one (7 today)", n)
	}
}

// Configurations that load: each mode with the other's settings at their defaults, and the other
// mode's selector given empty, which selects nothing and so is no off-mode setting.
func TestEachModeLoadsBesideTheOtherModesDefaultsAndAnEmptySelector(t *testing.T) {
	command := `BYWARD_UPSTREAM_COMMAND=["/usr/bin/server"]`
	for _, tc := range []struct {
		name string
		env  []string
	}{
		{"an HTTP upstream", base},
		{"a stdio upstream", stdioBase(command)},
		{"an HTTP upstream with an empty command", append(append([]string{}, base...), "BYWARD_UPSTREAM_COMMAND=")},
		{"a stdio upstream with an empty URL", stdioBase(command, "BYWARD_UPSTREAM_URL=")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, _, err := Load(nil, tc.env, baseFiles); err != nil {
				t.Fatal(err)
			}
		})
	}
}

// When the mode is unclear, each error says only what is wrong: a command that does not parse still
// makes the upstream stdio, no upstream at all is only "required", and a malformed URL still selects
// HTTP. These carry a second error of their own, so the messages are matched in parts.
func TestAnUnclearUpstreamGivesOnlyItsOwnErrors(t *testing.T) {
	files := func(p string) ([]byte, error) {
		if p == credFile {
			return []byte("k-123"), nil
		}
		return baseFiles(p)
	}
	for _, tc := range []struct {
		name     string
		env      []string
		contains []string
		absent   []string
	}{
		{"a malformed command still refuses the credential header as off-mode",
			stdioBase("BYWARD_UPSTREAM_COMMAND=notjson", "BYWARD_UPSTREAM_CREDENTIAL_HEADER=X-Key"),
			[]string{"BYWARD_UPSTREAM_CREDENTIAL_HEADER is set, but the upstream is stdio"}, []string{"there is no credential"}},
		{"a malformed command keeps the credential's stdio hint",
			stdioBase("BYWARD_UPSTREAM_COMMAND=notjson", "BYWARD_UPSTREAM_CREDENTIAL_FILE="+credFile),
			[]string{"is for an HTTP upstream; give a stdio upstream its credential with BYWARD_UPSTREAM_ENV_FILE"}, []string{"ASSERTION_HEADER"}},
		{"no upstream at all is only required",
			stdioBase("BYWARD_STDIO_MAX_PROCESSES=5"),
			[]string{"BYWARD_UPSTREAM_URL is required"}, []string{"the upstream is HTTP"}},
		{"a malformed URL still refuses the stdio setting beside it",
			append(append([]string{}, base...), "BYWARD_UPSTREAM_URL=ftp://x", "BYWARD_STDIO_MAX_PROCESSES=5"),
			[]string{"BYWARD_UPSTREAM_URL: want an absolute http(s) URL", "BYWARD_STDIO_MAX_PROCESSES is set, but the upstream is HTTP"}, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, _, err := Load(nil, tc.env, files)
			if !isConfigError(err) {
				t.Fatalf("err = %v, want a config error", err)
			}
			for _, s := range tc.contains {
				if !strings.Contains(err.Error(), s) {
					t.Errorf("err = %v, want it to say %q", err, s)
				}
			}
			for _, s := range tc.absent {
				if strings.Contains(err.Error(), s) {
					t.Errorf("err = %v, want nothing about %q", err, s)
				}
			}
		})
	}
}
