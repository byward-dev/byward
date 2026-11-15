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
	stdio := []string{`BYWARD_UPSTREAM_COMMAND=["/usr/bin/server"]`}
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
		{name: "a stdio setting at its default value", env: []string{"BYWARD_STDIO_MAX_PROCESSES=64"}, want: "BYWARD_STDIO_MAX_PROCESSES " + toStdio},
		{name: "a stdio setting given as a flag", args: []string{"--stdio-max-processes=5"}, want: "--stdio-max-processes " + toStdio},
		{name: "the stdio env file", env: []string{"BYWARD_UPSTREAM_ENV_FILE=/run/secrets/upstream-env"}, want: "BYWARD_UPSTREAM_ENV_FILE " + toStdio},
		{name: "the header timeout with stdio", stdio: true, env: []string{"BYWARD_UPSTREAM_HEADER_TIMEOUT=1m"}, want: "BYWARD_UPSTREAM_HEADER_TIMEOUT " + toHTTP},
		{name: "the strip list with stdio", stdio: true, env: []string{"BYWARD_UPSTREAM_STRIP_HEADERS=X-Api-Url"}, want: "BYWARD_UPSTREAM_STRIP_HEADERS " + toHTTP},
		{name: "the credential header with stdio", stdio: true, env: []string{"BYWARD_UPSTREAM_CREDENTIAL_HEADER=X-Api-Key"}, want: "BYWARD_UPSTREAM_CREDENTIAL_HEADER " + toHTTP},
		{name: "the credential with stdio keeps its hint", stdio: true, env: []string{"BYWARD_UPSTREAM_CREDENTIAL_FILE=" + credFile},
			want: "BYWARD_UPSTREAM_CREDENTIAL_FILE is for an HTTP upstream; give a stdio upstream its credential with BYWARD_UPSTREAM_ENV_FILE"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			env := append(append([]string{}, base...), tc.env...)
			if tc.stdio {
				env = stdioBase(append(stdio, tc.env...)...)
			}
			files := stdioFiles("KEY=value")
			_, _, err := Load(tc.args, env, func(p string) ([]byte, error) {
				if p == credFile {
					return []byte("k-123"), nil
				}
				return files(p)
			})
			if !isConfigError(err) || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want a config error containing %q", err, tc.want)
			}
		})
	}
}

// Each mode's own settings at their defaults never stop the other mode from loading.
func TestTheOtherModesDefaultsAreNeverRefused(t *testing.T) {
	if _, _, err := Load(nil, base, baseFiles); err != nil {
		t.Fatalf("HTTP upstream: %v", err)
	}
	if _, _, err := Load(nil, stdioBase(`BYWARD_UPSTREAM_COMMAND=["/usr/bin/server"]`), baseFiles); err != nil {
		t.Fatalf("stdio upstream: %v", err)
	}
}
