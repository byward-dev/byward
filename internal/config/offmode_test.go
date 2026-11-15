package config

import (
	"slices"
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
		{name: "the header timeout with stdio", stdio: true, env: []string{"BYWARD_UPSTREAM_HEADER_TIMEOUT=1m"}, want: "BYWARD_UPSTREAM_HEADER_TIMEOUT " + toHTTP},
		{name: "the strip list with stdio", stdio: true, env: []string{"BYWARD_UPSTREAM_STRIP_HEADERS=X-Api-Url"}, want: "BYWARD_UPSTREAM_STRIP_HEADERS " + toHTTP},
		{name: "the credential header with stdio", stdio: true, env: []string{"BYWARD_UPSTREAM_CREDENTIAL_HEADER=X-Api-Key"}, want: "BYWARD_UPSTREAM_CREDENTIAL_HEADER " + toHTTP},
		{name: "the URL with stdio keeps its both-set error", stdio: true, env: []string{"BYWARD_UPSTREAM_URL=http://u/mcp"},
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

// Each mode's own settings at their defaults never stop the other mode from loading.
func TestTheOtherModesDefaultsAreNeverRefused(t *testing.T) {
	if _, _, err := Load(nil, base, baseFiles); err != nil {
		t.Fatalf("HTTP upstream: %v", err)
	}
	if _, _, err := Load(nil, stdioBase(`BYWARD_UPSTREAM_COMMAND=["/usr/bin/server"]`), baseFiles); err != nil {
		t.Fatalf("stdio upstream: %v", err)
	}
	// The other mode's selector, given empty, selects nothing: it is not an off-mode setting.
	if _, _, err := Load(nil, append(append([]string{}, base...), "BYWARD_UPSTREAM_COMMAND="), baseFiles); err != nil {
		t.Fatalf("HTTP upstream with an empty command: %v", err)
	}
	if _, _, err := Load(nil, stdioBase(`BYWARD_UPSTREAM_COMMAND=["/usr/bin/server"]`, "BYWARD_UPSTREAM_URL="), baseFiles); err != nil {
		t.Fatalf("stdio upstream with an empty URL: %v", err)
	}
}

// The mode is the selector's, even when the command does not parse: a stdio upstream's credential
// header is refused as off-mode alone, never also told to add a credential.
func TestAMalformedStdioCommandStillDecidesTheMode(t *testing.T) {
	_, _, err := Load(nil, stdioBase("BYWARD_UPSTREAM_COMMAND=notjson", "BYWARD_UPSTREAM_CREDENTIAL_HEADER=X-Key"), baseFiles)
	if !isConfigError(err) || !strings.Contains(err.Error(), "BYWARD_UPSTREAM_CREDENTIAL_HEADER is set, but the upstream is stdio") ||
		strings.Contains(err.Error(), "there is no credential") {
		t.Fatalf("err = %v, want only the off-mode refusal for the header", err)
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

// The upstream groups decide which settings are refused for the other mode, so moving a setting into
// or out of one changes what starts: the members are pinned here, and a regrouping must change this
// test too.
func TestTheUpstreamGroupsHoldExactlyTheirModesSettings(t *testing.T) {
	got := map[Group][]string{}
	for _, s := range registry {
		if s.Group == GroupHTTPUpstream || s.Group == GroupStdioUpstream {
			got[s.Group] = append(got[s.Group], s.Name)
		}
	}
	want := map[Group][]string{
		GroupHTTPUpstream:  {"upstream-url", "upstream-header-timeout", "upstream-credential", "upstream-credential-header", "upstream-strip-headers"},
		GroupStdioUpstream: {"upstream-command", "upstream-env", "stdio-max-processes", "stdio-max-processes-per-user", "stdio-stream-idle-timeout"},
	}
	for g, names := range want {
		if !slices.Equal(got[g], names) {
			t.Errorf("%s holds %q, want %q", g, got[g], names)
		}
	}
}

// With no upstream at all there is no mode to be off, so a stdio setting is not refused as an HTTP
// upstream's: the one error is that an upstream is required.
func TestWithNoUpstreamASettingIsNotRefusedForTheWrongMode(t *testing.T) {
	_, _, err := Load(nil, stdioBase("BYWARD_STDIO_MAX_PROCESSES=5"), baseFiles)
	if !isConfigError(err) || !strings.Contains(err.Error(), "BYWARD_UPSTREAM_URL is required") || strings.Contains(err.Error(), "the upstream is HTTP") {
		t.Fatalf("err = %v, want only the required-upstream error", err)
	}
}

// A malformed command still makes the upstream stdio for the credential too: its hint, not the
// HTTP-side checks.
func TestAMalformedStdioCommandKeepsTheCredentialsHint(t *testing.T) {
	_, _, err := Load(nil, stdioBase("BYWARD_UPSTREAM_COMMAND=notjson", "BYWARD_UPSTREAM_CREDENTIAL_FILE="+credFile), func(p string) ([]byte, error) {
		if p == credFile {
			return []byte("k-123"), nil
		}
		return baseFiles(p)
	})
	if !isConfigError(err) || !strings.Contains(err.Error(), "is for an HTTP upstream; give a stdio upstream its credential with BYWARD_UPSTREAM_ENV_FILE") ||
		strings.Contains(err.Error(), "ASSERTION_HEADER") {
		t.Fatalf("err = %v, want the credential's stdio hint and no HTTP-side check", err)
	}
}

// A malformed HTTP upstream URL still selects HTTP, and every error is reported: the stdio setting
// beside it is refused too, not hidden behind the URL's.
func TestAMalformedURLReportsTheOffModeSettingToo(t *testing.T) {
	_, _, err := Load(nil, append(append([]string{}, base...), "BYWARD_UPSTREAM_URL=ftp://x", "BYWARD_STDIO_MAX_PROCESSES=5"), baseFiles)
	if !isConfigError(err) || !strings.Contains(err.Error(), "BYWARD_UPSTREAM_URL: want an absolute http(s) URL") ||
		!strings.Contains(err.Error(), "BYWARD_STDIO_MAX_PROCESSES is set, but the upstream is HTTP") {
		t.Fatalf("err = %v, want the URL's error and the off-mode refusal", err)
	}
}
