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
		{name: "the stdio env file naming an empty file", env: []string{"BYWARD_UPSTREAM_ENV_FILE=/run/secrets/empty"}, want: "BYWARD_UPSTREAM_ENV_FILE " + toStdio},
		{name: "the stdio env file given as a flag", args: []string{"--upstream-env-file=/run/secrets/upstream-env"}, want: "--upstream-env-file " + toStdio},
		{name: "the header timeout with stdio", stdio: true, env: []string{"BYWARD_UPSTREAM_HEADER_TIMEOUT=abc"}, want: "BYWARD_UPSTREAM_HEADER_TIMEOUT " + toHTTP},
		{name: "the strip list with stdio", stdio: true, env: []string{"BYWARD_UPSTREAM_STRIP_HEADERS=X-Api-Url"}, want: "BYWARD_UPSTREAM_STRIP_HEADERS " + toHTTP},
		{name: "the assertion header with stdio", stdio: true, env: []string{"BYWARD_ASSERTION_HEADER=X-Byward-Identity"}, want: "BYWARD_ASSERTION_HEADER " + toHTTP},
		{name: "the assertion claims with stdio", stdio: true, env: []string{"BYWARD_ASSERTION_CLAIMS=email"}, want: "BYWARD_ASSERTION_CLAIMS " + toHTTP},
		{name: "the unverified-email opt-in with stdio", stdio: true, env: []string{"BYWARD_ASSERTION_UNVERIFIED_EMAIL=true"}, want: "BYWARD_ASSERTION_UNVERIFIED_EMAIL " + toHTTP},
		{name: "the assertion key directory given as a flag with stdio", stdio: true, args: []string{"--assertion-keys-dir=/etc/byward/assertion-keys"},
			want: "--assertion-keys-dir " + toHTTP},
		{name: "the credential header with stdio", stdio: true, env: []string{"BYWARD_UPSTREAM_CREDENTIAL_HEADER=X-Api-Key"}, want: "BYWARD_UPSTREAM_CREDENTIAL_HEADER " + toHTTP},
		{name: "the URL with stdio keeps its both-set error", stdio: true, env: []string{"BYWARD_UPSTREAM_URL=http://u/mcp", "BYWARD_UPSTREAM_STRIP_HEADERS=X-A"},
			want: "BYWARD_UPSTREAM_URL and BYWARD_UPSTREAM_COMMAND are both set: an upstream is either HTTP or stdio"},
		{name: "a malformed stdio setting with both selectors gets only the both-set error", stdio: true,
			env:  []string{"BYWARD_UPSTREAM_URL=http://u/mcp", "BYWARD_STDIO_MAX_PROCESSES=-5"},
			want: "BYWARD_UPSTREAM_URL and BYWARD_UPSTREAM_COMMAND are both set: an upstream is either HTTP or stdio"},
		{name: "the credential with both selectors gets only the both-set error", stdio: true, env: []string{"BYWARD_UPSTREAM_URL=http://u/mcp", "BYWARD_UPSTREAM_CREDENTIAL_FILE=" + credFile},
			want: "BYWARD_UPSTREAM_URL and BYWARD_UPSTREAM_COMMAND are both set: an upstream is either HTTP or stdio"},
		{name: "the identity headers with stdio keep their own hint", stdio: true, env: []string{"BYWARD_IDENTITY_HEADERS=true"},
			want: "BYWARD_IDENTITY_HEADERS is for an HTTP upstream; a stdio upstream gets the user in its environment (BYWARD_SUBJECT, docs/how-to/stdio-upstream.md)"},
		{name: "the On-Behalf-Of header with stdio keeps its own hint", stdio: true, env: []string{"BYWARD_OBO_HEADER=X-Graph-Token"},
			want: "BYWARD_OBO_HEADER: a stdio upstream gets its downstream token from its token socket (BYWARD_DOWNSTREAM_TOKEN_SOCKET), not a header; leave BYWARD_OBO_HEADER unset"},
		{name: "the PostgreSQL store with stdio keeps its own hint", stdio: true, env: []string{"BYWARD_STORE_POSTGRES_DSN_FILE=" + credFile},
			want: "BYWARD_STORE_POSTGRES_DSN_FILE: the PostgreSQL store is for several replicas, and a stdio upstream's processes live on one (ADR-0007 §4); use the SQLite store"},
		{name: "the credential with stdio keeps its hint", stdio: true, env: []string{"BYWARD_UPSTREAM_CREDENTIAL_FILE=" + credFile},
			want: "BYWARD_UPSTREAM_CREDENTIAL_FILE is for an HTTP upstream; give a stdio upstream its credential with BYWARD_UPSTREAM_ENV_FILE"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			env := append(append([]string{}, base...), tc.env...)
			if tc.stdio {
				env = stdioBase(append([]string{stdioCommand}, tc.env...)...)
			}
			files := stdioFiles("KEY=value")
			_, _, err := Load(tc.args, env, func(p string) ([]byte, error) {
				switch p {
				case credFile:
					return []byte("k-123"), nil
				case "/run/secrets/empty":
					return []byte("\n"), nil
				}
				return files(p)
			})
			if !isConfigError(err) || err.Error() != tc.want { // the whole message: no second, contradicting error
				t.Fatalf("err = %v, want a config error that is exactly %q", err, tc.want)
			}
		})
	}
}

// Every setting for one upstream mode is refused with the other mode. The upstream groups are read
// from the registry, so a setting added to one is covered with no test to edit; the HTTP-only
// settings of other groups are named here. Every other setting of the identity and downstream-token
// groups must be named as applying to both modes or refusing stdio with its own hint, so a new one
// fails until someone decides which mode it is for. The selectors and the credential, which keep
// their own errors, are the only exceptions.
func TestEverySettingForOneUpstreamModeIsRefusedWithTheOtherMode(t *testing.T) {
	skipped := map[string]bool{"upstream-url": true, "upstream-command": true, "upstream-credential": true}
	httpOnlySettings := map[string]bool{"assertion-keys-dir": true, "assertion-header": true, "assertion-claims": true, "assertion-unverified-email": true}
	notOffMode := map[string]bool{"obo-scopes": true, "identity-headers": true, "obo-header": true} // both modes; own hints
	files := func(p string) ([]byte, error) {
		if p == "/run/secrets/off-mode" {
			return []byte("X=y"), nil
		}
		return baseFiles(p)
	}
	n := 0
	for _, s := range registry {
		forHTTP := s.Group == GroupHTTPUpstream || httpOnlySettings[s.Name]
		if (s.Group == GroupIdentity || s.Group == GroupDownstreamTokens) && !forHTTP && !notOffMode[s.Name] {
			t.Errorf("%s: list it in httpOnly and httpOnlySettings if only an HTTP upstream reads it, else in notOffMode (both modes, or its own stdio hint)", s.Name)
		}
		if !forHTTP && s.Group != GroupStdioUpstream || skipped[s.Name] {
			continue
		}
		n++
		t.Run(s.Name, func(t *testing.T) {
			given := s.Env() + "=x"
			if s.Secret() {
				given = s.Env() + "_FILE=/run/secrets/off-mode"
			}
			env, mode := append(append([]string{}, base...), given), "HTTP"
			if forHTTP {
				env, mode = stdioBase(stdioCommand, given), "stdio"
			}
			_, _, err := Load(nil, env, files)
			if want := strings.SplitN(given, "=", 2)[0] + " is set, but the upstream is " + mode; !isConfigError(err) || !strings.Contains(err.Error(), want) {
				t.Fatalf("err = %v, want a config error containing %q", err, want)
			}
		})
	}
	if n < 11 {
		t.Fatalf("%d upstream-mode settings checked, want every one (11 today)", n)
	}
}

// Configurations that load: each mode with the other's settings at their defaults, or given empty,
// as env templates list every variable; an empty value is not given, so it is no off-mode setting.
// The other mode's selector given empty selects nothing. (An empty assertion header or claims flag is
// refused by its own parser even beside a stdio upstream: TestAFlagSetToNothingIsRefusedAsGiven.)
func TestEachModeLoadsBesideTheOtherModesDefaultsAndEmptyValues(t *testing.T) {
	command := stdioCommand
	for _, tc := range []struct {
		name string
		args []string
		env  []string
	}{
		{"an HTTP upstream", nil, base},
		{"a stdio upstream", nil, stdioBase(command)},
		{"an HTTP upstream with an empty command", nil, append(append([]string{}, base...), "BYWARD_UPSTREAM_COMMAND=")},
		{"a stdio upstream with an empty URL", nil, stdioBase(command, "BYWARD_UPSTREAM_URL=")},
		{"an HTTP upstream with an empty stdio setting", nil, append(append([]string{}, base...), "BYWARD_STDIO_MAX_PROCESSES=")},
		{"an HTTP upstream with an empty stdio flag", []string{"--stdio-max-processes="}, base},
		{"a stdio upstream with an empty HTTP setting", nil, stdioBase(command, "BYWARD_UPSTREAM_STRIP_HEADERS=")},
		{"a stdio upstream with an empty assertion key directory", nil, stdioBase(command, "BYWARD_ASSERTION_KEYS_DIR=")},
		{"a stdio upstream with empty assertion claims", nil, stdioBase(command, "BYWARD_ASSERTION_CLAIMS=")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, _, err := Load(tc.args, tc.env, baseFiles); err != nil {
				t.Fatal(err)
			}
		})
	}
}

// When the mode is unclear, each error says only what is wrong: a command that does not parse still
// makes the upstream stdio, no upstream at all is only "required", and a malformed URL still selects
// HTTP. Matched in parts, since most carry a second error of their own (the command's or the
// URL's); the one with no upstream names its whole message.
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
		{"a malformed command still refuses the identity headers",
			stdioBase("BYWARD_UPSTREAM_COMMAND=notjson", "BYWARD_IDENTITY_HEADERS=true"),
			[]string{"BYWARD_IDENTITY_HEADERS is for an HTTP upstream"}, nil},
		{"a malformed command still refuses the On-Behalf-Of header",
			stdioBase("BYWARD_UPSTREAM_COMMAND=notjson", "BYWARD_OBO_HEADER=X-Graph-Token"),
			[]string{"BYWARD_OBO_HEADER: a stdio upstream gets its downstream token from its token socket"}, nil},
		{"a malformed command still refuses the PostgreSQL store",
			stdioBase("BYWARD_UPSTREAM_COMMAND=notjson", "BYWARD_STORE_POSTGRES_DSN_FILE="+credFile, "BYWARD_STORE_DIR="),
			[]string{"BYWARD_STORE_POSTGRES_DSN_FILE: the PostgreSQL store is for several replicas"}, nil},
		{"no upstream at all gives only the required error",
			stdioBase("BYWARD_STDIO_MAX_PROCESSES=5", "BYWARD_UPSTREAM_HEADER_TIMEOUT=abc", "BYWARD_UPSTREAM_STRIP_HEADERS=Host",
				"BYWARD_UPSTREAM_CREDENTIAL_HEADER=X-Key", "BYWARD_ASSERTION_HEADER=X-Byward-Identity"),
			[]string{"BYWARD_UPSTREAM_URL is required (or BYWARD_UPSTREAM_COMMAND, or a command after --)"}, []string{"the upstream is HTTP", ";"}},
		{"a malformed URL still reports the HTTP upstream's own settings",
			append(append([]string{}, base...), "BYWARD_UPSTREAM_URL=ftp://x", "BYWARD_UPSTREAM_STRIP_HEADERS=Host", "BYWARD_UPSTREAM_HEADER_TIMEOUT=abc"),
			[]string{"BYWARD_UPSTREAM_URL: want an absolute http(s) URL", "BYWARD_UPSTREAM_STRIP_HEADERS: want exact header names, such as X-Argocd-Base-Url; got entry 1 of 1, Host: MCP needs it at the upstream", "BYWARD_UPSTREAM_HEADER_TIMEOUT: want a duration"}, nil},
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
