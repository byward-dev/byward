package config

import (
	"slices"
	"strings"
	"testing"
)

// The off-mode refusals, after the setting as given: one for a stdio upstream's setting with an HTTP
// upstream, one for an HTTP upstream's with a stdio one.
const (
	toStdio = "is set, but the upstream is HTTP: it applies only to a stdio upstream (BYWARD_UPSTREAM_COMMAND); remove it"
	toHTTP  = "is set, but the upstream is stdio: it applies only to an HTTP upstream (BYWARD_UPSTREAM_URL); remove it"
)

// A setting given for the upstream mode that is off is refused at load, named as the operator gave
// it, in both directions and however it was given; before, the HTTP upstream's stdio settings were
// not even parsed (BYWARD_STDIO_MAX_PROCESSES=-5 loaded). The selectors keep their own errors.
func TestASettingForTheUpstreamModeThatIsOffIsRefused(t *testing.T) {
	const identityHint = " is for an HTTP upstream; a stdio upstream gets the user in its environment (BYWARD_SUBJECT, docs/how-to/stdio-upstream.md)"
	const postgresHint = ": the PostgreSQL store is for several replicas, and a stdio upstream's processes live on one (ADR-0007 §4); use the SQLite store"
	const credentialHint = " is for an HTTP upstream; give a stdio upstream its credential with BYWARD_UPSTREAM_ENV_FILE"
	oboHint := func(name string) string {
		return ": a stdio upstream gets its downstream token from its token socket (BYWARD_DOWNSTREAM_TOKEN_SOCKET), not a header; leave " + name + " unset"
	}
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
		{name: "the credential header with stdio", stdio: true, env: []string{"BYWARD_UPSTREAM_CREDENTIAL_HEADER=X-Api-Key"}, want: "BYWARD_UPSTREAM_CREDENTIAL_HEADER " + toHTTP},
		{name: "the URL with stdio keeps its both-set error", stdio: true, env: []string{"BYWARD_UPSTREAM_URL=http://u/mcp", "BYWARD_UPSTREAM_STRIP_HEADERS=X-A"},
			want: "BYWARD_UPSTREAM_URL and BYWARD_UPSTREAM_COMMAND are both set: an upstream is either HTTP or stdio"},
		{name: "a malformed stdio setting with both selectors gets only the both-set error", stdio: true,
			env:  []string{"BYWARD_UPSTREAM_URL=http://u/mcp", "BYWARD_STDIO_MAX_PROCESSES=-5"},
			want: "BYWARD_UPSTREAM_URL and BYWARD_UPSTREAM_COMMAND are both set: an upstream is either HTTP or stdio"},
		{name: "the credential with both selectors gets only the both-set error", stdio: true, env: []string{"BYWARD_UPSTREAM_URL=http://u/mcp", "BYWARD_UPSTREAM_CREDENTIAL_FILE=" + credFile},
			want: "BYWARD_UPSTREAM_URL and BYWARD_UPSTREAM_COMMAND are both set: an upstream is either HTTP or stdio"},
		{name: "the On-Behalf-Of header with stdio keeps its own hint", stdio: true, env: []string{"BYWARD_OBO_HEADER=X-Graph-Token"},
			want: "BYWARD_OBO_HEADER" + oboHint("BYWARD_OBO_HEADER")},
		{name: "the PostgreSQL store with stdio keeps its own hint", stdio: true, env: []string{"BYWARD_STORE_POSTGRES_DSN_FILE=" + credFile},
			want: "BYWARD_STORE_POSTGRES_DSN_FILE" + postgresHint},
		{name: "the credential with stdio keeps its hint", stdio: true, env: []string{"BYWARD_UPSTREAM_CREDENTIAL_FILE=" + credFile},
			want: "BYWARD_UPSTREAM_CREDENTIAL_FILE" + credentialHint},
		// The identity assertion's settings with a valid value, which only an HTTP upstream reads
		// (httpOnlyRefusal); the unverified-email opt-in's rows are in the hint walk.
		{name: "the assertion header with stdio is refused as HTTP-only", stdio: true, env: []string{"BYWARD_ASSERTION_HEADER=X-Byward-Identity"}, want: "BYWARD_ASSERTION_HEADER " + toHTTP},
		{name: "the assertion claims with stdio are refused as HTTP-only", stdio: true, env: []string{"BYWARD_ASSERTION_CLAIMS=email"}, want: "BYWARD_ASSERTION_CLAIMS " + toHTTP},
		{name: "the assertion key directory given as a flag with stdio is refused as HTTP-only", stdio: true, args: []string{"--assertion-keys-dir=/etc/byward/assertion-keys"},
			want: "--assertion-keys-dir " + toHTTP},
		// A refused setting is not parsed, nor checked against other settings (#631): "remove it" is its
		// one error. Before, each of these gave a second error beside the refusal. Each hint by flag, and as
		// a flag set to nothing, is in TestEverySettingWithAStdioHintIsRefusedWithOnlyItsHintBesideStdio,
		// with a value its parser refuses (the identity assertion's settings included).
		{name: "malformed plain identity headers with stdio get only the refusal", stdio: true, env: []string{"BYWARD_IDENTITY_HEADERS=maybe"},
			want: "BYWARD_IDENTITY_HEADERS" + identityHint},
		{name: "a malformed On-Behalf-Of header with stdio gets only the refusal", stdio: true, env: []string{"BYWARD_OBO_HEADER=not a header"},
			want: "BYWARD_OBO_HEADER" + oboHint("BYWARD_OBO_HEADER")},
		{name: "an empty PostgreSQL connection file with stdio gets only the refusal", stdio: true, env: []string{"BYWARD_STORE_POSTGRES_DSN_FILE=/run/secrets/empty"},
			want: "BYWARD_STORE_POSTGRES_DSN_FILE" + postgresHint},
		{name: "the PostgreSQL store beside a state directory with stdio gets only the refusal", stdio: true,
			env: []string{"BYWARD_STORE_POSTGRES_DSN_FILE=" + credFile, "BYWARD_STORE_DIR=/var/lib/byward/state"}, want: "BYWARD_STORE_POSTGRES_DSN_FILE" + postgresHint},
		{name: "the credential given inline with stdio gets only its hint, not the inline-secret error", stdio: true, env: []string{"BYWARD_UPSTREAM_CREDENTIAL=k-123"},
			want: "BYWARD_UPSTREAM_CREDENTIAL" + credentialHint},
		{name: "the credential given inline under --dev with stdio gets only its hint", stdio: true, args: []string{"--dev"}, env: []string{"BYWARD_UPSTREAM_CREDENTIAL=k-123"},
			want: "BYWARD_UPSTREAM_CREDENTIAL" + credentialHint},
		{name: "the PostgreSQL store given inline with stdio gets only its hint, not the inline-secret error", stdio: true, env: []string{"BYWARD_STORE_POSTGRES_DSN=postgres://db/x"},
			want: "BYWARD_STORE_POSTGRES_DSN" + postgresHint},
		{name: "the PostgreSQL store beside a counter file with stdio gets only the refusal", stdio: true,
			env: []string{"BYWARD_STORE_POSTGRES_DSN_FILE=" + credFile, "BYWARD_STORE_COUNTER_FILE=/var/lib/byward/store-writes"}, want: "BYWARD_STORE_POSTGRES_DSN_FILE" + postgresHint},
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

// Every setting of an upstream group is refused with the other mode. The groups are read from the
// registry, so a setting added to one is covered with no test to edit. Each is refused given a value,
// and, but for a secret (which takes no flag of its own), as a flag set to nothing, which is
// deliberate (#596). A setting of the groups with a StdioHint (the credential) is left to
// TestEverySettingWithAStdioHintIsRefusedWithOnlyItsHintBesideStdio, which walks the settings outside
// the groups with one too; the selectors are left out for a value, as with both set there is no mode.
func TestEverySettingOfAnUpstreamGroupIsRefusedWithTheOtherMode(t *testing.T) {
	skipped := map[string]bool{"upstream-url": true, "upstream-command": true} // given a value: the "both set" error
	files := func(p string) ([]byte, error) {
		if p == "/run/secrets/off-mode" {
			return []byte("X=y"), nil
		}
		return baseFiles(p)
	}
	for _, s := range registry {
		forHTTP := s.Group == GroupHTTPUpstream
		if !forHTTP && s.Group != GroupStdioUpstream || s.StdioHint != "" { // a hinted one: TestEverySettingWithAStdioHintIsRefusedWithOnlyItsHintBesideStdio
			continue
		}
		t.Run(s.Name, func(t *testing.T) {
			modeEnv, refusal := append([]string{}, base...), toStdio
			if forHTTP {
				modeEnv, refusal = stdioBase(stdioCommand), toHTTP
			}
			if !s.Secret() {
				flag := "--" + s.Name
				_, _, err := Load([]string{flag + "="}, modeEnv, files)
				if want := flag + " " + refusal; !isConfigError(err) || err.Error() != want {
					t.Errorf("%s=: err = %v, want a config error that is exactly %q", flag, err, want)
				}
			}
			if skipped[s.Name] {
				return
			}
			// Any value given is refused, false and true too (#606), and is its one error: a refused value is
			// not parsed (#631).
			givens := []string{s.Env() + "=x", s.Env() + "=false", s.Env() + "=true"}
			if s.Secret() {
				givens = []string{s.Env() + "_FILE=/run/secrets/off-mode"}
			}
			for _, given := range givens {
				_, _, err := Load(nil, append(slices.Clone(modeEnv), given), files)
				if want := strings.SplitN(given, "=", 2)[0] + " " + refusal; !isConfigError(err) || err.Error() != want {
					t.Errorf("%s: err = %v, want a config error that is exactly %q", given, err, want)
				}
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
		{"a malformed command still refuses the plain identity headers",
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
				"BYWARD_UPSTREAM_CREDENTIAL_HEADER=X-Key", "BYWARD_ASSERTION_HEADER=X-Byward-Identity", "BYWARD_IDENTITY_HEADERS=false"),
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
