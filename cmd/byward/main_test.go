package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/go-logr/logr"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/trace/noop"

	"github.com/byward-dev/byward/internal/testutil/assertionkey"
	"github.com/byward-dev/byward/internal/testutil/closedport"
	"github.com/byward-dev/byward/internal/testutil/sealingkey"
)

// serveEnv is what a test run that serves needs besides auth: the URLs, the public listener and an
// ephemeral internal listener (the default 127.0.0.1:9090 may be taken on the test host).
func serveEnv(publicURL, listen string) []string {
	return []string{"BYWARD_PUBLIC_URL=" + publicURL, "BYWARD_UPSTREAM_URL=http://127.0.0.1:9/mcp",
		"BYWARD_LISTEN=" + listen, "BYWARD_INTERNAL_LISTEN=127.0.0.1:0"}
}

func runWith(args []string, env ...string) (int, string, string) {
	var out, errb bytes.Buffer
	code := run(context.Background(), args, env, &out, &errb)
	return code, out.String(), errb.String()
}

// authEnv writes the files authenticated mode needs and returns the settings naming them.
func authEnv(t *testing.T) []string {
	t.Helper()
	dir := t.TempDir()
	keys := sealingkey.Dir(t)
	for p, c := range map[string]string{
		filepath.Join(dir, "clients.json"): `{"clients":[{"client_id":"test-app","client_name":"Test app","token_endpoint_auth_method":"none","redirect_uris":["http://127.0.0.1/callback"]}]}`,
		filepath.Join(dir, "secret"):       "s3cret-entra",
	} {
		if err := os.WriteFile(p, []byte(c), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return []string{"BYWARD_ENTRA_TENANT=00000000-0000-0000-0000-000000000001", "BYWARD_ENTRA_CLIENT_ID=00000000-0000-0000-0000-000000000002",
		"BYWARD_ENTRA_CLIENT_SECRET_FILE=" + filepath.Join(dir, "secret"), "BYWARD_KEYS_DIR=" + keys,
		"BYWARD_STATIC_CLIENTS_FILE=" + filepath.Join(dir, "clients.json"),
		"BYWARD_STORE_DIR=" + filepath.Join(dir, "state"), "BYWARD_ASSERTION_KEYS_DIR=" + assertionkey.Dir(t)}
}

func TestAnUnknownSettingIsAConfigErrorWithADidYouMeanHint(t *testing.T) {
	code, _, stderr := runWith(nil, "BYWARD_PUBLC_URL=x")
	if code != exitConfig || !strings.HasPrefix(stderr, "byward: configuration error: unknown setting BYWARD_PUBLC_URL") ||
		!strings.Contains(stderr, "did you mean BYWARD_PUBLIC_URL?") {
		t.Fatalf("code=%d stderr=%q; want exit %d and the unknown-setting configuration error with its did-you-mean hint", code, stderr, exitConfig)
	}
}

// A loose secret file stops the process as a configuration error, telling the operator the fix.
func TestLooseSecretFileIsAConfigError(t *testing.T) {
	env := append(authEnv(t), serveEnv("https://m.example/mcp", "127.0.0.1:0")...)
	var secret string
	for _, kv := range env {
		if v, ok := strings.CutPrefix(kv, "BYWARD_ENTRA_CLIENT_SECRET_FILE="); ok {
			secret = v
		}
	}
	if err := os.Chmod(secret, 0o644); err != nil { //nolint:gosec // G302: the mode under test
		t.Fatal(err)
	}
	code, _, stderr := runWith(nil, env...)
	if code != exitConfig {
		t.Fatalf("exit %d, want %d (configuration error); stderr %q", code, exitConfig, stderr)
	}
	// The startup log comes first; the error is a line of its own.
	if want := "\nbyward: configuration error: BYWARD_ENTRA_CLIENT_SECRET_FILE: secret file " + secret + " has mode 0644"; !strings.Contains(stderr, want) {
		t.Errorf("stderr %q lacks the configuration-error line %q", stderr, want[1:])
	}
	for _, want := range []string{secret, "chmod 600", "read-only"} {
		if !strings.Contains(stderr, want) {
			t.Errorf("stderr %q lacks %q", stderr, want)
		}
	}
}

func TestHelp(t *testing.T) {
	code, stdout, _ := runWith([]string{"--help"})
	if code != exitOK || !strings.Contains(stdout, "BYWARD_UPSTREAM_URL") {
		t.Fatalf("code=%d stdout=%q", code, stdout)
	}
}

func TestVersionJSON(t *testing.T) {
	code, stdout, _ := runWith([]string{"--version", "--json"})
	var v version
	if code != exitOK || json.Unmarshal([]byte(stdout), &v) != nil || v.GoVersion == "" {
		t.Fatalf("code=%d stdout=%q", code, stdout)
	}
}

func TestPrintConfigShowsSources(t *testing.T) {
	code, stdout, _ := runWith([]string{"--print-config", "--listen", "127.0.0.1:9"},
		append(authEnv(t), "BYWARD_PUBLIC_URL=https://m.example/mcp", "BYWARD_UPSTREAM_URL=http://127.0.0.1:9/mcp")...)
	for _, want := range []string{"BYWARD_LISTEN=127.0.0.1:9 (flag)", "BYWARD_PUBLIC_URL=https://m.example/mcp (env)", "BYWARD_SCOPE=mcp (default)"} {
		if !strings.Contains(stdout, want) {
			t.Fatalf("code=%d missing %q in %q", code, want, stdout)
		}
	}
}

func TestRunStopsOnCancelledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var out, errb bytes.Buffer
	code := run(ctx, nil, append(authEnv(t), serveEnv("https://m.example/mcp", "127.0.0.1:0")...), &out, &errb)
	if code != exitOK || !strings.Contains(errb.String(), `"msg":"starting"`) {
		t.Fatalf("code=%d logs=%s", code, errb.String())
	}
}

// With tracing on, OpenTelemetry's errors reach the proxy's own log at warn level, not stderr as they
// are: run hands its logger to the tracing setup.
func TestATracingErrorReachesTheLogAtWarnLevel(t *testing.T) {
	for _, kv := range os.Environ() { // autoexport and the proxy judgment read the process environment: a developer's settings too
		if k, _, _ := strings.Cut(kv, "="); strings.HasPrefix(k, "OTEL_") || strings.HasSuffix(strings.ToUpper(k), "_PROXY") {
			t.Setenv(k, "")
		}
	}
	t.Setenv("OTEL_TRACES_EXPORTER", "otlp")
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "http://"+closedport.Addr(t))
	t.Cleanup(func() {
		otel.SetTracerProvider(noop.NewTracerProvider())
		otel.SetErrorHandler(otel.ErrorHandlerFunc(func(error) {}))
		otel.SetLogger(logr.Discard())
	})
	ln, err := net.Listen("tcp", "127.0.0.1:0") // a taken listen address: run returns once tracing is set up
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	var out, errb bytes.Buffer
	env := append(authEnv(t), serveEnv("https://m.example/mcp", ln.Addr().String())...)
	if code := run(context.Background(), nil, append(env, "OTEL_TRACES_EXPORTER=otlp"), &out, &errb); code != exitRuntime || !strings.Contains(errb.String(), `"msg":"tracing on"`) {
		t.Fatalf("code=%d logs=%s; want tracing on, then the listen failure", code, errb.String())
	}
	otel.Handle(errors.New("probe")) // the handler Setup installed outlives run
	if logs := errb.String(); !strings.Contains(logs, `"level":"WARN","msg":"tracing error","error":"probe"`) {
		t.Fatalf("logs=%s; want the tracing error at warn level", logs)
	}
}

func TestDevModeLogsEachRelaxation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var out, errb bytes.Buffer
	code := run(ctx, []string{"--dev"}, append(authEnv(t), serveEnv("http://127.0.0.1:8080/mcp", "127.0.0.1:0")...), &out, &errb)
	if logs := errb.String(); code != exitOK || !strings.Contains(logs, `"relaxation":"secret file permissions are not checked"`) || !strings.Contains(logs, `"relaxation":"http public URL on loopback"`) {
		t.Fatalf("code=%d logs=%s", code, errb.String())
	}
}

// An http IdP issuer on loopback, which --dev accepts, is logged at startup as a relaxation
// (security invariant 12): #355's acceptance test, end to end from the settings.
func TestDevModeLogsAnHTTPIdPIssuerOnLoopback(t *testing.T) {
	dir := t.TempDir()
	secret := filepath.Join(dir, "oidc-secret")
	if err := os.WriteFile(secret, []byte("s3cret-oidc"), 0o600); err != nil {
		t.Fatal(err)
	}
	const relaxation = "http IdP issuer on loopback (http://localhost:8180/realms/byward)"
	var env []string
	for _, kv := range authEnv(t) {
		if !strings.HasPrefix(kv, "BYWARD_ENTRA_") {
			env = append(env, kv)
		}
	}
	env = append(env, "BYWARD_IDP=keycloak", "BYWARD_OIDC_ISSUER=http://localhost:8180/realms/byward", "BYWARD_OIDC_CLIENT_ID=byward",
		"BYWARD_OIDC_CLIENT_SECRET_FILE="+secret, "BYWARD_GATE_ALLOW_EMPTY=true", "BYWARD_DEV=true")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var out, errb bytes.Buffer
	if code := run(ctx, nil, append(env, serveEnv("http://127.0.0.1:8080/mcp", "127.0.0.1:0")...), &out, &errb); code != exitOK ||
		!strings.Contains(errb.String(), `"msg":"development mode relaxation","relaxation":"`+relaxation) {
		t.Fatalf("code=%d logs=%s; want the issuer logged as a relaxation", code, errb.String())
	}
}

func TestListenFailureIsARuntimeError(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	code, _, stderr := runWith(nil, append(authEnv(t), serveEnv("https://m.example/mcp", ln.Addr().String())...)...)
	if code != exitRuntime || !strings.Contains(stderr, "address already in use") {
		t.Fatalf("code=%d stderr=%s", code, stderr)
	}
}

func TestNoAuthLogsThatAuthIsOffAndTheNextStep(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var out, errb bytes.Buffer
	code := run(ctx, nil, append([]string{"BYWARD_INSECURE_NO_AUTH=true"}, serveEnv("http://localhost:8080/mcp", "127.0.0.1:0")...), &out, &errb)
	logs := errb.String()
	if code != exitOK || !strings.Contains(logs, `"level":"WARN","msg":"development mode relaxation","relaxation":"AUTHENTICATION IS OFF: anyone who can reach http://localhost:8080/mcp`) || !strings.Contains(logs, "to require sign-in") {
		t.Fatalf("code=%d logs=%s", code, logs)
	}
}

// The operator commands: a usage mistake exits 2 with nothing on stdout and the store untouched (not
// even created); a store that cannot open exits 1; a done revocation names the user and exits 0.
func TestRevokeCommandsExit2OnMisuse1OnAStoreFailureAndReportTheRevokedUser(t *testing.T) {
	user := "00000000-0000-0000-0000-00000000000a:11111111-1111-1111-1111-11111111111a"
	cases := []struct {
		name       string
		args       []string
		badStore   bool // BYWARD_STORE_DIR names a file, so the store cannot open
		code       int
		wantStdout string // "" means nothing at all
		inStderr   string
	}{
		{"revoke-user without a key", []string{"revoke-user"}, false, exitConfig, "", "usage: byward revoke-user <user key>"},
		{"revoke-user with two keys", []string{"revoke-user", user, user}, false, exitConfig, "", "usage:"},
		{"revoke-user with an email", []string{"revoke-user", "alice@contoso.example"}, false, exitConfig, "", "not a user key"},
		{"revoke-all without --yes", []string{"revoke-all"}, false, exitConfig, "", "revoke-all --yes"},
		{"revoke-all with yes instead of --yes", []string{"revoke-all", "yes"}, false, exitConfig, "", "revoke-all --yes"},
		{"revoke-all with --yes and more", []string{"revoke-all", "--yes", "extra"}, false, exitConfig, "", "revoke-all --yes"},
		{"revoke-user with a store that cannot open", []string{"revoke-user", user}, true, exitRuntime, "", "revoke-user failed"},
		{"revoke-all with a store that cannot open", []string{"revoke-all", "--yes"}, true, exitRuntime, "", "revoke-all failed"},
		{"revoke-user", []string{"revoke-user", strings.ToUpper(user)}, false, exitOK, "revoked user " + user, `"reason":"operator revoke-user"`},
		{"revoke-all", []string{"revoke-all", "--yes"}, false, exitOK, "revoked every user", `"reason":"operator revoke-all"`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			env := append(authEnv(t), "BYWARD_PUBLIC_URL=https://m.example/mcp", "BYWARD_UPSTREAM_URL=http://127.0.0.1:9/mcp")
			var stateDir string
			for _, kv := range env {
				if v, ok := strings.CutPrefix(kv, "BYWARD_STORE_DIR="); ok {
					stateDir = v
				}
			}
			if tc.badStore {
				if err := os.WriteFile(stateDir, nil, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			code, stdout, stderr := runWith(tc.args, env...)
			okStdout := strings.Contains(stdout, tc.wantStdout) && (tc.wantStdout != "" || stdout == "")
			if code != tc.code || !okStdout || !strings.Contains(stderr, tc.inStderr) {
				t.Fatalf("code %d (want %d)\nstdout %q (want %q)\nstderr %q (want %q)", code, tc.code, stdout, tc.wantStdout, stderr, tc.inStderr)
			}
			if _, err := os.Stat(stateDir); tc.code == exitConfig && !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("a usage mistake touched the store (%v)", err)
			}
		})
	}
}

func TestHelpListsTheOperatorCommands(t *testing.T) {
	code, stdout, _ := runWith([]string{"--help"})
	if code != exitOK || !strings.Contains(stdout, "byward revoke-user <user key> [-- stdio-upstream-command [args...]]") || !strings.Contains(stdout, "byward revoke-all --yes [-- stdio-upstream-command [args...]]") ||
		!strings.Contains(stdout, "byward store new-epoch --yes [-- stdio-upstream-command [args...]]") {
		t.Fatalf("code=%d help=%q", code, stdout)
	}
}

// store new-epoch: a usage mistake exits 2 without touching any store; the SQLite store is refused
// with exit 2, as it finds a restore by itself; a PostgreSQL store that cannot be reached exits 1.
func TestStoreNewEpochExits2OnMisuseOrSQLiteAnd1WhenPostgreSQLIsUnreachable(t *testing.T) {
	cases := []struct {
		name     string
		args     []string
		postgres bool
		code     int
		inStderr string
	}{
		{"no subcommand", []string{"store"}, true, exitConfig, "usage: byward store new-epoch --yes"},
		{"without --yes", []string{"store", "new-epoch"}, true, exitConfig, "usage: byward store new-epoch --yes"},
		{"with SQLite", []string{"store", "new-epoch", "--yes"}, false, exitConfig, "new-epoch is for the PostgreSQL store"},
		{"with PostgreSQL unreachable", []string{"store", "new-epoch", "--yes"}, true, exitRuntime, "store new-epoch failed"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			env := append(authEnv(t), "BYWARD_PUBLIC_URL=https://m.example/mcp", "BYWARD_UPSTREAM_URL=http://127.0.0.1:9/mcp")
			if tc.postgres {
				var kept []string
				for _, kv := range env {
					if !strings.HasPrefix(kv, "BYWARD_STORE_DIR=") {
						kept = append(kept, kv)
					}
				}
				dsn := filepath.Join(t.TempDir(), "dsn")
				if err := os.WriteFile(dsn, []byte("host=127.0.0.1 port=1 user=byward sslmode=verify-full connect_timeout=2"), 0o600); err != nil {
					t.Fatal(err)
				}
				env = append(kept, "BYWARD_STORE_POSTGRES_DSN_FILE="+dsn)
			}
			code, stdout, stderr := runWith(tc.args, env...)
			if code != tc.code || stdout != "" || !strings.Contains(stderr, tc.inStderr) {
				t.Fatalf("code %d (want %d), stdout %q, stderr %q (want %q)", code, tc.code, stdout, stderr, tc.inStderr)
			}
		})
	}
}

// revoke-user, revoke-all and store new-epoch take a stdio upstream after "--", as the proxy, check
// and doctor do, and do not start it (the marker check catches a start that runs before the command
// returns); a usage mistake before the "--" is still exit 2, with the store untouched.
func TestRevokeAndNewEpochTakeAStdioUpstreamAfterDashes(t *testing.T) {
	user := "00000000-0000-0000-0000-00000000000a:11111111-1111-1111-1111-11111111111a"
	cases := []struct {
		name       string
		args       []string
		code       int
		wantStdout string // "" means nothing at all
		inStderr   string
	}{
		{"revoke-user revokes the user", []string{"revoke-user", user, "--"}, exitOK, "revoked user " + user, `"reason":"operator revoke-user"`},
		{"revoke-all revokes every user", []string{"revoke-all", "--yes", "--"}, exitOK, "revoked every user", `"reason":"operator revoke-all"`},
		{"store new-epoch with SQLite", []string{"store", "new-epoch", "--yes", "--"}, exitConfig, "", "new-epoch is for the PostgreSQL store"},
		{"revoke-user without a key", []string{"revoke-user", "--"}, exitConfig, "", "usage: byward revoke-user <user key> [-- stdio-upstream-command [args...]]"},
		{"revoke-all without --yes", []string{"revoke-all", "--"}, exitConfig, "", "usage: byward revoke-all --yes [-- stdio-upstream-command [args...]]"},
		{"store new-epoch without --yes", []string{"store", "new-epoch", "--"}, exitConfig, "", "usage: byward store new-epoch --yes [-- stdio-upstream-command [args...]]"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			script := filepath.Join(dir, "mcp-server")
			if err := os.WriteFile(script, []byte("#!/bin/sh\ntouch "+dir+"/ran\n"), 0o700); err != nil { //nolint:gosec // G306: an executable test command
				t.Fatal(err)
			}
			env := slices.DeleteFunc(authEnv(t), func(kv string) bool { return strings.HasPrefix(kv, "BYWARD_ASSERTION_KEYS_DIR=") }) // refused with a stdio upstream
			env = append(env, "BYWARD_PUBLIC_URL=https://m.example/mcp", "BYWARD_DATA_DIR="+dir)
			code, stdout, stderr := runWith(append(tc.args, script, "--flag"), env...)
			okStdout := strings.Contains(stdout, tc.wantStdout) && (tc.wantStdout != "" || stdout == "")
			if code != tc.code || !okStdout || !strings.Contains(stderr, tc.inStderr) {
				t.Fatalf("code %d (want %d)\nstdout %q (want %q)\nstderr %q (want %q)", code, tc.code, stdout, tc.wantStdout, stderr, tc.inStderr)
			}
			if _, err := os.Stat(filepath.Join(dir, "ran")); err == nil {
				t.Fatal("the command started the stdio upstream")
			}
			if _, err := os.Stat(setting(env, "BYWARD_STORE_DIR")); tc.code == exitConfig && !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("a refused command touched the store (%v)", err)
			}
		})
	}
}

// setting is the value env gives name, the last one as config reads it; "" when it gives none.
func setting(env []string, name string) string {
	v := ""
	for _, kv := range env {
		if s, ok := strings.CutPrefix(kv, name+"="); ok {
			v = s
		}
	}
	return v
}

// Without authentication the broker's store is off: revoke-user, revoke-all and store new-epoch say
// so and exit 2, a configuration error, before revoke-user looks for an IdP that is not configured.
func TestRevokeAndNewEpochWithoutAuthenticationAreAConfigurationError(t *testing.T) {
	env := []string{"BYWARD_INSECURE_NO_AUTH=true", "BYWARD_PUBLIC_URL=http://127.0.0.1:8080/mcp", "BYWARD_UPSTREAM_URL=http://127.0.0.1:9/mcp"}
	for _, tc := range []struct {
		name string
		args []string
	}{
		{"revoke-user", []string{"revoke-user", "00000000-0000-0000-0000-00000000000a:11111111-1111-1111-1111-11111111111a"}},
		{"revoke-all", []string{"revoke-all", "--yes"}},
		{"store new-epoch", []string{"store", "new-epoch", "--yes"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			code, stdout, stderr := runWith(tc.args, env...)
			want := "byward: " + tc.name + ": the broker's store is off with BYWARD_INSECURE_NO_AUTH, so there is nothing to revoke and no store epoch to start"
			if code != exitConfig || stdout != "" || !strings.Contains(stderr, want) {
				t.Fatalf("code %d (want %d), stdout %q, stderr %q (want %q)", code, exitConfig, stdout, stderr, want)
			}
		})
	}
}

// An OTEL_TRACES_EXPORTER that autoexport does not know stops the process as a configuration error,
// on the last line, after the startup log.
func TestAnUnknownOTELTracesExporterIsAConfigError(t *testing.T) {
	// Blank the host's OTEL_* so only this test's setting reaches autoexport. autoexport reads the
	// process environment, while run's getenv reads only the environ it is passed: set the exporter
	// in both.
	for _, kv := range os.Environ() {
		if k, _, _ := strings.Cut(kv, "="); strings.HasPrefix(k, "OTEL_") {
			t.Setenv(k, "")
		}
	}
	t.Setenv("OTEL_TRACES_EXPORTER", "bogus")
	t.Cleanup(func() {
		otel.SetErrorHandler(otel.ErrorHandlerFunc(func(error) {}))
		otel.SetLogger(logr.Discard())
	})
	env := append(authEnv(t), serveEnv("https://m.example/mcp", "127.0.0.1:0")...)
	code, _, stderr := runWith(nil, append(env, "OTEL_TRACES_EXPORTER=bogus")...)
	const want = "byward: configuration error: OTEL_* tracing settings: "
	lines := strings.Split(strings.TrimSuffix(stderr, "\n"), "\n")
	if code != exitConfig || !strings.HasSuffix(stderr, "\n") || len(lines) < 2 || !strings.HasPrefix(lines[len(lines)-1], want) {
		t.Fatalf("code=%d stderr=%q; want exit %d and a last line, after the startup log, starting %q", code, stderr, exitConfig, want)
	}
}

// A configuration error is one line naming the program, whatever the error says.
func TestAConfigurationErrorIsOneLineNamingTheProgram(t *testing.T) {
	var stderr strings.Builder
	if code := reportConfigError(&stderr, errors.New("BYWARD_X: 100% wrong")); code != exitConfig {
		t.Errorf("exit %d, want %d", code, exitConfig)
	}
	if got, want := stderr.String(), "byward: configuration error: BYWARD_X: 100% wrong\n"; got != want {
		t.Errorf("stderr %q, want %q", got, want)
	}
}
