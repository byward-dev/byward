package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/go-logr/logr"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/trace/noop"

	"github.com/byward-dev/byward/internal/store/sqlite"
	"github.com/byward-dev/byward/internal/testutil/assertionkey"
	"github.com/byward-dev/byward/internal/testutil/closedport"
	"github.com/byward-dev/byward/internal/testutil/pgtest"
	"github.com/byward-dev/byward/internal/testutil/sealingkey"
	"github.com/byward-dev/byward/internal/tracing"
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

// runDone is runWith with a context that is already done, so a command that waits on it returns at
// once: startup stops right after it has started, and serves nothing.
func runDone(args []string, env ...string) (int, string, string) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var out, errb bytes.Buffer
	code := run(ctx, args, env, &out, &errb)
	return code, out.String(), errb.String()
}

// entraSecret is the Entra client secret authEnv writes; no output may ever hold it.
const entraSecret = "s3cret-entra"

// authEnv writes the files authenticated mode needs and returns the settings naming them.
func authEnv(t *testing.T) []string {
	t.Helper()
	dir := t.TempDir()
	keys := sealingkey.Dir(t)
	for p, c := range map[string]string{
		filepath.Join(dir, "clients.json"): `{"clients":[{"client_id":"test-app","client_name":"Test app","token_endpoint_auth_method":"none","redirect_uris":["http://127.0.0.1/callback"]}]}`,
		filepath.Join(dir, "secret"):       entraSecret,
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

// oidcAuthEnv is authEnv for an oidc IdP: without the Entra settings, and with authEnv's secret file
// as the client secret. The caller names the IdP, the client ID and, where the IdP needs one, the
// issuer.
func oidcAuthEnv(t *testing.T) []string {
	t.Helper()
	env := authEnv(t)
	secret := setting(env, "BYWARD_ENTRA_CLIENT_SECRET_FILE")
	return append(without(env, "BYWARD_ENTRA_"), "BYWARD_OIDC_CLIENT_SECRET_FILE="+secret)
}

// keycloakOperatorEnv is an operator command's env (operatorEnv) for a keycloak IdP that admits a user
// with no group, with the Entra client secret as the oidc one, and extra after.
func keycloakOperatorEnv(env []string, extra ...string) []string {
	return append(append(without(env, "BYWARD_ENTRA_"), "BYWARD_OIDC_CLIENT_SECRET_FILE="+setting(env, "BYWARD_ENTRA_CLIENT_SECRET_FILE"),
		"BYWARD_IDP=keycloak", "BYWARD_OIDC_ISSUER=https://sso.example.com/realms/acme", "BYWARD_OIDC_CLIENT_ID=byward", "BYWARD_GATE_ALLOW_EMPTY=true"), extra...)
}

// stdioAuthEnv is authEnv for a stdio upstream, which refuses the identity assertion's keys directory.
func stdioAuthEnv(t *testing.T) []string {
	t.Helper()
	return without(authEnv(t), "BYWARD_ASSERTION_KEYS_DIR=")
}

// without is a copy of env without the entries that start with prefix.
func without(env []string, prefix string) []string {
	return slices.DeleteFunc(slices.Clone(env), func(kv string) bool { return strings.HasPrefix(kv, prefix) })
}

func TestAnUnknownSettingIsAConfigErrorWithADidYouMeanHint(t *testing.T) {
	code, _, stderr := runWith(nil, "BYWARD_PUBLC_URL=x")
	if code != exitConfig || !strings.HasPrefix(stderr, "byward: configuration error: unknown setting BYWARD_PUBLC_URL") ||
		!strings.Contains(stderr, "did you mean BYWARD_PUBLIC_URL?") {
		t.Fatalf("code=%d stderr=%q; want exit %d and the unknown-setting configuration error with its did-you-mean hint", code, stderr, exitConfig)
	}
}

// A loose secret file stops the process as a configuration error naming the setting, never the path,
// and telling the operator the fix.
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
	// The startup log comes first; the error is a line of its own, naming the setting and the mode,
	// never the path (security invariant 2, #575).
	line := stderr[strings.LastIndex(stderr, "\nbyward: configuration error: ")+1:]
	if !strings.HasPrefix(line, "byward: configuration error: BYWARD_ENTRA_CLIENT_SECRET_FILE: secret file has mode 0644") {
		t.Errorf("stderr %q lacks the configuration-error line", stderr)
	}
	for _, want := range []string{"chmod 600", "read-only"} {
		if !strings.Contains(line, want) {
			t.Errorf("configuration-error line %q lacks %q", line, want)
		}
	}
	if strings.Contains(line, secret) {
		t.Errorf("configuration-error line %q shows the secret file's path", line)
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

// --print-config and the startup log show a setting of each shape that hides part or all of a value
// through that shape, never the part it hides (security invariant 2): a secret as <redacted>; a URL
// without its query, which can hold an API key (#458), marking it as left out ("?…"), as the operators
// who read a query there now see; each URL entry of a list as MarkedURL shows it, here its path
// parameters (";…"); and the stdio upstream's command by its program and how many arguments follow,
// never the arguments, one of which can be a token, as the release note says. The leak test covers
// every such setting.
func TestAValueOfEachHidingShapeIsShownThroughItInPrintConfigAndTheStartupLog(t *testing.T) {
	serve := serveEnv("https://m.example/mcp", "127.0.0.1:0")
	for _, c := range []struct {
		name, hidden string
		stdio        bool // with a stdio upstream, which takes no assertion keys (stdioAuthEnv) and no upstream URL
		env, args    []string
		line, logged string // the --print-config line and the startup log's config record, after "msg":"config",
	}{
		{"secret", entraSecret, false, nil, nil,
			"BYWARD_ENTRA_CLIENT_SECRET=<redacted> (file)", `"setting":"BYWARD_ENTRA_CLIENT_SECRET","value":"<redacted>","source":"file"}`},
		{"URL", "S3CRET-api-key", false, []string{"BYWARD_UPSTREAM_URL=http://127.0.0.1:9/mcp?api_key=S3CRET-api-key"}, nil,
			"BYWARD_UPSTREAM_URL=http://127.0.0.1:9/mcp?… (env)", `"setting":"BYWARD_UPSTREAM_URL","value":"http://127.0.0.1:9/mcp?…","source":"env"}`},
		{"URL list", "S3CRET-list", false, []string{"BYWARD_CLIENT_DENYLIST=https://evil.example/c.json;k=S3CRET-list, bad.example"}, nil,
			"BYWARD_CLIENT_DENYLIST=https://evil.example/c.json;…, bad.example (env)", `"setting":"BYWARD_CLIENT_DENYLIST","value":"https://evil.example/c.json;…, bad.example","source":"env"}`},
		{"command", "S3CRET-token", true, nil, []string{"--", "/bin/cat", "--token", "S3CRET-token"},
			"BYWARD_UPSTREAM_COMMAND=/bin/cat (2 arguments not shown) (flag)", `"setting":"BYWARD_UPSTREAM_COMMAND","value":"/bin/cat (2 arguments not shown)","source":"flag"}`},
	} {
		t.Run(c.name, func(t *testing.T) {
			env := slices.Concat(authEnv(t), serve, c.env) // the row's own settings last, so they win
			if c.stdio {
				env = slices.Concat(stdioAuthEnv(t), without(serve, "BYWARD_UPSTREAM_URL="), c.env)
			}
			code, stdout, stderr := runWith(append([]string{"--print-config"}, c.args...), env...)
			if code != exitOK || !strings.Contains(stdout, "\n"+c.line+"\n") || strings.Contains(stdout+stderr, c.hidden) {
				t.Errorf("--print-config: code %d, stdout %q, stderr %q; want the line %q and never %q", code, stdout, stderr, c.line, c.hidden)
			}
			_, stdout, stderr = runDone(c.args, env...)
			if want := `"msg":"config",` + c.logged; !strings.Contains(stderr, want) || strings.Contains(stderr+stdout, c.hidden) {
				t.Errorf("startup log %s; want %s and never %q", stderr, want, c.hidden)
			}
		})
	}
}

// A value holding a newline is shown quoted, on its own setting's one line, in --print-config and the
// startup log alike, so it cannot forge another setting's line (#505): here a resource name that
// would otherwise print a line claiming a client secret from a file. Every line of --print-config is
// one setting's, and no setting has two.
func TestAValueWithANewlineCannotForgeASettingsLineInPrintConfigOrTheStartupLog(t *testing.T) {
	env := []string{"BYWARD_INSECURE_NO_AUTH=true", "BYWARD_UPSTREAM_URL=http://127.0.0.1:9/mcp", "BYWARD_PUBLIC_URL=http://localhost:8080/mcp",
		"BYWARD_LISTEN=127.0.0.1:0", "BYWARD_INTERNAL_LISTEN=127.0.0.1:0", // the startup run below binds no fixed port
		"BYWARD_RESOURCE_NAME=x\nBYWARD_ENTRA_CLIENT_SECRET=<redacted> (file)"}
	code, stdout, stderr := runWith([]string{"--print-config"}, env...)
	if want := "\n" + `BYWARD_RESOURCE_NAME="x\nBYWARD_ENTRA_CLIENT_SECRET=<redacted> (file)" (env)` + "\n"; code != exitOK || !strings.Contains("\n"+stdout, want) {
		t.Fatalf("--print-config: code %d, stdout %q, stderr %q; want the line %q", code, stdout, stderr, strings.Trim(want, "\n"))
	}
	var notOwn, secretLines []string
	seen := map[string]bool{}
	for _, line := range strings.Split(strings.TrimSuffix(stdout, "\n"), "\n") {
		name, _, ok := strings.Cut(line, "=")
		if !ok || !strings.HasPrefix(name, "BYWARD_") || seen[name] {
			notOwn = append(notOwn, line)
		}
		seen[name] = true
		if name == "BYWARD_ENTRA_CLIENT_SECRET" {
			secretLines = append(secretLines, line)
		}
	}
	if want := []string{"BYWARD_ENTRA_CLIENT_SECRET= (default)"}; len(notOwn) > 0 || !slices.Equal(secretLines, want) {
		t.Errorf("--print-config: lines that are not one setting's own %q; BYWARD_ENTRA_CLIENT_SECRET lines %q, want only %q:\n%s", notOwn, secretLines, want, stdout)
	}
	code, _, stderr = runDone(nil, env...)
	if code != exitOK {
		t.Fatalf("startup: code %d, stderr %s", code, stderr)
	}
	if want := `"msg":"config","setting":"BYWARD_RESOURCE_NAME","value":"\"x\\nBYWARD_ENTRA_CLIENT_SECRET=<redacted> (file)\"","source":"env"}`; !strings.Contains(stderr, want) {
		t.Errorf("startup log %s; want %s", stderr, want)
	}
}

func TestRunStopsOnCancelledContext(t *testing.T) {
	code, _, logs := runDone(nil, append(authEnv(t), serveEnv("https://m.example/mcp", "127.0.0.1:0")...)...)
	if code != exitOK || !strings.Contains(logs, `"msg":"starting"`) {
		t.Fatalf("code=%d logs=%s", code, logs)
	}
}

// With tracing on, OpenTelemetry's errors reach the proxy's own log at warn level, not stderr as they
// are: run hands its logger to the tracing setup.
func TestATracingErrorReachesTheLogAtWarnLevel(t *testing.T) {
	blankOTELEnv(t)
	for _, kv := range os.Environ() { // the proxy judgment reads the process environment: a developer's settings too
		if k, _, _ := strings.Cut(kv, "="); strings.HasSuffix(strings.ToUpper(k), "_PROXY") {
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
	code, _, logs := runDone([]string{"--dev"}, append(authEnv(t), serveEnv("http://127.0.0.1:8080/mcp", "127.0.0.1:0")...)...)
	if code != exitOK || !strings.Contains(logs, `"relaxation":"secret file permissions are not checked"`) || !strings.Contains(logs, `"relaxation":"http public URL on loopback"`) {
		t.Fatalf("code=%d logs=%s", code, logs)
	}
}

// An http IdP issuer on loopback, which --dev accepts, is logged at startup as a relaxation
// (security invariant 12): #355's acceptance test, end to end from the settings.
func TestDevModeLogsAnHTTPIdPIssuerOnLoopback(t *testing.T) {
	const relaxation = "http IdP issuer on loopback (http://localhost:8180/realms/byward)"
	env := append(oidcAuthEnv(t), "BYWARD_IDP=keycloak", "BYWARD_OIDC_ISSUER=http://localhost:8180/realms/byward", "BYWARD_OIDC_CLIENT_ID=byward",
		"BYWARD_GATE_ALLOW_EMPTY=true", "BYWARD_DEV=true")
	if code, _, logs := runDone(nil, append(env, serveEnv("http://127.0.0.1:8080/mcp", "127.0.0.1:0")...)...); code != exitOK ||
		!strings.Contains(logs, `"msg":"development mode relaxation","relaxation":"`+relaxation) {
		t.Fatalf("code=%d logs=%s; want the issuer logged as a relaxation", code, logs)
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
	code, _, logs := runDone(nil, append([]string{"BYWARD_INSECURE_NO_AUTH=true"}, serveEnv("http://localhost:8080/mcp", "127.0.0.1:0")...)...)
	if code != exitOK || !strings.Contains(logs, `"level":"WARN","msg":"development mode relaxation","relaxation":"AUTHENTICATION IS OFF: anyone who can reach http://localhost:8080/mcp`) || !strings.Contains(logs, "to require sign-in") {
		t.Fatalf("code=%d logs=%s", code, logs)
	}
}

// The operator commands: a usage mistake, or a store that is not there (L152), exits 2 with nothing
// on stdout and nothing created; a store that cannot open exits 1; a done revocation names the user
// and the store, and exits 0. Stdout, and the stderr of a command that is not done, are pinned
// whole (outputMatches); a done command's stderr is its audit log, which must name the command.
func TestRevokeCommandsExit2OnMisuseOrNoStore1OnAStoreFailureAndNameTheRevokedUserAndStore(t *testing.T) {
	user := "00000000-0000-0000-0000-00000000000a:11111111-1111-1111-1111-11111111111a"
	const stateDirNotADir = ": no byward store there: the state directory, or a directory above it, is not a directory; run the command with the proxy's settings (see docs/how-to/state.md)\n"
	const storeCannotOpen = "BYWARD_STORE_DIR / BYWARD_STORE_COUNTER_FILE: sqlite store: read schema version: {varies} (see docs/how-to/state.md)\n"
	cases := []struct {
		name   string
		args   []string
		store  operatorStore
		code   int
		stdout string // the whole stdout: the store by its setting, never its path (#575)
		stderr string // the whole stderr of a command that is not done; "" for a done one
	}{
		{"revoke-user without a key", []string{"revoke-user"}, noStore, exitConfig, "", revokeUserUsage},
		{"revoke-user with two keys", []string{"revoke-user", user, user}, noStore, exitConfig, "", revokeUserUsage},
		{"revoke-user with an email", []string{"revoke-user", "alice@contoso.example"}, noStore, exitConfig, "", `byward: revoke-user (21 characters, not shown): not a user key: with Entra, tid:oid, the tenant and object IDs of the user; with an oidc IdP, the value of its subject claim (BYWARD_OIDC_SUBJECT_CLAIM, default sub; a sub is at most 255 printable ASCII characters), as the audit records' user_key shows it` + "\n"},
		{"revoke-user with an empty key", []string{"revoke-user", ""}, noStore, exitConfig, "", `byward: revoke-user (0 characters, not shown): not a user key: with Entra, tid:oid, the tenant and object IDs of the user; with an oidc IdP, the value of its subject claim (BYWARD_OIDC_SUBJECT_CLAIM, default sub; a sub is at most 255 printable ASCII characters), as the audit records' user_key shows it` + "\n"},
		{"revoke-user with a non-ASCII email, named by its characters, not bytes", []string{"revoke-user", "jöhn@exämple.com"}, noStore, exitConfig, "", `byward: revoke-user (16 characters, not shown): not a user key: with Entra, tid:oid, the tenant and object IDs of the user; with an oidc IdP, the value of its subject claim (BYWARD_OIDC_SUBJECT_CLAIM, default sub; a sub is at most 255 printable ASCII characters), as the audit records' user_key shows it` + "\n"},
		{"revoke-all without --yes", []string{"revoke-all"}, noStore, exitConfig, "", revokeAllUsage},
		{"revoke-all with yes instead of --yes", []string{"revoke-all", "yes"}, noStore, exitConfig, "", revokeAllUsage},
		{"revoke-all with --yes and more", []string{"revoke-all", "--yes", "extra"}, noStore, exitConfig, "", revokeAllUsage},
		{"revoke-user with no store", []string{"revoke-user", user}, noStore, exitConfig, "", "byward: revoke-user: BYWARD_STORE_DIR" + storeMissing},
		{"revoke-all with no store", []string{"revoke-all", "--yes"}, noStore, exitConfig, "", "byward: revoke-all: BYWARD_STORE_DIR" + storeMissing},
		{"revoke-user with a state directory that is a file", []string{"revoke-user", user}, stateDirIsAFile, exitConfig, "", "byward: revoke-user: BYWARD_STORE_DIR" + stateDirNotADir},
		{"revoke-all with a state directory that is a file", []string{"revoke-all", "--yes"}, stateDirIsAFile, exitConfig, "", "byward: revoke-all: BYWARD_STORE_DIR" + stateDirNotADir},
		{"revoke-user with a store that cannot open", []string{"revoke-user", user}, corruptStore, exitRuntime, "", "byward: revoke-user failed: " + storeCannotOpen},
		{"revoke-all with a store that cannot open", []string{"revoke-all", "--yes"}, corruptStore, exitRuntime, "", "byward: revoke-all failed: " + storeCannotOpen},
		{"revoke-user", []string{"revoke-user", strings.ToUpper(user)}, proxysStore, exitOK, "revoked user " + user + " in BYWARD_STORE_DIR" + revoked, ""},
		{"revoke-all", []string{"revoke-all", "--yes"}, proxysStore, exitOK, "revoked every user in BYWARD_STORE_DIR" + revoked, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			env, stateDir, counter := operatorEnv(t, tc.store)
			code, stdout, stderr := runWith(tc.args, env...)
			wantStdout := tc.stdout
			var wantStderr string
			var okStderr bool
			if tc.code == exitOK {
				wantStderr = `"reason":"operator ` + tc.args[0] + `"`
				okStderr = strings.Contains(stderr, wantStderr)
			} else {
				wantStderr = tc.stderr
				okStderr = outputMatches(stderr, wantStderr)
			}
			if code != tc.code || stdout != wantStdout || !okStderr {
				t.Fatalf("code %d (want %d)\nstdout %q\nwant   %q\nstderr %q\nwant   %q", code, tc.code, stdout, wantStdout, stderr, wantStderr)
			}
			if tc.code == exitOK {
				return
			}
			created := []string{counter}
			if tc.store == noStore {
				created = append(created, stateDir)
			}
			for _, p := range created {
				if _, err := os.Stat(p); !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("a command that is not done created %s (%v)", p, err)
				}
			}
		})
	}
}

// L152, ADR-0007 §9: a revocation run with a mistyped state directory, beside the real store's
// counter file, is refused before it writes anything: the real counter file keeps its value, so
// restore detection is not weakened, and the mistyped directory is not created.
func TestARevocationWithAMistypedStateDirectoryLeavesTheRealStoreAlone(t *testing.T) {
	env, stateDir, counter := operatorEnv(t, proxysStore)
	// A write past the store's first, so the mirror holds a value a new empty store would not write.
	if code, _, stderr := runWith([]string{"revoke-all", "--yes"}, env...); code != exitOK {
		t.Fatalf("revoke-all on the real store: %d %s", code, stderr)
	}
	before, err := os.ReadFile(filepath.Clean(counter))
	if err != nil {
		t.Fatal(err)
	}
	typo := stateDir + "-typo"
	for i, kv := range env {
		if strings.HasPrefix(kv, "BYWARD_STORE_DIR=") {
			env[i] = "BYWARD_STORE_DIR=" + typo
		}
	}
	code, stdout, stderr := runWith([]string{"revoke-all", "--yes"}, env...)
	want := "byward: revoke-all: BYWARD_STORE_DIR" + storeMissing // the setting, never the path (#575)
	if code != exitConfig || stdout != "" || stderr != want {
		t.Fatalf("code %d (want %d), stdout %q, stderr %q (want %q)", code, exitConfig, stdout, stderr, want)
	}
	if after, err := os.ReadFile(filepath.Clean(counter)); err != nil || !bytes.Equal(after, before) {
		t.Fatalf("the real counter file changed: %q, then %q (%v)", before, after, err)
	}
	if _, err := os.Stat(typo); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("the mistyped state directory was created (%v)", err)
	}
}

// operatorStore is what the state directory of an operator command's environment holds.
type operatorStore int

const (
	noStore         operatorStore = iota // nothing: the directory does not exist
	stateDirIsAFile                      // the directory's path is a file
	corruptStore                         // a byward.db that is not a database
	proxysStore                          // the store a proxy created
)

// operatorEnv is a proxy's environment for an operator command, with its state directory and
// counter file (BYWARD_STORE_COUNTER_FILE, outside the directory), the directory holding st.
func operatorEnv(t *testing.T, st operatorStore) (env []string, stateDir, counter string) {
	t.Helper()
	counter = filepath.Join(t.TempDir(), "store-writes")
	env = append(authEnv(t), "BYWARD_PUBLIC_URL=https://m.example/mcp", "BYWARD_UPSTREAM_URL=http://127.0.0.1:9/mcp",
		"BYWARD_STORE_COUNTER_FILE="+counter)
	for _, kv := range env {
		if v, ok := strings.CutPrefix(kv, "BYWARD_STORE_DIR="); ok {
			stateDir = v
		}
	}
	switch st {
	case stateDirIsAFile:
		if err := os.WriteFile(stateDir, nil, 0o600); err != nil {
			t.Fatal(err)
		}
	case corruptStore:
		if err := os.MkdirAll(stateDir, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(stateDir, "byward.db"), bytes.Repeat([]byte("not a database "), 100), 0o600); err != nil {
			t.Fatal(err)
		}
	case proxysStore:
		s, err := sqlite.Open(context.Background(), sqlite.Options{Dir: stateDir, CounterFile: counter})
		if err != nil {
			t.Fatal(err)
		}
		if err := s.Close(); err != nil {
			t.Fatal(err)
		}
	}
	return env, stateDir, counter
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
// Stderr is pinned whole (outputMatches).
func TestStoreNewEpochExits2OnMisuseOrSQLiteAnd1WhenPostgreSQLIsUnreachable(t *testing.T) {
	pgtest.ClearEnv(t) // a host's PG* environment or ~/.postgresql would change how the DSN parses (#509)
	cases := []struct {
		name     string
		args     []string
		postgres bool
		code     int
		stderr   string
	}{
		{"no subcommand", []string{"store"}, true, exitConfig, newEpochUsage},
		{"without --yes", []string{"store", "new-epoch"}, true, exitConfig, newEpochUsage},
		{"with SQLite", []string{"store", "new-epoch", "--yes"}, false, exitConfig, newEpochNeedsPostgres},
		{"with PostgreSQL unreachable", []string{"store", "new-epoch", "--yes"}, true, exitRuntime,
			"byward: store new-epoch failed: BYWARD_STORE_POSTGRES_DSN_FILE: postgres store: connect or read schema version: {varies} (see docs/how-to/postgres.md)\n"},
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
			if code != tc.code || stdout != "" || !outputMatches(stderr, tc.stderr) {
				t.Fatalf("code %d (want %d), stdout %q\nstderr %q\nwant   %q", code, tc.code, stdout, stderr, tc.stderr)
			}
		})
	}
}

// revoke-user, revoke-all and store new-epoch take a stdio upstream after "--", as the proxy, check
// and doctor do, and do not start it (the marker check catches a start that runs before the command
// returns); a usage mistake before the "--", or SQLite for new-epoch, is still exit 2, with the
// store untouched.
func TestRevokeAndNewEpochTakeAStdioUpstreamAfterDashes(t *testing.T) {
	user := "00000000-0000-0000-0000-00000000000a:11111111-1111-1111-1111-11111111111a"
	cases := []struct {
		name   string
		args   []string
		code   int
		stdout string // the whole stdout: the store by its setting, never its path (#575)
		stderr string // the whole stderr of a command that is not done; "" for a done one
	}{
		{"revoke-user revokes the user", []string{"revoke-user", user, "--"}, exitOK, "revoked user " + user + " in BYWARD_STORE_DIR" + revoked, ""},
		{"revoke-all revokes every user", []string{"revoke-all", "--yes", "--"}, exitOK, "revoked every user in BYWARD_STORE_DIR" + revoked, ""},
		{"store new-epoch refuses SQLite", []string{"store", "new-epoch", "--yes", "--"}, exitConfig, "", newEpochNeedsPostgres},
		{"revoke-user without a key is a usage error", []string{"revoke-user", "--"}, exitConfig, "", revokeUserUsage},
		{"revoke-all without --yes is a usage error", []string{"revoke-all", "--"}, exitConfig, "", revokeAllUsage},
		{"store new-epoch without --yes is a usage error", []string{"store", "new-epoch", "--"}, exitConfig, "", newEpochUsage},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			script := filepath.Join(dir, "mcp-server")
			if err := os.WriteFile(script, []byte("#!/bin/sh\ntouch "+dir+"/ran\n"), 0o700); err != nil { //nolint:gosec // G306: an executable test command
				t.Fatal(err)
			}
			env := append(stdioAuthEnv(t), "BYWARD_PUBLIC_URL=https://m.example/mcp", "BYWARD_DATA_DIR="+dir, // the test's own, so no defaulted path reaches the host's
				"BYWARD_STORE_COUNTER_FILE="+filepath.Join(dir, "store-writes"))
			if tc.code == exitOK { // a revocation needs the store a proxy created (L152)
				s, err := sqlite.Open(context.Background(), sqlite.Options{Dir: setting(env, "BYWARD_STORE_DIR"), CounterFile: setting(env, "BYWARD_STORE_COUNTER_FILE")})
				if err != nil {
					t.Fatal(err)
				}
				if err := s.Close(); err != nil {
					t.Fatal(err)
				}
			}
			code, stdout, stderr := runWith(append(tc.args, script, "--flag"), env...)
			wantStdout := tc.stdout
			wantStderr := tc.stderr
			var okStderr bool
			if tc.code == exitOK { // a done command's stderr is its audit log, which must name the command
				wantStderr = `"reason":"operator ` + tc.args[0] + `"`
				okStderr = strings.Contains(stderr, wantStderr)
			} else {
				okStderr = outputMatches(stderr, wantStderr)
			}
			if code != tc.code || stdout != wantStdout || !okStderr {
				t.Fatalf("code %d (want %d)\nstdout %q\nwant   %q\nstderr %q\nwant   %q", code, tc.code, stdout, wantStdout, stderr, wantStderr)
			}
			if _, err := os.Stat(filepath.Join(dir, "ran")); err == nil {
				t.Fatal("the command started the stdio upstream")
			}
			store := setting(env, "BYWARD_STORE_DIR")
			if _, err := os.Stat(store); tc.code == exitConfig && !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("a refused command created the store at %s", store)
			}
		})
	}
}

// The operator commands' refusals, and the line tails several tests share, pinned as literals.
const (
	revokeUserUsage       = "byward: usage: byward revoke-user <user key> [-- stdio-upstream-command [args...]]\n"
	revokeAllUsage        = "byward: usage: byward revoke-all --yes [-- stdio-upstream-command [args...]] (signs every user out)\n"
	newEpochUsage         = "byward: usage: byward store new-epoch --yes [-- stdio-upstream-command [args...]] (refresh tokens from before it stop working)\n"
	newEpochNeedsPostgres = "byward: store new-epoch: new-epoch is for the PostgreSQL store (BYWARD_STORE_POSTGRES_DSN_FILE); the SQLite store finds a restore at startup from BYWARD_STORE_COUNTER_FILE (docs/how-to/state.md)\n"
	// storeMissing follows "BYWARD_STORE_DIR" when the state directory holds no store.
	storeMissing = ": no byward store there: byward.db is missing; run the command with the proxy's settings (see docs/how-to/state.md)\n"
	// revoked ends a revocation's success line, after the store's name.
	revoked = ": their grants are gone and their tokens stop working within seconds\n"
)

// outputMatches reports whether got is want, where one {varies} in want stands for text byward does
// not choose (a store driver's own words, a database's description): some text, not none, on that
// one line.
func outputMatches(got, want string) bool {
	start, end, ok := strings.Cut(want, "{varies}")
	if !ok {
		return got == want
	}
	if len(got) < len(start)+len(end) || !strings.HasPrefix(got, start) || !strings.HasSuffix(got, end) {
		return false
	}
	varied := got[len(start) : len(got)-len(end)]
	return varied != "" && !strings.Contains(varied, "\n")
}

// outputMatches pins all of an output but its one {varies}, which must hold some text and stay on
// its line.
func TestOutputMatchesLeavesOnlyItsPlaceholderFree(t *testing.T) {
	for _, tc := range []struct {
		got, want string
		match     bool
	}{
		{"a: x\n", "a: x\n", true},
		{"a: x\n", "a: y\n", false},
		{"a: x\n", "a: x\n\n", false},
		{"a: x\nmore\n", "a: x\n", false}, // a line after, no placeholder
		{"a: cause (see b)\n", "a: {varies} (see b)\n", true},
		{"b: cause (see b)\n", "a: {varies} (see b)\n", false},       // another start
		{"a:  (see b)\n", "a: {varies} (see b)\n", false},            // no text in its place
		{"a: one\ntwo (see b)\n", "a: {varies} (see b)\n", false},    // a second line in its place
		{"a: cause (see b)\nmore\n", "a: {varies} (see b)\n", false}, // a line after
		{"a: cause (see b)", "a: {varies} (see b)\n", false},         // no newline
		{"a: (see b)\n", "a: {varies}: (see b)\n", false},            // start and end overlap
		{"", "a: {varies}\n", false},                                 // nothing at all
	} {
		if got := outputMatches(tc.got, tc.want); got != tc.match {
			t.Errorf("outputMatches(%q, %q) = %v, want %v", tc.got, tc.want, got, tc.match)
		}
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
			want := "byward: " + tc.name + ": the broker's store is off with BYWARD_INSECURE_NO_AUTH, so there is nothing to revoke and no store epoch to start\n"
			if code != exitConfig || stdout != "" || stderr != want {
				t.Fatalf("code %d (want %d), stdout %q, stderr %q (want %q)", code, exitConfig, stdout, stderr, want)
			}
		})
	}
}

// Settings that do not load stop revoke-user, revoke-all and store new-epoch with exit 2 and the
// line the proxy gives for them.
func TestOperatorCommandsRefuseSettingsThatDoNotLoad(t *testing.T) {
	const want = "byward: configuration error: unknown setting BYWARD_PUBLC_URL (did you mean BYWARD_PUBLIC_URL?)\n"
	for _, tc := range []struct {
		name string
		args []string
	}{
		{"revoke-user", []string{"revoke-user", "00000000-0000-0000-0000-00000000000a:11111111-1111-1111-1111-11111111111a"}},
		{"revoke-all", []string{"revoke-all", "--yes"}},
		{"store new-epoch", []string{"store", "new-epoch", "--yes"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			code, stdout, stderr := runWith(tc.args, "BYWARD_PUBLC_URL=https://m.example/mcp")
			if code != exitConfig || stdout != "" || stderr != want {
				t.Fatalf("code %d (want %d), stdout %q\nstderr %q\nwant   %q", code, exitConfig, stdout, stderr, want)
			}
		})
	}
}

// Settings revoke-user cannot build the IdP from (here an Entra certificate file that holds no key)
// are a configuration error, exit 2, with the line check --offline gives for them, as at startup
// (ADR-0020 §5, L174); before, revoke-user reported them as a failed revocation, exit 1.
func TestRevokeUserIsAConfigurationErrorForIdPSettingsStartupRefuses(t *testing.T) {
	cert := filepath.Join(t.TempDir(), "cert.pem")
	if err := os.WriteFile(cert, []byte("not a certificate"), 0o600); err != nil {
		t.Fatal(err)
	}
	env := append(authEnv(t), "BYWARD_PUBLIC_URL=https://m.example/mcp", "BYWARD_UPSTREAM_URL=http://u/mcp",
		"BYWARD_ENTRA_CLIENT_SECRET_FILE=", "BYWARD_ENTRA_CLIENT_CERTIFICATE_FILE="+cert)
	checkCode, _, checkStderr := runWith([]string{"check", "--offline"}, env...)
	want := lastLine(checkStderr)
	if checkCode != exitConfig || !strings.HasPrefix(want, "byward: configuration error: BYWARD_ENTRA_CLIENT_CERTIFICATE_FILE: ") {
		t.Fatalf("check --offline: code %d, stderr %q; the test expects these settings refused as a configuration error", checkCode, checkStderr)
	}
	code, stdout, stderr := runWith([]string{"revoke-user", "00000000-0000-0000-0000-00000000000a:11111111-1111-1111-1111-11111111111a"}, env...)
	if code != exitConfig || stdout != "" || stderr != want+"\n" {
		t.Fatalf("revoke-user: code %d (want %d), stdout %q, stderr %q; want only %q", code, exitConfig, stdout, stderr, want)
	}
}

// lastLine is the last line of out, without its newline.
func lastLine(out string) string {
	lines := strings.Split(strings.TrimSuffix(out, "\n"), "\n")
	return lines[len(lines)-1]
}

// An OTEL_TRACES_EXPORTER that autoexport does not know stops the process as a configuration error,
// on the last line, after the startup log.
func TestAnUnknownOTELTracesExporterIsAConfigError(t *testing.T) {
	// Blank the host's OTEL_* so only this test's setting reaches autoexport. autoexport reads the
	// process environment, while run's getenv reads only the environ it is passed: set the exporter
	// in both.
	blankOTELEnv(t)
	t.Setenv("OTEL_TRACES_EXPORTER", "bogus")
	t.Cleanup(func() {
		otel.SetErrorHandler(otel.ErrorHandlerFunc(func(error) {}))
		otel.SetLogger(logr.Discard())
	})
	env := append(authEnv(t), serveEnv("https://m.example/mcp", "127.0.0.1:0")...)
	code, _, stderr := runWith(nil, append(env, "OTEL_TRACES_EXPORTER=bogus")...)
	// The reason is the exporter's own (tracing.NewExporter's error), as check gives it (L157).
	_, reason := tracing.NewExporter(context.Background(), os.Getenv, slog.New(slog.DiscardHandler))
	if reason == nil {
		t.Fatal("tracing.NewExporter accepts OTEL_TRACES_EXPORTER=bogus; the test expects a refusal")
	}
	want := "byward: configuration error: OTEL_* tracing settings: " + reason.Error()
	lines := strings.Split(strings.TrimSuffix(stderr, "\n"), "\n")
	if code != exitConfig || !strings.HasSuffix(stderr, "\n") || len(lines) < 2 || lines[len(lines)-1] != want {
		t.Fatalf("code=%d stderr=%q; want exit %d and a last line, after the startup log, %q", code, stderr, exitConfig, want)
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

// blankOTELEnv blanks every OTEL_* variable for the test: autoexport reads the process environment,
// a developer's settings too.
func blankOTELEnv(t *testing.T) {
	t.Helper()
	for _, kv := range os.Environ() {
		if k, _, _ := strings.Cut(kv, "="); strings.HasPrefix(k, "OTEL_") {
			t.Setenv(k, "")
		}
	}
}

// revoke-user prints a user key that looks like a credential (logging.LooksSecret) only by its length
// in characters, under any subject claim, and says a pasted token revoked nothing (#594). Such a key
// is still revoked: a sub such as eyJohn.Smith, or a name such as "Ann Basic Lee", is a real user's.
// Any other key is printed as given.
func TestRevokeUserNamesACredentialShapedKeyOnlyByItsLength(t *testing.T) {
	const hint = "if you pasted a token, it revoked nothing: no user has that key\n"
	for _, tc := range []struct {
		claim, key string
		hidden     string // the key as the line names it; "" when it is shown in full
	}{
		{"sub", "eyJohn.Smith", "(12 characters, not shown)"},
		{"sub", "eyJohn.Smith ", "(12 characters, not shown)"}, // judged trimmed: untrimmed, it no longer looks like one
		{"sub", "eyJhbGciOiJSUzI1NiJ9." + canary + ".c2ln", "(35 characters, not shown)"},
		{"sub", "f47ac10b-58cc-4372-a567-0e02b2c3d479", ""},
		{"name", "Ann Basic Lee", "(13 characters, not shown)"},
		{"name", "Ånn Basic Lee", "(13 characters, not shown)"},
		{"email", "heyJoe.Smith.Jr@example.com", "(27 characters, not shown)"},
		{"email", "jöhn@exämple.com", ""},
		{"name", "José", ""},
		{"sub", "ghp_" + canary + "Q7Q7Q7", "(19 characters, not shown)"}, // the catalogue's kinds (#657)
		{"sub", "xoxb-" + canary + "-12345", "(20 characters, not shown)"},
		{"sub", "postgres://u:" + canary + "@h", "(24 characters, not shown)"},
	} {
		t.Run(tc.claim+"/"+tc.key, func(t *testing.T) {
			env, _, _ := operatorEnv(t, proxysStore)
			env = keycloakOperatorEnv(env, "BYWARD_OIDC_SUBJECT_CLAIM="+tc.claim)
			code, stdout, stderr := runWith([]string{"revoke-user", tc.key}, env...)
			want := "revoked user " + tc.key + " in BYWARD_STORE_DIR" + revoked
			if tc.hidden != "" {
				want = "revoked user " + tc.hidden + ", a key that looks like a credential, in BYWARD_STORE_DIR" + revoked + hint
			}
			if code != exitOK || stdout != want {
				t.Fatalf("code %d, stdout %q, stderr %q; want exit 0 and %q", code, stdout, stderr, want)
			}
			if tc.hidden != "" && strings.Contains(stdout+stderr, strings.TrimSpace(tc.key)) {
				t.Errorf("the key is shown: stdout %q, stderr %q", stdout, stderr)
			}
		})
	}
}
