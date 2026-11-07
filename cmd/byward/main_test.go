package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/byward-dev/byward/internal/testutil/assertionkey"
)

// serveEnv is what a test run that serves needs besides auth: the URLs, the public listener and an
// ephemeral internal listener (the default 127.0.0.1:9090 may be taken on the test host).
func serveEnv(publicURL, listen string) []string {
	return []string{"BYWARD_PUBLIC_URL=" + publicURL, "BYWARD_UPSTREAM_URL=http://u/mcp",
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
	keys := filepath.Join(dir, "keys")
	k := make([]byte, 32)
	_, _ = rand.Read(k)
	for p, c := range map[string]string{
		filepath.Join(keys, "k1"):          base64.StdEncoding.EncodeToString(k),
		filepath.Join(dir, "clients.json"): `{"clients":[{"client_id":"test-app","client_name":"Test app","token_endpoint_auth_method":"none","redirect_uris":["http://127.0.0.1/callback"]}]}`,
		filepath.Join(dir, "secret"):       "s3cret-entra",
	} {
		_ = os.MkdirAll(filepath.Dir(p), 0o700)
		if err := os.WriteFile(p, []byte(c), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return []string{"BYWARD_ENTRA_TENANT=00000000-0000-0000-0000-000000000001", "BYWARD_ENTRA_CLIENT_ID=00000000-0000-0000-0000-000000000002",
		"BYWARD_ENTRA_CLIENT_SECRET_FILE=" + filepath.Join(dir, "secret"), "BYWARD_KEYS_DIR=" + keys,
		"BYWARD_STATIC_CLIENTS_FILE=" + filepath.Join(dir, "clients.json"),
		"BYWARD_STORE_DIR=" + filepath.Join(dir, "state"), "BYWARD_ASSERTION_KEYS_DIR=" + assertionkey.Dir(t)}
}

func TestConfigErrorExitCode(t *testing.T) {
	code, _, stderr := runWith(nil, "BYWARD_PUBLC_URL=x")
	if code != exitConfig || !strings.Contains(stderr, "did you mean BYWARD_PUBLIC_URL?") {
		t.Fatalf("code=%d stderr=%q", code, stderr)
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
		append(authEnv(t), "BYWARD_PUBLIC_URL=https://m.example/mcp", "BYWARD_UPSTREAM_URL=http://u/mcp")...)
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

func TestDevModeLogsEachRelaxation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var out, errb bytes.Buffer
	code := run(ctx, []string{"--dev"}, append(authEnv(t), serveEnv("http://127.0.0.1:8080/mcp", "127.0.0.1:0")...), &out, &errb)
	if code != exitOK || !strings.Contains(errb.String(), "development mode relaxation") || !strings.Contains(errb.String(), "http public URL on loopback") {
		t.Fatalf("code=%d logs=%s", code, errb.String())
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
			env := append(authEnv(t), "BYWARD_PUBLIC_URL=https://m.example/mcp", "BYWARD_UPSTREAM_URL=http://u/mcp")
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
	if code != exitOK || !strings.Contains(stdout, "byward revoke-user <user key>") || !strings.Contains(stdout, "byward revoke-all --yes") {
		t.Fatalf("code=%d help=%q", code, stdout)
	}
}
