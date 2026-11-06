package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

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
	return []string{"MCP_AUTHPROXY_ENTRA_TENANT=00000000-0000-0000-0000-000000000001", "MCP_AUTHPROXY_ENTRA_CLIENT_ID=00000000-0000-0000-0000-000000000002",
		"MCP_AUTHPROXY_ENTRA_CLIENT_SECRET_FILE=" + filepath.Join(dir, "secret"), "MCP_AUTHPROXY_KEYS_DIR=" + keys,
		"MCP_AUTHPROXY_STATIC_CLIENTS_FILE=" + filepath.Join(dir, "clients.json")}
}

func TestConfigErrorExitCode(t *testing.T) {
	code, _, stderr := runWith(nil, "MCP_AUTHPROXY_PUBLC_URL=x")
	if code != exitConfig || !strings.Contains(stderr, "did you mean MCP_AUTHPROXY_PUBLIC_URL?") {
		t.Fatalf("code=%d stderr=%q", code, stderr)
	}
}

func TestHelp(t *testing.T) {
	code, stdout, _ := runWith([]string{"--help"})
	if code != exitOK || !strings.Contains(stdout, "MCP_AUTHPROXY_UPSTREAM_URL") {
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
		append(authEnv(t), "MCP_AUTHPROXY_PUBLIC_URL=https://m.example/mcp", "MCP_AUTHPROXY_UPSTREAM_URL=http://u/mcp")...)
	for _, want := range []string{"MCP_AUTHPROXY_LISTEN=127.0.0.1:9 (flag)", "MCP_AUTHPROXY_PUBLIC_URL=https://m.example/mcp (env)", "MCP_AUTHPROXY_SCOPE=mcp (default)"} {
		if !strings.Contains(stdout, want) {
			t.Fatalf("code=%d missing %q in %q", code, want, stdout)
		}
	}
}

func TestRunStopsOnCancelledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var out, errb bytes.Buffer
	code := run(ctx, nil, append(authEnv(t), "MCP_AUTHPROXY_PUBLIC_URL=https://m.example/mcp", "MCP_AUTHPROXY_UPSTREAM_URL=http://u/mcp", "MCP_AUTHPROXY_LISTEN=127.0.0.1:0", "MCP_AUTHPROXY_INTERNAL_LISTEN=127.0.0.1:0"), &out, &errb)
	if code != exitOK || !strings.Contains(errb.String(), `"msg":"starting"`) {
		t.Fatalf("code=%d logs=%s", code, errb.String())
	}
}

func TestDevModeLogsEachRelaxation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var out, errb bytes.Buffer
	code := run(ctx, []string{"--dev"}, append(authEnv(t), "MCP_AUTHPROXY_PUBLIC_URL=http://127.0.0.1:8080/mcp", "MCP_AUTHPROXY_UPSTREAM_URL=http://u/mcp", "MCP_AUTHPROXY_LISTEN=127.0.0.1:0", "MCP_AUTHPROXY_INTERNAL_LISTEN=127.0.0.1:0"), &out, &errb)
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
	code, _, stderr := runWith(nil, append(authEnv(t), "MCP_AUTHPROXY_PUBLIC_URL=https://m.example/mcp", "MCP_AUTHPROXY_UPSTREAM_URL=http://u/mcp", "MCP_AUTHPROXY_LISTEN="+ln.Addr().String(), "MCP_AUTHPROXY_INTERNAL_LISTEN=127.0.0.1:0")...)
	if code != exitRuntime || !strings.Contains(stderr, "address already in use") {
		t.Fatalf("code=%d stderr=%s", code, stderr)
	}
}

func TestNoAuthLogsThatAuthIsOffAndTheNextStep(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var out, errb bytes.Buffer
	code := run(ctx, nil, []string{"MCP_AUTHPROXY_INSECURE_NO_AUTH=true", "MCP_AUTHPROXY_PUBLIC_URL=http://localhost:8080/mcp", "MCP_AUTHPROXY_UPSTREAM_URL=http://u/mcp", "MCP_AUTHPROXY_LISTEN=127.0.0.1:0", "MCP_AUTHPROXY_INTERNAL_LISTEN=127.0.0.1:0"}, &out, &errb)
	logs := errb.String()
	if code != exitOK || !strings.Contains(logs, `"level":"WARN","msg":"development mode relaxation","relaxation":"AUTHENTICATION IS OFF: anyone who can reach http://localhost:8080/mcp`) || !strings.Contains(logs, "to require sign-in") {
		t.Fatalf("code=%d logs=%s", code, logs)
	}
}
