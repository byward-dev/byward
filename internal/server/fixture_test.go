package server

import (
	"crypto/rand"
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"
)

// authEnv writes a key directory, a static-clients file and an IdP secret into a temp dir and
// returns the settings that point at them.
func authEnv(t testing.TB) []string {
	t.Helper()
	dir := t.TempDir()
	keys := filepath.Join(dir, "keys")
	if err := os.Mkdir(keys, 0o700); err != nil {
		t.Fatal(err)
	}
	k := make([]byte, 32)
	_, _ = rand.Read(k)
	write := func(p, content string) {
		if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write(filepath.Join(keys, "2026-11-06"), base64.StdEncoding.EncodeToString(k))
	write(filepath.Join(dir, "clients.json"), `{"clients":[{"client_id":"test-app","client_name":"Test app","token_endpoint_auth_method":"none","redirect_uris":["http://127.0.0.1/callback"]}]}`)
	write(filepath.Join(dir, "secret"), "s3cret-entra")
	return []string{
		"MCP_AUTHPROXY_ENTRA_TENANT=00000000-0000-0000-0000-000000000001",
		"MCP_AUTHPROXY_ENTRA_CLIENT_ID=00000000-0000-0000-0000-000000000002",
		"MCP_AUTHPROXY_ENTRA_CLIENT_SECRET_FILE=" + filepath.Join(dir, "secret"),
		"MCP_AUTHPROXY_KEYS_DIR=" + keys,
		"MCP_AUTHPROXY_STATIC_CLIENTS_FILE=" + filepath.Join(dir, "clients.json"),
	}
}
