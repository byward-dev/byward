package server

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/go-jose/go-jose/v4"

	"github.com/byward-dev/byward/internal/config"
)

// setting returns the value of name in env.
func setting(env []string, name string) string {
	for _, kv := range env {
		if v, ok := strings.CutPrefix(kv, name+"="); ok {
			return v
		}
	}
	return ""
}

func TestSecretFilesOthersCanReadRefuseToStartOutsideDev(t *testing.T) {
	entraSecret := func(t *testing.T, env []string) {
		if err := os.Chmod(setting(env, "BYWARD_ENTRA_CLIENT_SECRET_FILE"), 0o644); err != nil { //nolint:gosec // G302: the mode under test
			t.Fatal(err)
		}
	}
	staticSecret := func(t *testing.T, env []string) {
		clients := setting(env, "BYWARD_STATIC_CLIENTS_FILE")
		secret := filepath.Join(filepath.Dir(clients), "app-secret")
		if err := os.WriteFile(secret, []byte(strings.Repeat("x", 32)), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(secret, 0o644); err != nil { //nolint:gosec // G302: the mode under test
			t.Fatal(err)
		}
		body := `{"clients":[{"client_id":"svc","client_name":"Service","token_endpoint_auth_method":"client_secret_basic","client_secret_file":"app-secret","redirect_uris":["http://127.0.0.1/callback"]}]}`
		if err := os.WriteFile(clients, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	both := func(t *testing.T, env []string) { entraSecret(t, env); staticSecret(t, env) }
	cases := []struct {
		name      string
		loosen    func(*testing.T, []string)
		wantNames []string
	}{
		{"Entra client secret", entraSecret, []string{"BYWARD_ENTRA_CLIENT_SECRET_FILE"}},
		{"static client secret", staticSecret, []string{"client_secret_file"}},
		{"both at once: one start names every loose file", both, []string{"BYWARD_ENTRA_CLIENT_SECRET_FILE", "client_secret_file"}},
	}
	for _, c := range cases {
		for _, dev := range []bool{false, true} {
			env := append(authEnv(t), "BYWARD_PUBLIC_URL=https://mcp.example.com/mcp", "BYWARD_UPSTREAM_URL=http://u/mcp")
			if dev {
				env = append(env, "BYWARD_DEV=true")
			}
			c.loosen(t, env)
			cfg, _, err := config.Load(nil, env, os.ReadFile)
			if err != nil {
				t.Fatal(err)
			}
			s, err := New(cfg, slog.New(slog.DiscardHandler))
			switch {
			case dev && err != nil:
				t.Errorf("%s at 0644 with --dev: %v, want it relaxed", c.name, err)
			case !dev && err == nil:
				t.Errorf("%s at 0644: started, want a refusal", c.name)
			case !dev:
				for _, want := range append(c.wantNames, "0644") {
					if !strings.Contains(err.Error(), want) {
						t.Errorf("%s at 0644: err = %v, want it to name %s", c.name, err, want)
					}
				}
			}
			if s != nil && s.closeStore != nil {
				_ = s.closeStore()
			}
		}
	}
}

// A JWKS file holds public keys, so a world-readable one is normal and must not be refused.
func TestWorldReadableJWKSFileIsNotTreatedAsASecret(t *testing.T) {
	env := append(authEnv(t), "BYWARD_PUBLIC_URL=https://mcp.example.com/mcp", "BYWARD_UPSTREAM_URL=http://u/mcp")
	clients := setting(env, "BYWARD_STATIC_CLIENTS_FILE")
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	jwks, err := json.Marshal(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &key.PublicKey, KeyID: "k1", Use: "sig", Algorithm: "PS256"}}})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(filepath.Dir(clients), "jwks.json")
	if err := os.WriteFile(path, jwks, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o644); err != nil { //nolint:gosec // G302: public keys, world-readable on purpose
		t.Fatal(err)
	}
	body := `{"clients":[{"client_id":"svc","client_name":"Service","token_endpoint_auth_method":"private_key_jwt","jwks_file":"jwks.json","redirect_uris":["http://127.0.0.1/callback"]}]}`
	if err := os.WriteFile(clients, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, _, err := config.Load(nil, env, os.ReadFile)
	if err != nil {
		t.Fatal(err)
	}
	s, err := New(cfg, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatalf("a 0644 JWKS file refused the start: %v", err)
	}
	if s.closeStore != nil {
		_ = s.closeStore()
	}
}
