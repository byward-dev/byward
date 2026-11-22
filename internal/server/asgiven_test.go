package server

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/byward-dev/byward/internal/config"
)

// A credential or store file whose content is refused is named as the operator gave it: its file
// flag, or its file variable (#619).
func TestARefusedFileIsNamedAsGiven(t *testing.T) {
	file := func(content string) string {
		p := filepath.Join(t.TempDir(), "f")
		if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	without := func(env []string, prefixes ...string) []string {
		return slices.DeleteFunc(env, func(kv string) bool {
			return slices.ContainsFunc(prefixes, func(p string) bool { return strings.HasPrefix(kv, p+"=") })
		})
	}
	served := []string{"BYWARD_PUBLIC_URL=https://mcp.example.com/mcp", "BYWARD_UPSTREAM_URL=http://u/mcp"}
	entra := func() []string { return append(without(authEnv(t), "BYWARD_ENTRA_CLIENT_SECRET_FILE"), served...) }
	oidcEnv := append([]string{"BYWARD_IDP=keycloak", "BYWARD_OIDC_ISSUER=https://sso.example.com/realms/acme", "BYWARD_OIDC_CLIENT_ID=byward"}, served...)
	store := func() []string {
		return append(without(authEnv(t), "BYWARD_STORE_DIR", "BYWARD_STORE_COUNTER_FILE"), served...)
	}
	entraRefuses := func(cfg *config.Config) error { _, _, _, err := entraClientAuth(cfg); return err }
	oidcRefuses := func(cfg *config.Config) error { _, _, err := oidcClientAuth(cfg); return err }
	storeRefuses := func(cfg *config.Config) error { _, err := checkStore(cfg); return err }
	cert, key, dsn := file("not a certificate\n"), file("not a key\n"), file("postgres://byward@db.example/byward\n")
	for _, tc := range []struct {
		name   string
		args   []string
		env    []string
		refuse func(*config.Config) error
		want   string
	}{
		{"an Entra certificate, by env", nil, append(entra(), "BYWARD_ENTRA_CLIENT_CERTIFICATE_FILE="+cert), entraRefuses, "BYWARD_ENTRA_CLIENT_CERTIFICATE_FILE: "},
		{"an Entra certificate, by flag", []string{"--entra-client-certificate-file=" + cert}, entra(), entraRefuses, "--entra-client-certificate-file: "},
		{"an OIDC client key, by env", nil, append(slices.Clone(oidcEnv), "BYWARD_OIDC_CLIENT_KEY_FILE="+key), oidcRefuses, "BYWARD_OIDC_CLIENT_KEY_FILE: "},
		{"an OIDC client key, by flag", []string{"--oidc-client-key-file=" + key}, slices.Clone(oidcEnv), oidcRefuses, "--oidc-client-key-file: "},
		{"a PostgreSQL DSN, by env", nil, append(store(), "BYWARD_STORE_POSTGRES_DSN_FILE="+dsn), storeRefuses, "BYWARD_STORE_POSTGRES_DSN_FILE: "},
		{"a PostgreSQL DSN, by flag", []string{"--store-postgres-dsn-file=" + dsn}, store(), storeRefuses, "--store-postgres-dsn-file: "},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg, _, err := config.Load(tc.args, tc.env, os.ReadFile)
			if err != nil {
				t.Fatal(err)
			}
			if err := tc.refuse(cfg); err == nil || !strings.HasPrefix(err.Error(), tc.want) {
				t.Fatalf("err = %v, want it to start with %q", err, tc.want)
			}
		})
	}
}
