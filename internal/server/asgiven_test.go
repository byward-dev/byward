package server

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/byward-dev/byward/internal/config"
	"github.com/byward-dev/byward/internal/testutil/fakeidp"
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
	weak := file(string(fakeidp.PrivateKeyPEM(t, weakRSAKey(t)))) // parses, but cannot sign: refused after parsing
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
		{"a weak OIDC client key, by env", nil, append(slices.Clone(oidcEnv), "BYWARD_OIDC_CLIENT_KEY_FILE="+weak), oidcRefuses, "BYWARD_OIDC_CLIENT_KEY_FILE: idp: a 1024-bit RSA key"},
		{"a weak OIDC client key, by flag", []string{"--oidc-client-key-file=" + weak}, slices.Clone(oidcEnv), oidcRefuses, "--oidc-client-key-file: idp: a 1024-bit RSA key"},
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

// A path setting's file or directory that cannot be used is named as the operator gave it, flag or
// variable, in every refusal that names it (#619); a setting left at its default keeps its variable.
func TestAPathSettingThatCannotBeUsedIsNamedAsGiven(t *testing.T) {
	dropping := func(env []string, vars ...string) []string {
		return slices.DeleteFunc(env, func(kv string) bool {
			return slices.ContainsFunc(vars, func(v string) bool { return strings.HasPrefix(kv, v+"=") })
		})
	}
	served := []string{"BYWARD_PUBLIC_URL=https://mcp.example.com/mcp", "BYWARD_UPSTREAM_URL=http://u/mcp"}
	write := func(content string, mode os.FileMode) string {
		p := filepath.Join(t.TempDir(), "f")
		if err := os.WriteFile(p, []byte(content), mode); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(p, mode); err != nil {
			t.Fatal(err)
		}
		return p
	}
	missing := filepath.Join(t.TempDir(), "missing")
	loose := func(cfg *config.Config) error { return errors.Join(looseSecretFiles(cfg)...) }
	auth := func(cfg *config.Config) error { _, err := loadAuthParts(cfg, nil); return err }
	pair := func(cfg *config.Config) error { _, err := diskCert(cfg); return err }
	keys := func(cfg *config.Config) error { _, err := assertionKeys(cfg); return err }
	store := func(cfg *config.Config) error { _, err := checkStore(cfg); return err }
	for _, tc := range []struct {
		name   string
		base   []string          // the environment, without the settings under test
		set    map[string]string // the settings under test, by name, given all by env or all by flag
		refuse func(*config.Config) error
		want   func(by func(string) string) string // the message's start, naming each setting by by
	}{
		{"a TLS key others can read", dropping(authEnv(t)), map[string]string{"tls-cert-file": write("x", 0o600), "tls-key-file": write("x", 0o644)}, loose,
			func(by func(string) string) string { return by("tls-key-file") + ": " }},
		{"a TLS pair that cannot be read", dropping(authEnv(t)), map[string]string{"tls-cert-file": write("not a certificate", 0o600), "tls-key-file": write("not a key", 0o600)}, pair,
			func(by func(string) string) string { return by("tls-cert-file") + " / " + by("tls-key-file") + ": " }},
		{"a missing federated token file", dropping(authEnv(t), "BYWARD_ENTRA_CLIENT_SECRET_FILE"), map[string]string{"entra-federated-token-file": missing}, loose,
			func(by func(string) string) string { return by("entra-federated-token-file") + ": " }},
		{"a missing sealing key directory", dropping(authEnv(t), "BYWARD_KEYS_DIR"), map[string]string{"keys-dir": missing}, auth,
			func(by func(string) string) string { return by("keys-dir") + ": " }},
		{"a missing static clients file", dropping(authEnv(t), "BYWARD_STATIC_CLIENTS_FILE"), map[string]string{"static-clients-file": missing}, auth,
			func(by func(string) string) string { return by("static-clients-file") + ": " }},
		{"a missing assertion key directory", dropping(authEnv(t), "BYWARD_ASSERTION_KEYS_DIR"), map[string]string{"assertion-keys-dir": missing}, keys,
			func(by func(string) string) string { return by("assertion-keys-dir") + ": " }},
		{"a state directory that is a file", dropping(authEnv(t), "BYWARD_STORE_DIR", "BYWARD_STORE_COUNTER_FILE"), map[string]string{"store-dir": write("", 0o600)}, store,
			func(by func(string) string) string { return by("store-dir") + " / BYWARD_STORE_COUNTER_FILE: " }},
	} {
		for _, byFlag := range []bool{false, true} {
			by := func(n string) string { return config.Setting{Name: n}.Env() }
			var args []string
			env := append(slices.Clone(tc.base), served...)
			if byFlag {
				by = func(n string) string { return "--" + n }
			}
			for n, v := range tc.set {
				if byFlag {
					args = append(args, "--"+n+"="+v)
				} else {
					env = append(env, config.Setting{Name: n}.Env()+"="+v)
				}
			}
			t.Run(fmt.Sprintf("%s, by flag %v", tc.name, byFlag), func(t *testing.T) {
				cfg, _, err := config.Load(args, env, os.ReadFile)
				if err != nil {
					t.Fatal(err)
				}
				if want := tc.want(by); func() bool { err := tc.refuse(cfg); return err == nil || !strings.HasPrefix(err.Error(), want) }() {
					t.Fatalf("err = %v, want it to start with %q", tc.refuse(cfg), want)
				}
			})
		}
	}
}

// The credential doctor names in its fixes is named as the operator gave it (#619): the diagnosis of
// the Entra and the OIDC client carries the flag or the variable.
func TestTheDiagnosedCredentialIsNamedAsGiven(t *testing.T) {
	secret := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(secret, []byte("s3cret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	key := filepath.Join(t.TempDir(), "key.pem")
	if err := os.WriteFile(key, fakeidp.PrivateKeyPEM(t, weakRSAKey(t)), 0o600); err != nil {
		t.Fatal(err)
	}
	served := []string{"BYWARD_PUBLIC_URL=https://mcp.example.com/mcp", "BYWARD_UPSTREAM_URL=http://u/mcp"}
	entra := func() []string {
		return append(slices.DeleteFunc(authEnv(t), func(kv string) bool { return strings.HasPrefix(kv, "BYWARD_ENTRA_CLIENT_SECRET_FILE=") }), served...)
	}
	oidcEnv := append([]string{"BYWARD_IDP=keycloak", "BYWARD_OIDC_ISSUER=https://sso.example.com/realms/acme", "BYWARD_OIDC_CLIENT_ID=byward"}, served...)
	entraSetting := func(cfg *config.Config) string { _, d, _, _ := entraClientAuth(cfg); return d.CredentialSetting }
	oidcSetting := func(cfg *config.Config) string { return oidcDiagnosis(cfg).CredentialSetting }
	for _, tc := range []struct {
		name    string
		args    []string
		env     []string
		setting func(*config.Config) string
		want    string
	}{
		{"an Entra secret, by env", nil, append(entra(), "BYWARD_ENTRA_CLIENT_SECRET_FILE="+secret), entraSetting, "BYWARD_ENTRA_CLIENT_SECRET_FILE"},
		{"an Entra secret, by flag", []string{"--entra-client-secret-file=" + secret}, entra(), entraSetting, "--entra-client-secret-file"},
		{"an Entra federated token, by env", nil, append(entra(), "BYWARD_ENTRA_FEDERATED_TOKEN_FILE="+secret), entraSetting, "BYWARD_ENTRA_FEDERATED_TOKEN_FILE"},
		{"an Entra federated token, by flag", []string{"--entra-federated-token-file=" + secret}, entra(), entraSetting, "--entra-federated-token-file"},
		{"an OIDC secret, by env", nil, append(slices.Clone(oidcEnv), "BYWARD_OIDC_CLIENT_SECRET_FILE="+secret), oidcSetting, "BYWARD_OIDC_CLIENT_SECRET_FILE"},
		{"an OIDC secret, by flag", []string{"--oidc-client-secret-file=" + secret}, slices.Clone(oidcEnv), oidcSetting, "--oidc-client-secret-file"},
		{"an OIDC key, by env", nil, append(slices.Clone(oidcEnv), "BYWARD_OIDC_CLIENT_KEY_FILE="+key), oidcSetting, "BYWARD_OIDC_CLIENT_KEY_FILE"},
		{"an OIDC key, by flag", []string{"--oidc-client-key-file=" + key}, slices.Clone(oidcEnv), oidcSetting, "--oidc-client-key-file"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg, _, err := config.Load(tc.args, tc.env, os.ReadFile)
			if err != nil {
				t.Fatal(err)
			}
			if got := tc.setting(cfg); got != tc.want {
				t.Fatalf("CredentialSetting = %q, want %q", got, tc.want)
			}
		})
	}
}
