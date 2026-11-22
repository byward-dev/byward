package server

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/byward-dev/byward/internal/config"
	"github.com/byward-dev/byward/internal/testutil/fakeidp"
	"github.com/byward-dev/byward/internal/testutil/testcert"
)

// A credential or store file whose content is refused is named as the operator gave it: its file
// flag, or its file variable (#619). So is a key algorithm the client key cannot sign with.
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
	rsa := file(string(fakeidp.PrivateKeyPEM(t, fakeidp.NewCertificate(t).Key)))
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
		{"an OIDC key algorithm the key cannot sign with, by env", nil, append(slices.Clone(oidcEnv), "BYWARD_OIDC_CLIENT_KEY_FILE="+rsa, "BYWARD_OIDC_CLIENT_KEY_ALG=ES256"), oidcRefuses, "BYWARD_OIDC_CLIENT_KEY_ALG: "},
		{"an OIDC key algorithm the key cannot sign with, by flag", []string{"--oidc-client-key-alg=ES256"}, append(slices.Clone(oidcEnv), "BYWARD_OIDC_CLIENT_KEY_FILE="+rsa), oidcRefuses, "--oidc-client-key-alg: "},
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
// variable, in every refusal and warning that names it (#619); a setting left at its default keeps its
// variable.
func TestAPathSettingThatCannotBeUsedIsNamedAsGiven(t *testing.T) {
	dropping := func(env []string, vars ...string) []string {
		return append(slices.DeleteFunc(env, func(kv string) bool {
			return slices.ContainsFunc(vars, func(v string) bool { return strings.HasPrefix(kv, v+"=") })
		}), "BYWARD_PUBLIC_URL=https://mcp.example.com/mcp", "BYWARD_UPSTREAM_URL=http://u/mcp")
	}
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
	cert, looseKey := write("x", 0o600), write("x", 0o644)
	badCert, badKey := write("not a certificate", 0o600), write("not a key", 0o600)
	stateFile, counter := write("", 0o600), filepath.Join(t.TempDir(), "store-writes")
	otherCert, otherKey := testcert.Issue(t, testcert.Options{Hosts: []string{"other.example.com"}, Leaf: testcert.Valid(time.Now(), 90)}).Write(t, t.TempDir())
	loose := func(cfg *config.Config) error { return errors.Join(looseSecretFiles(cfg)...) }
	auth := func(cfg *config.Config) error { _, err := loadAuthParts(cfg, nil); return err }
	pair := func(cfg *config.Config) error { _, err := diskCert(cfg); return err }
	keys := func(cfg *config.Config) error { _, err := assertionKeys(cfg); return err }
	check := func(cfg *config.Config) error { _, err := checkStore(cfg); return err }
	open := func(cfg *config.Config) error { _, err := openStoreFor(cfg, discard, nil, false); return err }
	openExisting := func(cfg *config.Config) error { _, err := openExistingStore(cfg, discard, nil); return err }
	warns := func(cfg *config.Config) error { // the first startup warning, as "Setting: Message"
		p, err := diskCert(cfg)
		if err != nil {
			return err
		}
		if ws := servingCertWarnings(cfg, p, time.Now()); len(ws) > 0 {
			return errors.New(ws[0].Setting + ": " + ws[0].Message)
		}
		return nil
	}
	for _, tc := range []struct {
		name   string
		args   []string
		env    []string
		refuse func(*config.Config) error
		want   string // the message's start
	}{
		{"a serving certificate key others can read, by env", nil, append(dropping(authEnv(t)), "BYWARD_TLS_CERT_FILE="+cert, "BYWARD_TLS_KEY_FILE="+looseKey), loose,
			"BYWARD_TLS_KEY_FILE: "},
		{"a serving certificate key others can read, by flag", []string{"--tls-cert-file=" + cert, "--tls-key-file=" + looseKey}, dropping(authEnv(t)), loose,
			"--tls-key-file: "},
		{"a serving certificate pair that does not parse, by env", nil, append(dropping(authEnv(t)), "BYWARD_TLS_CERT_FILE="+badCert, "BYWARD_TLS_KEY_FILE="+badKey), pair,
			"BYWARD_TLS_CERT_FILE / BYWARD_TLS_KEY_FILE: "},
		{"a serving certificate pair that does not parse, by flag", []string{"--tls-cert-file=" + badCert, "--tls-key-file=" + badKey}, dropping(authEnv(t)), pair,
			"--tls-cert-file / --tls-key-file: "},
		{"a serving certificate for another host, by env", nil, append(dropping(authEnv(t)), "BYWARD_TLS_CERT_FILE="+otherCert, "BYWARD_TLS_KEY_FILE="+otherKey), warns,
			"BYWARD_TLS_CERT_FILE: "},
		{"a serving certificate for another host, by flag", []string{"--tls-cert-file=" + otherCert, "--tls-key-file=" + otherKey}, dropping(authEnv(t)), warns,
			"--tls-cert-file: "},
		{"a missing federated token file, by env", nil, append(dropping(authEnv(t), "BYWARD_ENTRA_CLIENT_SECRET_FILE"), "BYWARD_ENTRA_FEDERATED_TOKEN_FILE="+missing), loose,
			"BYWARD_ENTRA_FEDERATED_TOKEN_FILE: "},
		{"a missing federated token file, by flag", []string{"--entra-federated-token-file=" + missing}, dropping(authEnv(t), "BYWARD_ENTRA_CLIENT_SECRET_FILE"), loose,
			"--entra-federated-token-file: "},
		{"a missing sealing key directory, by env", nil, append(dropping(authEnv(t), "BYWARD_KEYS_DIR"), "BYWARD_KEYS_DIR="+missing), auth,
			"BYWARD_KEYS_DIR: "},
		{"a missing sealing key directory, by flag", []string{"--keys-dir=" + missing}, dropping(authEnv(t), "BYWARD_KEYS_DIR"), auth,
			"--keys-dir: "},
		{"a missing static clients file, by env", nil, append(dropping(authEnv(t), "BYWARD_STATIC_CLIENTS_FILE"), "BYWARD_STATIC_CLIENTS_FILE="+missing), auth,
			"BYWARD_STATIC_CLIENTS_FILE: "},
		{"a missing static clients file, by flag", []string{"--static-clients-file=" + missing}, dropping(authEnv(t), "BYWARD_STATIC_CLIENTS_FILE"), auth,
			"--static-clients-file: "},
		{"a missing assertion key directory, by env", nil, append(dropping(authEnv(t), "BYWARD_ASSERTION_KEYS_DIR"), "BYWARD_ASSERTION_KEYS_DIR="+missing), keys,
			"BYWARD_ASSERTION_KEYS_DIR: "},
		{"a missing assertion key directory, by flag", []string{"--assertion-keys-dir=" + missing}, dropping(authEnv(t), "BYWARD_ASSERTION_KEYS_DIR"), keys,
			"--assertion-keys-dir: "},
		{"a store directory that is a file, checked, by env", nil, append(dropping(authEnv(t), "BYWARD_STORE_DIR", "BYWARD_STORE_COUNTER_FILE"), "BYWARD_STORE_DIR="+stateFile, "BYWARD_STORE_COUNTER_FILE="+counter), check,
			"BYWARD_STORE_DIR / BYWARD_STORE_COUNTER_FILE: "},
		{"a store directory that is a file, checked, by flag", []string{"--store-dir=" + stateFile, "--store-counter-file=" + counter}, dropping(authEnv(t), "BYWARD_STORE_DIR", "BYWARD_STORE_COUNTER_FILE"), check,
			"--store-dir / --store-counter-file: "},
		{"a store directory that is a file, its counter file left at its default", []string{"--store-dir=" + stateFile}, dropping(authEnv(t), "BYWARD_STORE_DIR", "BYWARD_STORE_COUNTER_FILE"), check,
			"--store-dir / BYWARD_STORE_COUNTER_FILE: "},
		{"a store directory that is a file, opened, by env", nil, append(dropping(authEnv(t), "BYWARD_STORE_DIR", "BYWARD_STORE_COUNTER_FILE"), "BYWARD_STORE_DIR="+stateFile, "BYWARD_STORE_COUNTER_FILE="+counter), open,
			"BYWARD_STORE_DIR / BYWARD_STORE_COUNTER_FILE: "},
		{"a store directory that is a file, opened, by flag", []string{"--store-dir=" + stateFile, "--store-counter-file=" + counter}, dropping(authEnv(t), "BYWARD_STORE_DIR", "BYWARD_STORE_COUNTER_FILE"), open,
			"--store-dir / --store-counter-file: "},
		{"a store an operator command finds missing, by env", nil, append(dropping(authEnv(t), "BYWARD_STORE_DIR", "BYWARD_STORE_COUNTER_FILE"), "BYWARD_STORE_DIR="+missing), openExisting,
			"BYWARD_STORE_DIR: "},
		{"a store an operator command finds missing, by flag", []string{"--store-dir=" + missing}, dropping(authEnv(t), "BYWARD_STORE_DIR", "BYWARD_STORE_COUNTER_FILE"), openExisting,
			"--store-dir: "},
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
	entraSetting := func(t *testing.T, cfg *config.Config) string {
		_, d, _, err := entraClientAuth(cfg)
		if err != nil {
			t.Fatal(err)
		}
		return d.CredentialSetting
	}
	oidcSetting := func(_ *testing.T, cfg *config.Config) string { return oidcDiagnosis(cfg).CredentialSetting }
	for _, tc := range []struct {
		name    string
		args    []string
		env     []string
		setting func(*testing.T, *config.Config) string
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
			if got := tc.setting(t, cfg); got != tc.want {
				t.Fatalf("CredentialSetting = %q, want %q", got, tc.want)
			}
		})
	}
}
