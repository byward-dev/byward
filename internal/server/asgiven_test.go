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
	"github.com/byward-dev/byward/internal/testutil/pgtest"
	"github.com/byward-dev/byward/internal/testutil/testcert"
)

// servedSettings are the public URL, https://mcp.example.com/mcp, and an HTTP upstream's URL.
var servedSettings = []string{"BYWARD_PUBLIC_URL=https://mcp.example.com/mcp", "BYWARD_UPSTREAM_URL=http://u/mcp"}

// servedEnv is authEnv without the variables named, plus servedSettings: the environment the
// settings under test are set beside.
func servedEnv(t testing.TB, without ...string) []string {
	env := slices.DeleteFunc(authEnv(t), func(kv string) bool {
		return slices.ContainsFunc(without, func(v string) bool { return strings.HasPrefix(kv, v+"=") })
	})
	return append(env, servedSettings...)
}

// oidcServed is the environment for an OIDC IdP without a client credential, plus servedSettings.
func oidcServed() []string {
	return append([]string{"BYWARD_IDP=keycloak", "BYWARD_OIDC_ISSUER=https://sso.example.com/realms/acme", "BYWARD_OIDC_CLIENT_ID=byward"}, servedSettings...)
}

// fileOf writes content into a new file with mode, set whatever the umask.
func fileOf(t testing.TB, content string, mode os.FileMode) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "f")
	if err := os.WriteFile(p, []byte(content), mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, mode); err != nil {
		t.Fatal(err)
	}
	return p
}

// A credential or DSN file whose content is refused is named as the operator gave it: its file
// flag, or its file variable (#619). So is a key algorithm the client key cannot sign with.
func TestARefusedFileIsNamedAsGiven(t *testing.T) {
	pgtest.ClearEnv(t) // the DSN is parsed, which reads PG* variables, the service file and ~/.pgpass
	entraRefuses := func(cfg *config.Config) error { _, _, _, err := entraClientAuth(cfg); return err }
	oidcRefuses := func(cfg *config.Config) error { _, _, err := oidcClientAuth(cfg); return err }
	storeRefuses := func(cfg *config.Config) error { _, err := checkStore(cfg); return err }
	cert, key, dsn := fileOf(t, "not a certificate\n", 0o600), fileOf(t, "not a key\n", 0o600), fileOf(t, "postgres://byward@db.example/byward\n", 0o600)
	weak := fileOf(t, string(fakeidp.PrivateKeyPEM(t, weakRSAKey(t))), 0o600) // parses, but cannot sign: refused after parsing
	rsa := fileOf(t, string(fakeidp.PrivateKeyPEM(t, fakeidp.NewCertificate(t).Key)), 0o600)
	for _, tc := range []struct {
		name   string
		args   []string
		env    []string
		refuse func(*config.Config) error
		want   string
		says   string // a fragment of the reason, so the row fails on another refusal of the same setting
	}{
		{"an Entra certificate, by env", nil, append(servedEnv(t, "BYWARD_ENTRA_CLIENT_SECRET_FILE"), "BYWARD_ENTRA_CLIENT_CERTIFICATE_FILE="+cert), entraRefuses, "BYWARD_ENTRA_CLIENT_CERTIFICATE_FILE: ", "no PEM private key"},
		{"an Entra certificate, by flag", []string{"--entra-client-certificate-file=" + cert}, servedEnv(t, "BYWARD_ENTRA_CLIENT_SECRET_FILE"), entraRefuses, "--entra-client-certificate-file: ", "no PEM private key"},
		{"an OIDC client key, by env", nil, append(oidcServed(), "BYWARD_OIDC_CLIENT_KEY_FILE="+key), oidcRefuses, "BYWARD_OIDC_CLIENT_KEY_FILE: ", "not a PEM private key"},
		{"an OIDC client key, by flag", []string{"--oidc-client-key-file=" + key}, oidcServed(), oidcRefuses, "--oidc-client-key-file: ", "not a PEM private key"},
		{"a weak OIDC client key, by env", nil, append(oidcServed(), "BYWARD_OIDC_CLIENT_KEY_FILE="+weak), oidcRefuses, "BYWARD_OIDC_CLIENT_KEY_FILE: idp: a 1024-bit RSA key", "1024-bit RSA key"},
		{"a weak OIDC client key, by flag", []string{"--oidc-client-key-file=" + weak}, oidcServed(), oidcRefuses, "--oidc-client-key-file: idp: a 1024-bit RSA key", "1024-bit RSA key"},
		{"an OIDC key algorithm the key cannot sign with, by env", nil, append(oidcServed(), "BYWARD_OIDC_CLIENT_KEY_FILE="+rsa, "BYWARD_OIDC_CLIENT_KEY_ALG=ES256"), oidcRefuses, "BYWARD_OIDC_CLIENT_KEY_ALG: ", "cannot sign with that algorithm"},
		{"an OIDC key algorithm the key cannot sign with, by flag", []string{"--oidc-client-key-alg=ES256"}, append(oidcServed(), "BYWARD_OIDC_CLIENT_KEY_FILE="+rsa), oidcRefuses, "--oidc-client-key-alg: ", "cannot sign with that algorithm"},
		{"a PostgreSQL DSN, by env", nil, append(servedEnv(t, "BYWARD_STORE_DIR"), "BYWARD_STORE_POSTGRES_DSN_FILE="+dsn), storeRefuses, "BYWARD_STORE_POSTGRES_DSN_FILE: ", "verify-full"},
		{"a PostgreSQL DSN, by flag", []string{"--store-postgres-dsn-file=" + dsn}, servedEnv(t, "BYWARD_STORE_DIR"), storeRefuses, "--store-postgres-dsn-file: ", "verify-full"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg, _, err := config.Load(tc.args, tc.env, os.ReadFile)
			if err != nil {
				t.Fatal(err)
			}
			if err := tc.refuse(cfg); err == nil || !strings.HasPrefix(err.Error(), tc.want) || !strings.Contains(err.Error(), tc.says) {
				t.Fatalf("err = %v, want it to start with %q and say %q", err, tc.want, tc.says)
			}
		})
	}
}

// A path setting's file or directory that cannot be used is named as the operator gave it, flag or
// variable, in the refusals and the warning below (#619); a setting left at its default keeps its
// variable.
func TestAPathSettingThatCannotBeUsedIsNamedAsGiven(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "missing")
	cert, looseKey := fileOf(t, "x", 0o600), fileOf(t, "x", 0o644)
	looseToken := fileOf(t, "t", 0o644)
	badCert, badKey := fileOf(t, "not a certificate", 0o600), fileOf(t, "not a key", 0o600)
	stateFile, counter := fileOf(t, "", 0o600), filepath.Join(t.TempDir(), "store-writes")
	otherCert, otherKey := testcert.Issue(t, testcert.Options{Hosts: []string{"other.example.com"}, Leaf: testcert.Valid(time.Now(), 90)}).Write(t, t.TempDir())
	expiredCert, expiredKey := testcert.Issue(t, testcert.Options{Hosts: []string{"mcp.example.com"}, Leaf: testcert.Validity{NotBefore: time.Now().Add(-90 * 24 * time.Hour), NotAfter: time.Now().Add(-24 * time.Hour)}}).Write(t, t.TempDir())
	loose := func(cfg *config.Config) error { return errors.Join(looseSecretFiles(cfg)...) }
	auth := func(cfg *config.Config) error { _, err := loadAuthParts(cfg, nil); return err }
	pair := func(cfg *config.Config) error { _, err := diskCert(cfg); return err }
	start := func(cfg *config.Config) error { _, err := servingTLS(cfg, discard, time.Now); return err }
	servable := func(cfg *config.Config) error { _, err := servableCert(cfg, time.Now()); return err }
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
		says   string // a fragment of the reason, so the row fails on another refusal of the same setting
	}{
		{"a serving certificate key others can read, by env", nil, append(servedEnv(t), "BYWARD_TLS_CERT_FILE="+cert, "BYWARD_TLS_KEY_FILE="+looseKey), loose,
			"BYWARD_TLS_KEY_FILE: ", "0644"},
		{"a serving certificate key others can read, by flag", []string{"--tls-cert-file=" + cert, "--tls-key-file=" + looseKey}, servedEnv(t), loose,
			"--tls-key-file: ", "0644"},
		{"a serving certificate pair that does not parse, by env", nil, append(servedEnv(t), "BYWARD_TLS_CERT_FILE="+badCert, "BYWARD_TLS_KEY_FILE="+badKey), pair,
			"BYWARD_TLS_CERT_FILE / BYWARD_TLS_KEY_FILE: ", "failed to find any PEM data"},
		{"a serving certificate pair that does not parse, by flag", []string{"--tls-cert-file=" + badCert, "--tls-key-file=" + badKey}, servedEnv(t), pair,
			"--tls-cert-file / --tls-key-file: ", "failed to find any PEM data"},
		{"a serving certificate pair that does not parse at start, by env", nil, append(servedEnv(t), "BYWARD_TLS_CERT_FILE="+badCert, "BYWARD_TLS_KEY_FILE="+badKey), start,
			"BYWARD_TLS_CERT_FILE / BYWARD_TLS_KEY_FILE: ", "failed to find any PEM data"},
		{"a serving certificate pair that does not parse at start, by flag", []string{"--tls-cert-file=" + badCert, "--tls-key-file=" + badKey}, servedEnv(t), start,
			"--tls-cert-file / --tls-key-file: ", "failed to find any PEM data"},
		{"an expired serving certificate, by env", nil, append(servedEnv(t), "BYWARD_TLS_CERT_FILE="+expiredCert, "BYWARD_TLS_KEY_FILE="+expiredKey), servable,
			"BYWARD_TLS_CERT_FILE / BYWARD_TLS_KEY_FILE: ", "expired on"},
		{"an expired serving certificate, by flag", []string{"--tls-cert-file=" + expiredCert, "--tls-key-file=" + expiredKey}, servedEnv(t), servable,
			"--tls-cert-file / --tls-key-file: ", "expired on"},
		{"a serving certificate for another host, by env", nil, append(servedEnv(t), "BYWARD_TLS_CERT_FILE="+otherCert, "BYWARD_TLS_KEY_FILE="+otherKey), warns,
			"BYWARD_TLS_CERT_FILE: ", "covers neither"},
		{"a serving certificate for another host, by flag", []string{"--tls-cert-file=" + otherCert, "--tls-key-file=" + otherKey}, servedEnv(t), warns,
			"--tls-cert-file: ", "covers neither"},
		{"a federated token file others can read, by env", nil, append(servedEnv(t, "BYWARD_ENTRA_CLIENT_SECRET_FILE"), "BYWARD_ENTRA_FEDERATED_TOKEN_FILE="+looseToken), loose,
			"BYWARD_ENTRA_FEDERATED_TOKEN_FILE: ", "0644"},
		{"a federated token file others can read, by flag", []string{"--entra-federated-token-file=" + looseToken}, servedEnv(t, "BYWARD_ENTRA_CLIENT_SECRET_FILE"), loose,
			"--entra-federated-token-file: ", "0644"},
		{"a missing federated token file, by env", nil, append(servedEnv(t, "BYWARD_ENTRA_CLIENT_SECRET_FILE"), "BYWARD_ENTRA_FEDERATED_TOKEN_FILE="+missing), loose,
			"BYWARD_ENTRA_FEDERATED_TOKEN_FILE: ", "no such file"},
		{"a missing federated token file, by flag", []string{"--entra-federated-token-file=" + missing}, servedEnv(t, "BYWARD_ENTRA_CLIENT_SECRET_FILE"), loose,
			"--entra-federated-token-file: ", "no such file"},
		{"a missing sealing key directory, by env", nil, append(servedEnv(t, "BYWARD_KEYS_DIR"), "BYWARD_KEYS_DIR="+missing), auth,
			"BYWARD_KEYS_DIR: ", "no such file"},
		{"a missing sealing key directory, by flag", []string{"--keys-dir=" + missing}, servedEnv(t, "BYWARD_KEYS_DIR"), auth,
			"--keys-dir: ", "no such file"},
		{"a missing static clients file, by env", nil, append(servedEnv(t, "BYWARD_STATIC_CLIENTS_FILE"), "BYWARD_STATIC_CLIENTS_FILE="+missing), auth,
			"BYWARD_STATIC_CLIENTS_FILE: ", "no such file"},
		{"a missing static clients file, by flag", []string{"--static-clients-file=" + missing}, servedEnv(t, "BYWARD_STATIC_CLIENTS_FILE"), auth,
			"--static-clients-file: ", "no such file"},
		{"a missing assertion key directory, by env", nil, append(servedEnv(t, "BYWARD_ASSERTION_KEYS_DIR"), "BYWARD_ASSERTION_KEYS_DIR="+missing), keys,
			"BYWARD_ASSERTION_KEYS_DIR: ", "no such file"},
		{"a missing assertion key directory, by flag", []string{"--assertion-keys-dir=" + missing}, servedEnv(t, "BYWARD_ASSERTION_KEYS_DIR"), keys,
			"--assertion-keys-dir: ", "no such file"},
		{"a store directory that is a file, checked, by env", nil, append(servedEnv(t, "BYWARD_STORE_DIR"), "BYWARD_STORE_DIR="+stateFile, "BYWARD_STORE_COUNTER_FILE="+counter), check,
			"BYWARD_STORE_DIR / BYWARD_STORE_COUNTER_FILE: ", "not a directory"},
		{"a store directory that is a file, checked, by flag", []string{"--store-dir=" + stateFile, "--store-counter-file=" + counter}, servedEnv(t, "BYWARD_STORE_DIR"), check,
			"--store-dir / --store-counter-file: ", "not a directory"},
		{"a store directory that is a file, its counter file left at its default", []string{"--store-dir=" + stateFile}, servedEnv(t, "BYWARD_STORE_DIR"), check,
			"--store-dir / BYWARD_STORE_COUNTER_FILE: ", "not a directory"},
		{"a store directory that is a file, opened, by env", nil, append(servedEnv(t, "BYWARD_STORE_DIR"), "BYWARD_STORE_DIR="+stateFile, "BYWARD_STORE_COUNTER_FILE="+counter), open,
			"BYWARD_STORE_DIR / BYWARD_STORE_COUNTER_FILE: ", "not a directory"},
		{"a store directory that is a file, opened, by flag", []string{"--store-dir=" + stateFile, "--store-counter-file=" + counter}, servedEnv(t, "BYWARD_STORE_DIR"), open,
			"--store-dir / --store-counter-file: ", "not a directory"},
		{"a missing store an operator command needs, by env", nil, append(servedEnv(t, "BYWARD_STORE_DIR"), "BYWARD_STORE_DIR="+missing), openExisting,
			"BYWARD_STORE_DIR: ", "byward.db is missing"},
		{"a missing store an operator command needs, by flag", []string{"--store-dir=" + missing}, servedEnv(t, "BYWARD_STORE_DIR"), openExisting,
			"--store-dir: ", "byward.db is missing"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg, _, err := config.Load(tc.args, tc.env, os.ReadFile)
			if err != nil {
				t.Fatal(err)
			}
			if err := tc.refuse(cfg); err == nil || !strings.HasPrefix(err.Error(), tc.want) || !strings.Contains(err.Error(), tc.says) {
				t.Fatalf("err = %v, want it to start with %q and say %q", err, tc.want, tc.says)
			}
		})
	}
}

// The credential doctor names in its fixes is named as the operator gave it (#619): the diagnosis of
// the Entra and the OIDC client carries the flag or the variable.
func TestTheDiagnosedCredentialIsNamedAsGiven(t *testing.T) {
	secret, key := fileOf(t, "s3cret\n", 0o600), fileOf(t, string(fakeidp.PrivateKeyPEM(t, fakeidp.NewCertificate(t).Key)), 0o600)
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
		{"an Entra secret, by env", nil, append(servedEnv(t, "BYWARD_ENTRA_CLIENT_SECRET_FILE"), "BYWARD_ENTRA_CLIENT_SECRET_FILE="+secret), entraSetting, "BYWARD_ENTRA_CLIENT_SECRET_FILE"},
		{"an Entra secret, by flag", []string{"--entra-client-secret-file=" + secret}, servedEnv(t, "BYWARD_ENTRA_CLIENT_SECRET_FILE"), entraSetting, "--entra-client-secret-file"},
		{"an Entra federated token, by env", nil, append(servedEnv(t, "BYWARD_ENTRA_CLIENT_SECRET_FILE"), "BYWARD_ENTRA_FEDERATED_TOKEN_FILE="+secret), entraSetting, "BYWARD_ENTRA_FEDERATED_TOKEN_FILE"},
		{"an Entra federated token, by flag", []string{"--entra-federated-token-file=" + secret}, servedEnv(t, "BYWARD_ENTRA_CLIENT_SECRET_FILE"), entraSetting, "--entra-federated-token-file"},
		{"an OIDC secret, by env", nil, append(oidcServed(), "BYWARD_OIDC_CLIENT_SECRET_FILE="+secret), oidcSetting, "BYWARD_OIDC_CLIENT_SECRET_FILE"},
		{"an OIDC secret, by flag", []string{"--oidc-client-secret-file=" + secret}, oidcServed(), oidcSetting, "--oidc-client-secret-file"},
		{"an OIDC key, by env", nil, append(oidcServed(), "BYWARD_OIDC_CLIENT_KEY_FILE="+key), oidcSetting, "BYWARD_OIDC_CLIENT_KEY_FILE"},
		{"an OIDC key, by flag", []string{"--oidc-client-key-file=" + key}, oidcServed(), oidcSetting, "--oidc-client-key-file"},
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
