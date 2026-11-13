//go:build integration

package server

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/byward-dev/byward/internal/config"
	"github.com/byward-dev/byward/internal/doctor"
)

// doctor checks the proxy's client credential at a real Keycloak without a user (#288): the right
// secret or key passes, a wrong one fails with a fix naming its setting. Keycloak answers a wrong
// secret unauthorized_client 401 and a wrong key invalid_client 400 (26.8.0).
func TestIntegrationKeycloakDoctorChecksTheClientCredential(t *testing.T) {
	if os.Getenv("BYWARD_REAL_CLIENTS") != "1" {
		t.Skip("set BYWARD_REAL_CLIENTS=1 to run Keycloak (needs Docker and the network)")
	}
	if _, err := exec.LookPath("docker"); err != nil {
		t.Fatalf("BYWARD_REAL_CLIENTS=1 but docker is not available: %v", err)
	}
	const public = "http://127.0.0.1:9"
	key, cert := keycloakClientKey(t)
	realm := keycloakRealm(public + "/callback/keycloak")
	realm["clients"] = append(realm["clients"].([]any), map[string]any{
		"clientId": "byward-jwt", "enabled": true, "protocol": "openid-connect", "publicClient": false,
		"clientAuthenticatorType": "client-jwt", "standardFlowEnabled": true, "redirectUris": []any{public + "/callback/keycloak"},
		"attributes": map[string]any{"jwt.credential.certificate": cert, "token.endpoint.auth.signing.alg": "ES256"},
	})
	issuer := startKeycloak(t, realm) + "/realms/byward"
	other, _ := keycloakClientKey(t)
	for _, tc := range []struct {
		name, clientID, secret, key string
		want                        doctor.Status
		fix                         string
	}{
		{"the right secret", "byward", keycloakClientSecret, "", doctor.Pass, ""},
		{"a wrong secret", "byward", "not-the-secret", "", doctor.Fail, "BYWARD_OIDC_CLIENT_SECRET_FILE"},
		{"the registered key", "byward-jwt", "", key, doctor.Pass, ""},
		{"another key", "byward-jwt", "", other, doctor.Fail, "BYWARD_OIDC_CLIENT_KEY_FILE"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			env := oidcEnv(t, "keycloak", issuer, tc.clientID, tc.secret, "BYWARD_PUBLIC_URL="+public+"/mcp", "BYWARD_UPSTREAM_URL=http://u/mcp")
			if tc.key != "" {
				env = append(slices.DeleteFunc(env, func(kv string) bool { return strings.HasPrefix(kv, "BYWARD_OIDC_CLIENT_SECRET_FILE=") }),
					"BYWARD_OIDC_CLIENT_KEY_FILE="+tc.key)
			}
			cfg, _, err := config.Load([]string{"--dev"}, env, os.ReadFile)
			if err != nil {
				t.Fatal(err)
			}
			report, err := Doctor(context.Background(), cfg, DoctorOptions{})
			if err != nil {
				t.Fatal(err)
			}
			for _, r := range report.Checks {
				if r.Name == "client credential" {
					if r.Status != tc.want || !strings.Contains(r.Fix, tc.fix) {
						t.Fatalf("client credential %+v; want %s with a fix naming %q", r, tc.want, tc.fix)
					}
					return
				}
			}
			t.Fatalf("no client credential check in %+v", report.Checks)
		})
	}
}

// keycloakClientKey makes an EC P-256 key for private_key_jwt and returns the path of its PEM file
// and its self-signed certificate (base64 DER), which Keycloak's client-jwt client verifies with.
func keycloakClientKey(t *testing.T) (keyFile, cert string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "byward-test"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	pkcs8, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	keyFile = filepath.Join(t.TempDir(), "client-key.pem")
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8}), 0o600); err != nil {
		t.Fatal(err)
	}
	return keyFile, base64.StdEncoding.EncodeToString(der)
}
