// Package assertionkey writes identity assertion signing keys for tests, in the file layout
// BYWARD_ASSERTION_KEYS_DIR expects (docs/how-to/identity-assertion.md).
package assertionkey

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
)

// Write creates a P-256 key named id (its key ID) in dir, mode 0600, as PEM PKCS#8 or, with sec1,
// as the "EC PRIVATE KEY" `openssl ecparam -genkey` writes.
func Write(t testing.TB, dir, id string, sec1 bool) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	block := &pem.Block{Type: "PRIVATE KEY"}
	if sec1 {
		block.Type = "EC PRIVATE KEY"
		block.Bytes, err = x509.MarshalECPrivateKey(k)
	} else {
		block.Bytes, err = x509.MarshalPKCS8PrivateKey(k)
	}
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, id), pem.EncodeToMemory(block), 0o600); err != nil {
		t.Fatal(err)
	}
	return k
}

// Dir creates a key directory under t.TempDir() holding one key, "k1", and returns it.
func Dir(t testing.TB) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "assertion-keys")
	Write(t, dir, "k1", false)
	return dir
}
