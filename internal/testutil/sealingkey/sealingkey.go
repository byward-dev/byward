// Package sealingkey writes sealing keys for tests, in the file layout BYWARD_KEYS_DIR expects: one
// base64-encoded random key per file, named by its key ID.
package sealingkey

import (
	"crypto/rand"
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"

	"github.com/byward-dev/byward/internal/token"
)

// Write creates a random sealing key named id (its key ID) in dir, mode 0600, creating dir if needed.
func Write(t testing.TB, dir, id string) {
	t.Helper()
	k := make([]byte, token.KeySize)
	_, _ = rand.Read(k)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, id), []byte(base64.StdEncoding.EncodeToString(k)), 0o600); err != nil {
		t.Fatal(err)
	}
}

// Dir creates a key directory under t.TempDir() holding one key, "k1", and returns it.
func Dir(t testing.TB) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "keys")
	Write(t, dir, "k1")
	return dir
}
