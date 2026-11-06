package token

import (
	"crypto/rand"
	"encoding/base64"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func randomKey(t testing.TB) string {
	t.Helper()
	b := make([]byte, KeySize)
	_, _ = rand.Read(b)
	return base64.StdEncoding.EncodeToString(b) + "\n"
}

// keyDir writes one file per entry (name → content) into a new directory with mode 0700.
func keyDir(t testing.TB, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func mustRing(t testing.TB, dir string) *KeyRing {
	t.Helper()
	r, err := LoadKeyRing(dir)
	if err != nil {
		t.Fatalf("LoadKeyRing: %v", err)
	}
	return r
}

func TestKeyFileThatSortsLastSeals(t *testing.T) {
	r := mustRing(t, keyDir(t, map[string]string{
		"2026-05-01": randomKey(t), "2026-11-06": randomKey(t), "2026-08-15": randomKey(t),
	}))
	if got := r.SigningKeyID(); got != "2026-11-06" {
		t.Fatalf("signing key = %q, want the last-sorting name", got)
	}
	if got := r.KeyIDs(); !slices.Equal(got, []string{"2026-05-01", "2026-08-15", "2026-11-06"}) {
		t.Fatalf("key IDs = %v", got)
	}
}

func TestKeyDirectorySkipsDotfilesAndDirectoriesAndFollowsSymlinks(t *testing.T) {
	dir := keyDir(t, map[string]string{".hidden": "not a key", "..data": "x"})
	if err := os.Mkdir(filepath.Join(dir, "subdir"), 0o700); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(t.TempDir(), "real-key")
	if err := os.WriteFile(target, []byte(randomKey(t)), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(dir, "k1")); err != nil {
		t.Fatal(err)
	}
	if got := mustRing(t, dir).KeyIDs(); !slices.Equal(got, []string{"k1"}) {
		t.Fatalf("key IDs = %v, want only the symlinked key", got)
	}
}

func TestBadKeyFilesFailTheLoadNamingTheFile(t *testing.T) {
	short := base64.StdEncoding.EncodeToString(make([]byte, 16))
	same := base64.StdEncoding.EncodeToString([]byte(strings.Repeat("a", KeySize)))
	cases := []struct {
		name, file, content, want string
	}{
		{"not base64", "k1", "not!base64", "not base64"},
		{"too short", "k1", short, "16 bytes, want 32"},
		{"all bytes the same", "k1", same, "every byte is the same"},
		{"all zero", "k1", base64.StdEncoding.EncodeToString(make([]byte, KeySize)), "every byte is the same"},
		{"empty", "k1", "", "0 bytes"},
		{"too large", "k1", strings.Repeat("A", maxKeyFile+1), "too large"},
		{"bad key ID", "key one", randomKey(t), "must match"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := keyDir(t, map[string]string{"good": randomKey(t), tc.file: tc.content})
			_, err := LoadKeyRing(dir)
			if err == nil || !strings.Contains(err.Error(), filepath.Join(dir, tc.file)) || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want one naming %s and saying %q", err, tc.file, tc.want)
			}
		})
	}
}

func TestWorldWritableKeysAreRejected(t *testing.T) {
	t.Run("file", func(t *testing.T) {
		dir := keyDir(t, map[string]string{"k1": randomKey(t)})
		if err := os.Chmod(filepath.Join(dir, "k1"), 0o646); err != nil { //nolint:gosec // G302: the insecure mode under test
			t.Fatal(err)
		}
		if _, err := LoadKeyRing(dir); err == nil || !strings.Contains(err.Error(), "k1 is world-writable") {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("directory", func(t *testing.T) {
		dir := keyDir(t, map[string]string{"k1": randomKey(t)})
		if err := os.Chmod(dir, 0o707); err != nil { //nolint:gosec // G302: the insecure mode under test
			t.Fatal(err)
		}
		if _, err := LoadKeyRing(dir); err == nil || !strings.Contains(err.Error(), "world-writable") {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("group- and other-readable is fine", func(t *testing.T) {
		dir := keyDir(t, map[string]string{"k1": randomKey(t)})
		if err := os.Chmod(filepath.Join(dir, "k1"), 0o644); err != nil { //nolint:gosec // G302: the Kubernetes default under test
			t.Fatal(err)
		}
		mustRing(t, dir)
	})
}

func TestUnreadableKeyFileFailsTheLoad(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root reads any file")
	}
	dir := keyDir(t, map[string]string{"k1": randomKey(t)})
	if err := os.Chmod(filepath.Join(dir, "k1"), 0o000); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadKeyRing(dir); err == nil || !strings.Contains(err.Error(), "k1") {
		t.Fatalf("err = %v, want one naming k1", err)
	}
}

func TestMissingOrEmptyKeyDirectoryRefusesToStart(t *testing.T) {
	for name, dir := range map[string]string{
		"missing":       filepath.Join(t.TempDir(), "absent"),
		"empty":         t.TempDir(),
		"only dotfiles": keyDir(t, map[string]string{".gitkeep": ""}),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := LoadKeyRing(dir); err == nil || !strings.Contains(err.Error(), dir) {
				t.Fatalf("err = %v, want one naming %s", err, dir)
			}
		})
	}
}
