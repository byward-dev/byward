package token

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/byward-dev/byward/internal/secretfile"
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
	if err := os.Chmod(dir, 0o700); err != nil { //nolint:gosec // G302: a directory needs x; the mode exactly, whatever the umask
		t.Fatal(err)
	}
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

// noCheck is the permission check --dev uses: none.
func noCheck(string) error { return nil }

func mustRing(t testing.TB, dir string) *KeyRing {
	t.Helper()
	r, err := LoadKeyRing(dir, noCheck)
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
		{"key ID over 64 characters", strings.Repeat("k", 65), randomKey(t), "must match"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := keyDir(t, map[string]string{"good": randomKey(t), tc.file: tc.content})
			_, err := LoadKeyRing(dir, noCheck)
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
		if _, err := LoadKeyRing(dir, noCheck); err == nil || !strings.Contains(err.Error(), "k1 is world-writable") {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("directory", func(t *testing.T) {
		dir := keyDir(t, map[string]string{"k1": randomKey(t)})
		if err := os.Chmod(dir, 0o707); err != nil { //nolint:gosec // G302: the insecure mode under test
			t.Fatal(err)
		}
		if _, err := LoadKeyRing(dir, noCheck); err == nil || !strings.Contains(err.Error(), "world-writable") {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("directory on a read-only mount (Kubernetes secret volume, mode 1777)", func(t *testing.T) {
		dir := keyDir(t, map[string]string{"k1": randomKey(t)})
		if err := os.Chmod(dir, 0o777|os.ModeSticky); err != nil { //nolint:gosec // G302: the Kubernetes mode under test
			t.Fatal(err)
		}
		prev := readOnlyFS
		readOnlyFS = func(p string) bool { return p == dir }
		t.Cleanup(func() { readOnlyFS = prev })
		mustRing(t, dir)
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
	if _, err := LoadKeyRing(dir, noCheck); !errors.Is(err, fs.ErrPermission) || !strings.Contains(err.Error(), filepath.Join(dir, "k1")) {
		t.Fatalf("err = %v, want a permission error naming the file", err)
	}
}

func TestMissingOrEmptyKeyDirectoryRefusesToStart(t *testing.T) {
	notADir := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(notADir, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	dangling := keyDir(t, nil)
	if err := os.Symlink(filepath.Join(dangling, "absent"), filepath.Join(dangling, "k1")); err != nil {
		t.Fatal(err)
	}
	missing, empty := filepath.Join(t.TempDir(), "absent"), keyDir(t, nil)
	dotfiles := keyDir(t, map[string]string{".gitkeep": ""})
	cases := []struct {
		name, dir, want string // want: the error must contain it
	}{
		{"not a directory", notADir, notADir + ": not a directory"},
		{"dangling symlink", dangling, "key file " + filepath.Join(dangling, "k1")},
		{"missing", missing, "key directory: stat " + missing},
		{"empty", empty, "key directory " + empty + " has no key files"},
		{"only dotfiles", dotfiles, "key directory " + dotfiles + " has no key files"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := LoadKeyRing(tc.dir, noCheck); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want one containing %q", err, tc.want)
			}
		})
	}
}

// The sealing keys are secret files (L163): each goes through the secret file check before it is
// read, and the load fails naming the file the check refused.
func TestAKeyFileTheSecretCheckRefusesFailsTheLoad(t *testing.T) {
	dir := keyDir(t, map[string]string{"k1": randomKey(t), "k2": randomKey(t)})
	refused := errors.New("refused by the check")
	var checked []string
	check := func(path string) error {
		checked = append(checked, filepath.Base(path))
		if filepath.Base(path) == "k2" {
			return fmt.Errorf("secret file %s: %w", path, refused)
		}
		return nil
	}
	_, err := LoadKeyRing(dir, check)
	if !errors.Is(err, refused) || !strings.Contains(err.Error(), filepath.Join(dir, "k2")) {
		t.Fatalf("err = %v, want the check's refusal naming k2", err)
	}
	if !slices.Contains(checked, "k1") || !slices.Contains(checked, "k2") {
		t.Fatalf("checked %v, want every key file", checked)
	}
}

// With the production check, a key file other users can read is refused on a writable disk, and
// passes with the check --dev uses.
func TestAKeyFileOthersCanReadIsRefusedOutsideDev(t *testing.T) {
	dir := keyDir(t, map[string]string{"k1": randomKey(t)})
	if err := os.Chmod(filepath.Join(dir, "k1"), 0o644); err != nil { //nolint:gosec // G302: the mode under test
		t.Fatal(err)
	}
	if _, err := LoadKeyRing(dir, secretfile.Check); err == nil || !strings.Contains(err.Error(), "has mode 0644") {
		t.Fatalf("err = %v, want the secret file refusal", err)
	}
	if _, err := LoadKeyRing(dir, noCheck); err != nil {
		t.Fatalf("with --dev's check: %v", err)
	}
}
