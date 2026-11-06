package secretfile

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSecretFilesOthersCanReachAreRefusedUnlessReadOnly(t *testing.T) {
	cases := []struct {
		mode     os.FileMode
		readOnly bool
		wantErr  bool
	}{
		{0o600, false, false},
		{0o400, false, false},
		{0o640, false, true},
		{0o604, false, true},
		{0o620, false, true},
		{0o644, true, false}, // Kubernetes secret volume default
		{0o444, true, false},
	}
	for _, c := range cases {
		path := filepath.Join(t.TempDir(), "secret")
		if err := os.WriteFile(path, []byte("s"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, c.mode); err != nil {
			t.Fatal(err)
		}
		prev := readOnlyFS
		readOnlyFS = func(string) bool { return c.readOnly }
		err := Check(path)
		readOnlyFS = prev
		if c.wantErr != (err != nil) {
			t.Errorf("mode %04o, read-only %v: err = %v, want error %v", c.mode, c.readOnly, err, c.wantErr)
		}
		if err != nil {
			for _, want := range []string{path, "chmod 600", "chown", "65532", "read-only"} {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("mode %04o: error %q lacks %q (the file and both fixes)", c.mode, err, want)
				}
			}
		}
	}
}

// The real check, unstubbed: an always-true readOnlyFS would let every loose secret through.
func TestLooseSecretOnAWritableFileSystemIsRefused(t *testing.T) {
	path := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(path, []byte("s"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o644); err != nil { //nolint:gosec // G302: the mode under test
		t.Fatal(err)
	}
	if readOnlyFS(path) {
		t.Fatal("a writable temp directory was reported as a read-only mount")
	}
	if err := Check(path); err == nil {
		t.Fatal("a 0644 secret on a writable file system passed")
	}
}

func TestSymlinkedSecretIsJudgedByItsTarget(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	if err := os.WriteFile(target, []byte("s"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(target, 0o644); err != nil { //nolint:gosec // G302: the mode under test
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if err := Check(link); err == nil {
		t.Fatal("a 0644 target behind a symlink passed")
	}
}

func TestMissingSecretFileIsAnError(t *testing.T) {
	if err := Check(filepath.Join(t.TempDir(), "absent")); err == nil {
		t.Fatal("missing file passed")
	}
}
