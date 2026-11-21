package secretfile

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSecretFilesOthersCanReachAreRefusedUnlessReadOnly(t *testing.T) {
	cases := []struct {
		mode     os.FileMode
		readOnly bool
		inErr    string // "" when the file passes
	}{
		{0o600, false, ""},
		{0o400, false, ""},
		{0o640, false, "has mode 0640, so other users can access it;"},
		{0o604, false, "has mode 0604, so other users can access it;"},
		{0o620, false, "has mode 0620, so other users can access it;"},
		// Execute alone gives no read, but is still a permission for others (#473).
		{0o610, false, "has mode 0610, so other users can access it;"},
		{0o601, false, "has mode 0601, so other users can access it;"},
		{0o644, true, ""}, // Kubernetes secret volume default
		{0o444, true, ""},
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
		switch {
		case c.inErr == "" && err != nil:
			t.Errorf("mode %04o, read-only %v: err = %v, want no error", c.mode, c.readOnly, err)
		case c.inErr != "" && err == nil:
			t.Errorf("mode %04o, read-only %v: no error, want one containing %q", c.mode, c.readOnly, c.inErr)
		}
		if err != nil {
			for _, want := range []string{c.inErr, "chmod 600", "chown", "65532", "read-only"} {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("mode %04o: error %q lacks %q (the reason and both fixes)", c.mode, err, want)
				}
			}
			// The caller names the setting or field; the path never shows (security invariant 2, #575).
			if strings.Contains(err.Error(), path) {
				t.Errorf("mode %04o: error %q shows the file's path", c.mode, err)
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

// A missing secret file is refused by its cause alone, never its path (security invariant 2, #575):
// a TLS key removed while byward runs is logged through it.
func TestAMissingSecretFileIsNamedByItsCauseNeverItsPath(t *testing.T) {
	if err := Check(filepath.Join(t.TempDir(), "absent")); !errors.Is(err, fs.ErrNotExist) || err.Error() != "no such file or directory" {
		t.Fatalf("err = %v, want the cause without the path", err)
	}
}
