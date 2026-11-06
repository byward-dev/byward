//go:build linux

package token

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// The real read-only check, on a read-only tmpfs with the root mode Kubernetes uses. It needs
// root to mount, so it is skipped elsewhere.
func TestKeysOnAReadOnlyTmpfsWithMode1777Load(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("mounting a tmpfs needs root")
	}
	dir := t.TempDir()
	if out, err := exec.Command("mount", "-t", "tmpfs", "-o", "mode=1777", "tmpfs", dir).CombinedOutput(); err != nil {
		t.Skipf("cannot mount a tmpfs here: %v %s", err, out)
	}
	t.Cleanup(func() { _ = exec.Command("umount", dir).Run() })
	if err := os.WriteFile(filepath.Join(dir, "k1"), []byte(randomKey(t)), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadKeyRing(dir); err == nil || !strings.Contains(err.Error(), "world-writable") {
		t.Fatalf("writable tmpfs with mode 1777: err = %v, want the world-writable refusal", err)
	}
	if out, err := exec.Command("mount", "-o", "remount,ro", dir).CombinedOutput(); err != nil {
		t.Fatalf("remount read-only: %v %s", err, out)
	}
	mustRing(t, dir)
}
