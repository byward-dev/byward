//go:build linux

package token

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

// The real read-only check, on a read-only tmpfs with the root mode Kubernetes uses. It needs
// root to mount, so it is skipped elsewhere.
func TestKeysOnAReadOnlyTmpfsWithMode1777Load(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("mounting a tmpfs needs root")
	}
	dir := t.TempDir()
	if err := syscall.Mount("tmpfs", dir, "tmpfs", 0, "mode=1777"); err != nil {
		t.Skipf("cannot mount a tmpfs here: %v", err)
	}
	t.Cleanup(func() { _ = syscall.Unmount(dir, 0) })
	if err := os.WriteFile(filepath.Join(dir, "k1"), []byte(randomKey(t)), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadKeyRing(dir); err == nil || !strings.Contains(err.Error(), "world-writable") {
		t.Fatalf("writable tmpfs with mode 1777: err = %v, want the world-writable refusal", err)
	}
	if err := syscall.Mount("", dir, "", syscall.MS_REMOUNT|syscall.MS_RDONLY, ""); err != nil {
		t.Fatalf("remount read-only: %v", err)
	}
	mustRing(t, dir)
}
