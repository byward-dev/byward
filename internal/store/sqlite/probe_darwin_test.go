package sqlite

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

// ufAppend is chflags(2)'s UF_APPEND: files may be added to the directory, never removed.
const ufAppend = 0x4

// A state directory where the write probe can be created but not removed is named by what it is,
// never by its path (security invariant 2, #575). Only an append-only directory does that, which
// macOS lets its owner set (chflags uappnd); Linux needs CAP_LINUX_IMMUTABLE.
func TestAWriteProbeThatCannotBeRemovedIsNamedWithoutItsPath(t *testing.T) {
	dir := t.TempDir()
	if err := syscall.Chflags(dir, ufAppend); err != nil {
		t.Skipf("cannot make the directory append-only: %v", err)
	}
	t.Cleanup(func() { _ = syscall.Chflags(dir, 0) })
	// A file system may take the flag without enforcing it.
	if f, err := os.CreateTemp(dir, "check-*"); err == nil {
		_ = f.Close()
		if os.Remove(f.Name()) == nil {
			t.Skip("the file system does not enforce append-only directories")
		}
	}
	_, err := Open(bounded(t), Options{Dir: dir, CounterFile: filepath.Join(t.TempDir(), "w")})
	if err == nil || err.Error() != "sqlite store: the state directory: operation not permitted" || strings.Contains(err.Error(), dir) {
		t.Fatalf("err = %v, want the state directory named by what it is and the cause alone", err)
	}
}
