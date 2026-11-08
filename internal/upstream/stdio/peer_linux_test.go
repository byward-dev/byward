//go:build linux

package stdio

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

// SO_PEERPIDFD fails both on kernels without it and, on 6.5 and later, for a peer that has already
// exited: only the first may go unpinned.
func TestAPeerIsUnpinnedOnlyOnAKernelWithoutPidfds(t *testing.T) {
	for _, tc := range []struct {
		name      string
		fd        int
		err       error
		wantFD    int
		wantError bool
	}{
		{name: "pinned", fd: 9, wantFD: 9},
		{name: "a kernel before 6.5", err: unix.ENOPROTOOPT, wantFD: -1},
		{name: "a peer already reaped", err: unix.EINVAL, wantFD: -1, wantError: true},
		{name: "a peer that is gone", err: unix.ESRCH, wantFD: -1, wantError: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fd, err := pinPeer(func() (int, error) { return tc.fd, tc.err })
			if fd != tc.wantFD || (err != nil) != tc.wantError {
				t.Fatalf("got pidfd %d, error %v; want %d and an error %v", fd, err, tc.wantFD, tc.wantError)
			}
		})
	}
}

// A process chooses its own name, and /proc/<pid>/stat shows it in parentheses before the parent's
// PID: a name that looks like the rest of the line must not fake the ancestry.
func TestAProcessNameCannotFakeItsParent(t *testing.T) {
	sleep, err := exec.LookPath("sleep")
	if err != nil {
		t.Skip("no sleep binary")
	}
	src, err := os.ReadFile(sleep) //nolint:gosec // G304: copies the system sleep binary
	if err != nil {
		t.Fatal(err)
	}
	fake := filepath.Join(t.TempDir(), "x) S 1 1 (")
	if err := os.WriteFile(fake, src, 0o700); err != nil { //nolint:gosec // G306: an executable test binary
		t.Fatal(err)
	}
	c := exec.Command(fake, "30") //nolint:gosec // G204: the copy of sleep this test made
	if err := c.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Process.Kill(); _ = c.Wait() })
	if got, err := parentOf(c.Process.Pid); err != nil || got != os.Getpid() {
		t.Fatalf("parent %d, %v; want this test process %d", got, err, os.Getpid())
	}
}

// A pinned peer is the same process only while it lives: once reaped, its pidfd says so.
func TestAPinnedPeerIsTheSameProcessOnlyWhileItLives(t *testing.T) {
	c := exec.Command("sleep", "30")
	if err := c.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Process.Kill(); _ = c.Wait() })
	pidfd, err := unix.PidfdOpen(c.Process.Pid, 0)
	if err != nil {
		t.Skipf("no pidfd_open: %v", err)
	}
	t.Cleanup(func() { _ = unix.Close(pidfd) })
	if !(peerCred{pid: c.Process.Pid, pidfd: pidfd}).stillSame() {
		t.Fatal("a live peer is not the same process")
	}
	if (peerCred{pid: c.Process.Pid + 1, pidfd: pidfd}).stillSame() {
		t.Fatal("a pidfd of another process passed")
	}
	if (peerCred{pid: c.Process.Pid, pidfd: 1 << 20}).stillSame() {
		t.Fatal("an unreadable pidfd passed")
	}
	_ = c.Process.Kill()
	_ = c.Wait()
	if (peerCred{pid: c.Process.Pid, pidfd: pidfd}).stillSame() {
		t.Fatal("a reaped peer is still the same process")
	}
	if !(peerCred{pid: 42, pidfd: -1}).stillSame() {
		t.Fatal("an unpinned peer (a kernel before 6.5) has nothing to check, so it passes")
	}
}
