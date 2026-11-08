//go:build linux

package stdio

import (
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
