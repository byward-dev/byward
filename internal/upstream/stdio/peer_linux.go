//go:build linux

package stdio

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"strconv"

	"golang.org/x/sys/unix"
)

// peerCred is a socket peer's process and uid. pidfd pins the process where the kernel supports
// SO_PEERPIDFD (Linux 6.5); -1 otherwise, which leaves a narrow PID-reuse race documented in the
// stdio how-to.
type peerCred struct {
	pid, uid int
	pidfd    int
}

func readPeerCred(fd int) (peerCred, error) {
	u, err := unix.GetsockoptUcred(fd, unix.SOL_SOCKET, unix.SO_PEERCRED)
	if err != nil {
		return peerCred{}, fmt.Errorf("SO_PEERCRED: %w", err)
	}
	pidfd, err := pinPeer(func() (int, error) { return unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_PEERPIDFD) })
	if err != nil {
		return peerCred{}, err
	}
	return peerCred{pid: int(u.Pid), uid: int(u.Uid), pidfd: pidfd}, nil
}

// pinPeer gets the peer's pidfd. Only a kernel without SO_PEERPIDFD (before 6.5: ENOPROTOOPT) goes
// unpinned (-1). Any other error refuses the peer rather than be taken for an old kernel, which
// would reopen the PID-reuse race. A peer already reaped is caught after the walk either way:
// newer kernels hand out a pidfd for it whose fdinfo shows "Pid: -1" (stillSame).
func pinPeer(get func() (int, error)) (int, error) {
	pidfd, err := get()
	switch {
	case err == nil:
		return pidfd, nil
	case errors.Is(err, unix.ENOPROTOOPT):
		return -1, nil
	}
	return -1, fmt.Errorf("SO_PEERPIDFD: %w", err)
}

func (c peerCred) release() {
	if c.pidfd >= 0 {
		_ = unix.Close(c.pidfd)
	}
}

// stillSame reports whether the pinned peer is still the process with pid: a pidfd's fdinfo shows
// "Pid: -1" once its process has exited. Without a pidfd there is nothing to check.
func (c peerCred) stillSame() bool {
	if c.pidfd < 0 {
		return true
	}
	info, err := os.ReadFile("/proc/self/fdinfo/" + strconv.Itoa(c.pidfd))
	if err != nil {
		return false
	}
	for line := range bytes.SplitSeq(info, []byte("\n")) {
		if v, ok := bytes.CutPrefix(line, []byte("Pid:")); ok {
			n, err := strconv.Atoi(string(bytes.TrimSpace(v)))
			return err == nil && n == c.pid
		}
	}
	return false
}

// parentOf reads pid's parent from /proc/<pid>/stat: the field after the command name, which is
// in parentheses and may itself contain spaces and parentheses.
func parentOf(pid int) (int, error) {
	stat, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
	if err != nil {
		return 0, err
	}
	i := bytes.LastIndexByte(stat, ')')
	if i < 0 {
		return 0, errors.New("unreadable /proc stat")
	}
	fields := bytes.Fields(stat[i+1:]) // state, ppid, ...
	if len(fields) < 2 {
		return 0, errors.New("unreadable /proc stat")
	}
	return strconv.Atoi(string(fields[1]))
}
