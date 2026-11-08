//go:build darwin

package stdio

import (
	"fmt"

	"golang.org/x/sys/unix"
)

// peerCred is a socket peer's process and uid. macOS has no pidfd, so the PID-reuse race the stdio
// how-to describes for older Linux kernels applies. Weaker still: LOCAL_PEERCRED is the peer's
// credentials at connect, but LOCAL_PEERPID is the last process to use the peer's socket, which a
// process that passed its connection on would not be (xnu uipc_usrreq.c). macOS is for
// development only.
type peerCred struct {
	pid, uid int
}

func readPeerCred(fd int) (peerCred, error) {
	x, err := unix.GetsockoptXucred(fd, unix.SOL_LOCAL, unix.LOCAL_PEERCRED)
	if err != nil {
		return peerCred{}, fmt.Errorf("LOCAL_PEERCRED: %w", err)
	}
	pid, err := unix.GetsockoptInt(fd, unix.SOL_LOCAL, unix.LOCAL_PEERPID)
	if err != nil {
		return peerCred{}, fmt.Errorf("LOCAL_PEERPID: %w", err)
	}
	return peerCred{pid: pid, uid: int(x.Uid)}, nil
}

func (peerCred) release() {}

func (peerCred) stillSame() bool { return true }

// parentOf reads pid's parent from the kernel's process table.
func parentOf(pid int) (int, error) {
	k, err := unix.SysctlKinfoProc("kern.proc.pid", pid)
	if err != nil {
		return 0, err
	}
	if int(k.Proc.P_pid) != pid {
		return 0, fmt.Errorf("process %d is gone", pid)
	}
	return int(k.Eproc.Ppid), nil
}
