//go:build linux || darwin

package secretfile

import "syscall"

// rdonly is ST_RDONLY in statfs(2) on Linux and MNT_RDONLY on macOS; both are 1. The syscall
// package exports neither name.
const rdonly = 0x1

// readOnlyFS reports whether path is on a file system mounted read-only.
var readOnlyFS = func(path string) bool {
	var st syscall.Statfs_t
	if err := syscall.Statfs(path, &st); err != nil {
		return false
	}
	return uint64(st.Flags)&rdonly != 0 //nolint:gosec // G115: Flags is non-negative on both systems
}
