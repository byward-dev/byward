//go:build unix

package servingcert

import (
	"io/fs"
	"syscall"
)

// fileID is a file's device and inode: a file replaced by another, or a symlink pointed at
// another, has a new one even when its size and modification time are the same.
type fileID struct{ dev, ino uint64 }

func idOf(fi fs.FileInfo) fileID {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return fileID{}
	}
	return fileID{dev: uint64(st.Dev), ino: st.Ino} //nolint:gosec,unconvert // G115: Dev is int32 on darwin, uint64 on linux
}
