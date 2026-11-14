//go:build !unix

package servingcert

import "io/fs"

// fileID is empty where the system gives no inode: size and modification time alone tell a
// change.
type fileID struct{}

func idOf(fs.FileInfo) fileID { return fileID{} }
