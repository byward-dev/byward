package logging

import (
	"errors"
	"io/fs"
)

// FileError is err, an error from opening, reading or checking a file, without the file's path: a
// *fs.PathError quotes it, and a setting or field meant to name a secret's file may hold the secret
// itself, pasted where the path belongs (security invariant 2). The cause is kept, so errors.Is still
// finds fs.ErrNotExist or fs.ErrPermission. An error that wraps a *fs.PathError is reduced to that
// cause, wrapping included; any other error is returned as it is, so a reader that reports a path
// in its own words must not be given to it.
func FileError(err error) error {
	if pe := (*fs.PathError)(nil); errors.As(err, &pe) {
		return pe.Err
	}
	return err
}
