//go:build !linux && !darwin

package token

// readOnlyFS is unknown here, so a world-writable key directory is always rejected.
var readOnlyFS = func(string) bool { return false }
