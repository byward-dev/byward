//go:build !linux && !darwin

package secretfile

// readOnlyFS is unknown here, so a group- or other-readable secret file is always refused.
var readOnlyFS = func(string) bool { return false }
