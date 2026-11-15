//go:build !linux && !darwin

package secretfile

// ReadOnlyFS is unknown here, so no path counts as read-only and every permission rule applies.
func ReadOnlyFS(string) bool { return false }
