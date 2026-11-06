// Package secretfile checks the files secrets are read from: the IdP client secret and static
// clients' `client_secret_file` (ADR-0018 §11). A secret that other users on the host can read is
// refused at startup; only --dev relaxes this.
package secretfile

import (
	"fmt"
	"os"
)

// Check refuses a secret file (symlinks followed) that its group or others can read or write.
// A file on a read-only mount passes: Kubernetes secret volumes and similar platform mounts are
// mode 0644 by default, are visible only inside the pod, and cannot be changed from it.
func Check(path string) error {
	fi, err := os.Stat(path)
	if err != nil {
		return err
	}
	if perm := fi.Mode().Perm(); perm&0o077 != 0 && !readOnlyFS(path) {
		return fmt.Errorf("secret file %s has mode %04o, so other users can read it; chmod 600 it and chown it to the proxy's user (uid 65532 in the image), or mount it read-only (e.g. docker run -v ./secret:/run/secrets/x:ro)", path, perm)
	}
	return nil
}
