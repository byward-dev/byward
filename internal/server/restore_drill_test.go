//go:build integration

// Tests behind the integration tag must be named TestIntegration*: `mise run test:integration:go`
// (and its CI job) runs only those, so the unit suite is not run twice.
package server

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The restore drill (ADR-0007 §9, ADR-0024 integration lane): snapshot the state directory, keep
// writing, restore the snapshot over it with the restore counter untouched, and restart. The
// restored store starts a new epoch, a refresh token from before the restore is refused at
// /token, the restore is on the audit stream exactly once, and a new sign-in works again.
func TestIntegrationRestoreDrillRefusesRefreshTokensFromBeforeTheRestore(t *testing.T) {
	_, cfg := storeEnv(t)
	db := filepath.Join(cfg.StoreDir, "byward.db")

	_, wired, _, stopSeeding := signedInServer(t, cfg)
	before := seedSignedInUser(t, wired, "drill", time.Now())
	stopSeeding()

	// Snapshot: a copy of the database file, as a file-level backup makes. Closing the store
	// checkpoints the WAL, so the file alone holds the grant and the refresh token.
	if fi, err := os.Stat(db + "-wal"); err == nil && fi.Size() > 0 {
		t.Fatalf("%s-wal still holds %d bytes after close; the snapshot would miss them", db, fi.Size())
	}
	snapshot, err := os.ReadFile(db) //nolint:gosec // G304: the test's own temporary database
	if err != nil {
		t.Fatal(err)
	}

	// Writes after the snapshot: the user refreshes, which rotates the token and advances the
	// restore counter outside the state directory.
	s, _, _, stopWriting := signedInServer(t, cfg)
	if code, body := postRefresh(t, s, before); code != http.StatusOK || body["refresh_token"] == nil {
		t.Fatalf("refresh before the restore: %d %v, want a new token pair (the drill proves nothing otherwise)", code, body)
	}
	stopWriting()

	// Restore the snapshot over the state directory; the counter file is not part of the backup.
	for _, side := range []string{"-wal", "-shm"} {
		_ = os.Remove(db + side)
	}
	if err := os.WriteFile(db, snapshot, 0o600); err != nil { //nolint:gosec // G703: the test's own temporary database
		t.Fatal(err)
	}

	s, wired, logs, _ := signedInServer(t, cfg)
	// The snapshot holds this token as current, so only the new epoch refuses it.
	if code, body := postRefresh(t, s, before); code != http.StatusBadRequest || body["error"] != "invalid_grant" {
		t.Errorf("refresh token from before the restore: %d %v, want 400 invalid_grant", code, body)
	}
	if n := strings.Count(logs.String(), `"event":"store_restored"`); n != 1 {
		t.Errorf("store_restored audit records: %d, want 1\n%s", n, logs)
	}
	if !strings.Contains(logs.String(), `"epoch":2`) {
		t.Errorf("startup log does not report epoch 2:\n%s", logs)
	}
	// The new epoch does not refuse everything: a sign-in after the restore refreshes.
	after := seedSignedInUser(t, wired, "after-restore", time.Now())
	if code, body := postRefresh(t, s, after); code != http.StatusOK {
		t.Errorf("refresh token issued after the restore: %d %v, want a new token pair", code, body)
	}
}
