package server

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	"github.com/byward-dev/byward/internal/store"
	"github.com/byward-dev/byward/internal/store/sqlite"
)

// L152: a revocation on a store at another binary's schema version is refused naming the way out:
// the proxy's byward version, or (older) the upgraded proxy first; never a backup, which is a
// proxy start's way out of a newer schema. The adapters' tests show the refusal changes nothing.
func TestARevocationOnAnotherSchemaVersionNamesTheWayOut(t *testing.T) {
	for _, tc := range []struct {
		name  string
		delta int
		want  error
		fix   string
	}{
		{"older", -1, store.ErrOlderSchema, "run it with the proxy's byward version, or start the upgraded proxy first, which migrates"},
		{"newer", +1, store.ErrNewerSchema, "run the command with the proxy's byward version"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, cfg := storeEnv(t)
			withStore(t, cfg, func(*sqlite.Store) {})
			// The SQLite store keeps its schema version in user_version.
			db, err := sql.Open("sqlite", filepath.Join(cfg.StoreDir, "byward.db"))
			if err != nil {
				t.Fatal(err)
			}
			var v int
			if err := db.QueryRow("PRAGMA user_version").Scan(&v); err != nil {
				t.Fatal(err)
			}
			if _, err := db.Exec(fmt.Sprintf("PRAGMA user_version = %d", v+tc.delta)); err != nil {
				t.Fatal(err)
			}
			_ = db.Close()
			_, err = RevokeAll(context.Background(), cfg, discard)
			if !errors.Is(err, tc.want) || errors.Is(err, ErrNoStore) || !strings.HasPrefix(err.Error(), "BYWARD_STORE_DIR: ") || strings.Contains(err.Error(), cfg.StoreDir) || !strings.Contains(err.Error(), tc.fix) {
				t.Fatalf("RevokeAll = %v; want %v naming BYWARD_STORE_DIR, never its path (security invariant 2, #575), and %q", err, tc.want, tc.fix)
			}
			if strings.Contains(err.Error(), "backup") {
				t.Fatalf("RevokeAll = %v; an operator command's way out never mentions a backup", err)
			}
		})
	}
}
