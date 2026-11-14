package server

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/byward-dev/byward/internal/audit"
	"github.com/byward-dev/byward/internal/config"
)

// ErrNewEpochNeedsPostgres is NewEpoch's answer for the SQLite store, which finds a restore by
// itself at startup.
var ErrNewEpochNeedsPostgres = errors.New("new-epoch is for the PostgreSQL store (BYWARD_STORE_POSTGRES_DSN_FILE); the SQLite store finds a restore at startup from BYWARD_STORE_COUNTER_FILE (docs/how-to/state.md)")

// reasonNewEpoch is the store_restored reason of an operator's new-epoch.
const reasonNewEpoch = "operator new-epoch"

// NewEpoch is `byward store new-epoch` (ADR-0007 §9, amended for #227): the step after a pg_restore
// or a point-in-time recovery of the PostgreSQL store. It starts a new epoch, so refresh tokens
// from before it are refused and their users sign in again, and forgets every remembered consent.
// It runs beside running replicas, which adopt the epoch at once. It returns the new epoch.
func NewEpoch(ctx context.Context, cfg *config.Config, log *slog.Logger) (int64, error) {
	if cfg.NoAuth {
		return 0, errors.New("new-epoch needs the broker's store; it is off with BYWARD_INSECURE_NO_AUTH")
	}
	if cfg.StorePostgresDSN == "" {
		return 0, ErrNewEpochNeedsPostgres
	}
	octx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	st, err := openPostgres(octx, cfg, log)
	if err != nil {
		return 0, err
	}
	defer func() { _ = st.Close() }()
	epoch, err := st.NewEpoch(ctx)
	if err != nil {
		return 0, fmt.Errorf("starting a new epoch: %w", err)
	}
	logRestore(log, audit.New(log, nil, time.Now), epoch, "BYWARD_STORE_POSTGRES_DSN_FILE", st.Describe(), reasonNewEpoch)
	return epoch, nil
}
