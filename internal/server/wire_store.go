package server

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/byward-dev/byward/internal/audit"
	"github.com/byward-dev/byward/internal/config"
	"github.com/byward-dev/byward/internal/denylist"
	"github.com/byward-dev/byward/internal/store"
	"github.com/byward-dev/byward/internal/store/postgres"
	"github.com/byward-dev/byward/internal/store/sqlite"
)

// openedStore is the store the server runs on: SQLite, or PostgreSQL for several replicas.
type openedStore interface {
	store.Store
	Ping(ctx context.Context) error
	Close() error
}

// restoreChecker is a store shared by replicas, which finds a restore while they run (PostgreSQL,
// ADR-0007 §9 as amended for #227); SQLite finds one at Open.
type restoreChecker interface {
	CheckRestore(ctx context.Context) (postgres.Restore, error)
}

// wireStore is openStore; tests replace it to reach the wired store.
var wireStore = openStore

// collectEvery is how often expired store rows are removed (ADR-0007 §1); store.Collector says
// which.
const collectEvery = 5 * time.Minute

// runBackground keeps the revocation list fresh, removes expired store rows and, when watch is not
// nil, watches for a restore, until ctx ends; it returns only when all have stopped, so Run closes
// the store after the last write.
func runBackground(ctx context.Context, st store.Collector, deny *denylist.List, log *slog.Logger, watch func(context.Context)) {
	var wg sync.WaitGroup
	wg.Go(func() { collect(ctx, st, log) })
	if watch != nil {
		wg.Go(func() { watch(ctx) })
	}
	deny.Run(ctx, log)
	wg.Wait()
}

// restoreCheckEvery is how often a replica compares the store with its mark: as often as it syncs
// the deny list, so a restore is found as soon as revocations made after the copy could be missed.
const restoreCheckEvery = 5 * time.Second

// watchRestore runs rc.CheckRestore every restoreCheckEvery until ctx ends. The replica that starts
// the new epoch logs and audits it, as a restore found at startup is; a failure is logged once until
// a check succeeds again.
func watchRestore(ctx context.Context, rc restoreChecker, log *slog.Logger, rec *audit.Log) {
	t := time.NewTicker(restoreCheckEvery)
	defer t.Stop()
	failing := false
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		r, err := rc.CheckRestore(ctx)
		switch {
		case err != nil && ctx.Err() == nil && !failing:
			failing = true
			log.ErrorContext(ctx, "checking the store for a restore failed", "error", err.Error())
		case err == nil:
			failing = false
			if r.Restored {
				logRestore(log, rec, r.Epoch, "BYWARD_STORE_POSTGRES_DSN_FILE", "", "restored from an older copy, found while running")
			}
		}
	}
}

// logRestore reports a new epoch started for a restore: a warning for the operator, and the
// store_restored audit event.
func logRestore(log *slog.Logger, rec *audit.Log, epoch int64, setting, value, reason string) {
	log.Warn("store restored from an older copy: a new epoch started, refresh tokens issued before the restore are refused and their users sign in again",
		"reason", "store_restore", "epoch", epoch, "setting", setting, "value", value)
	rec.Record(nil, audit.Event{Name: audit.StoreRestored, Outcome: audit.Success, Reason: reason, Epoch: epoch})
}

// collect runs store.Collect now and every collectEvery until ctx ends; a failure is logged and
// retried at the next tick.
func collect(ctx context.Context, st store.Collector, log *slog.Logger) {
	t := time.NewTicker(collectEvery)
	defer t.Stop()
	for {
		if err := st.Collect(ctx, time.Now()); err != nil && ctx.Err() == nil {
			log.ErrorContext(ctx, "removing expired store rows failed", "error", err.Error())
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// openStore opens the configured store: PostgreSQL when BYWARD_STORE_POSTGRES_DSN_FILE is set, else
// SQLite, which reports what it found (ADR-0007 §9): a database behind its counter file was restored
// from an older copy, so the store started a new epoch and refresh tokens from before the restore no
// longer work; users sign in again.
func openStore(cfg *config.Config, log *slog.Logger, rec *audit.Log) (openedStore, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if cfg.StorePostgresDSN != "" {
		return openPostgres(ctx, cfg, log)
	}
	st, err := sqlite.Open(ctx, sqlite.Options{Dir: cfg.StoreDir, CounterFile: cfg.StoreCounterFile})
	if err != nil {
		return nil, fmt.Errorf("BYWARD_STORE_DIR / BYWARD_STORE_COUNTER_FILE: %w", err)
	}
	s := st.Startup()
	switch {
	case s.Restored:
		logRestore(log, rec, s.Epoch, "BYWARD_STORE_DIR", cfg.StoreDir, "restored from an older copy")
	case s.CounterMissing:
		log.Warn("store counter file missing: a restore of the state directory could not be detected at this start",
			"reason", "store_counter_missing", "setting", "BYWARD_STORE_COUNTER_FILE", "value", cfg.StoreCounterFile)
	}
	log.Info("store open", "setting", "BYWARD_STORE_DIR", "value", cfg.StoreDir, "epoch", s.Epoch)
	return st, nil
}

// openPostgres opens the PostgreSQL store. Development mode accepts a connection without
// verify-full TLS, which config lists among its relaxations. The log names the database, never the
// DSN.
func openPostgres(ctx context.Context, cfg *config.Config, log *slog.Logger) (*postgres.Store, error) {
	st, err := postgres.Open(ctx, postgres.Options{DSN: cfg.StorePostgresDSN, AllowPlaintext: cfg.Dev})
	if err != nil {
		return nil, fmt.Errorf("BYWARD_STORE_POSTGRES_DSN_FILE: %w (see docs/how-to/postgres.md)", err)
	}
	log.Info("store open", "setting", "BYWARD_STORE_POSTGRES_DSN_FILE", "value", st.Describe()) // the database, never the DSN
	return st, nil
}

// restoreWatch is watchRestore for a store that checks for restores while running, or nil.
func restoreWatch(st openedStore, log *slog.Logger, rec *audit.Log) func(context.Context) {
	rc, ok := st.(restoreChecker)
	if !ok {
		return nil
	}
	return func(ctx context.Context) { watchRestore(ctx, rc, log, rec) }
}
