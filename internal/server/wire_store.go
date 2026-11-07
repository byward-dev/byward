package server

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/byward-dev/byward/internal/audit"
	"github.com/byward-dev/byward/internal/config"
	"github.com/byward-dev/byward/internal/denylist"
	"github.com/byward-dev/byward/internal/health"
	"github.com/byward-dev/byward/internal/store"
	"github.com/byward-dev/byward/internal/store/sqlite"
	"github.com/byward-dev/byward/internal/token"
)

// readiness is what /readyz checks in authenticated mode: a signing key and the store. Never the
// IdP (ADR-0021 §10).
func readiness(ring *token.KeyRing, st pinger) []health.Check {
	checks := []health.Check{{Name: "keys", Ready: func(context.Context) error {
		if ring.SigningKeyID() == "" {
			return errors.New("no signing key")
		}
		return nil
	}}}
	return append(checks, health.Check{Name: "store", Ready: st.Ping})
}

// wireStore is openStore; tests replace it to reach the wired store.
var wireStore = openStore

// collectEvery is how often expired store rows are removed (ADR-0007 §1): grants, codes, refresh
// tokens, revocations older than store.RevocationRetention, and expired or never-used client
// registrations (ADR-0008 §3).
const collectEvery = 5 * time.Minute

// runBackground keeps the revocation list fresh and removes expired store rows until ctx ends,
// and returns only when both have stopped, so Run closes the store after the last write.
func runBackground(ctx context.Context, st store.Collector, deny *denylist.List, log *slog.Logger) {
	var wg sync.WaitGroup
	wg.Go(func() { collect(ctx, st, log) })
	deny.Run(ctx, log)
	wg.Wait()
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

// openStore opens the SQLite store and reports what it found (ADR-0007 §9): a database behind its
// counter file was restored from an older copy, so the store started a new epoch and refresh
// tokens from before the restore no longer work; users sign in again.
func openStore(cfg *config.Config, log *slog.Logger, rec *audit.Log) (*sqlite.Store, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	st, err := sqlite.Open(ctx, sqlite.Options{Dir: cfg.StoreDir, CounterFile: cfg.StoreCounterFile})
	if err != nil {
		return nil, fmt.Errorf("BYWARD_STORE_DIR / BYWARD_STORE_COUNTER_FILE: %w", err)
	}
	s := st.Startup()
	switch {
	case s.Restored:
		log.Warn("store restored from an older copy: a new epoch started, refresh tokens issued before the restore are refused and their users sign in again",
			"reason", "store_restore", "epoch", s.Epoch, "setting", "BYWARD_STORE_DIR", "value", cfg.StoreDir)
		rec.Record(nil, audit.Event{Name: audit.StoreRestored, Outcome: audit.Success, Reason: "restored from an older copy", Epoch: s.Epoch})
	case s.CounterMissing:
		log.Warn("store counter file missing: a restore of the state directory could not be detected at this start",
			"reason", "store_counter_missing", "setting", "BYWARD_STORE_COUNTER_FILE", "value", cfg.StoreCounterFile)
	}
	log.Info("store open", "setting", "BYWARD_STORE_DIR", "value", cfg.StoreDir, "epoch", s.Epoch)
	return st, nil
}
