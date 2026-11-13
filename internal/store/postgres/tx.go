package postgres

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// maxAttempts bounds the attempts of one write. Conflicting writes on one key commit one at a time,
// so this many attempts covers a burst of that many writers on the same key.
const maxAttempts = 40

// write runs fn in one SERIALIZABLE transaction that also takes a value from store_writes, retrying
// the whole transaction on a serialization failure, a deadlock or a unique violation. Every insert
// here checks for its key first, so a concurrent SERIALIZABLE insert of the same key surfaces as a
// serialization failure; one by a writer that is not SERIALIZABLE surfaces as a unique violation
// (postgresql.org/docs/current/transaction-iso.html). Either way the retry's own check then sees
// the key. fn must not keep state across attempts. Errors from fn, such as the store's, are
// returned as they are.
func (s *Store) write(ctx context.Context, fn func(pgx.Tx) error) error {
	return s.inTx(ctx, pgx.Serializable, fn)
}

// inTx runs fn in one transaction at iso that also takes a value from store_writes, retried as
// write says.
func (s *Store) inTx(ctx context.Context, iso pgx.TxIsoLevel, fn func(pgx.Tx) error) error {
	return retryLostRaces(ctx, func() error { return s.once(ctx, iso, fn) })
}

// retryLostRaces calls attempt until it succeeds, fails for another reason than a lost race, has
// run maxAttempts times, or ctx ends, waiting a random, growing pause between attempts so writers
// that collided do not collide again in step.
func retryLostRaces(ctx context.Context, attempt func() error) error {
	for n := 1; ; n++ {
		err := attempt()
		if err == nil || !retryable(err) {
			return err
		}
		if n == maxAttempts {
			return fmt.Errorf("postgres store: still conflicting after %d attempts: %w", n, err)
		}
		if ctx.Err() != nil { // checked first: a select with a timer that has also fired picks either
			return fmt.Errorf("postgres store: %w (after %w)", ctx.Err(), err)
		}
		wait := time.Duration(rand.Int64N(int64(min(time.Millisecond<<min(n, 7), 100*time.Millisecond)))) //nolint:gosec // G404: jitter, not a secret
		select {
		case <-ctx.Done():
			return fmt.Errorf("postgres store: %w (after %w)", ctx.Err(), err)
		case <-time.After(wait):
		}
	}
}

func (s *Store) once(ctx context.Context, iso pgx.TxIsoLevel, fn func(pgx.Tx) error) error {
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: iso})
	if err != nil {
		return fmt.Errorf("postgres store: begin: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }() // a no-op after Commit
	if err := fn(tx); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, "SELECT nextval('store_writes')"); err != nil {
		return fmt.Errorf("postgres store: write counter: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("postgres store: commit: %w", err)
	}
	return nil
}

// retryable: a transaction that lost a race and may succeed when run again.
func retryable(err error) bool {
	var pg *pgconn.PgError
	if !errors.As(err, &pg) {
		return false
	}
	switch pg.Code {
	case "40001", // serialization_failure
		"40P01", // deadlock_detected
		"23505": // unique_violation
		return true
	}
	return false
}
