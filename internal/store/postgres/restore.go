package postgres

import (
	"context"
	"fmt"
	"sync"

	"github.com/jackc/pgx/v5"
)

// Restore detection (ADR-0007 §9, amended for #227). Every write transaction takes a value from the
// store_writes sequence, and pg_dump saves the sequence with the data. Each replica keeps the highest
// value of its own transactions that committed: a sequence that reads lower than that came back from
// an older copy. Values of transactions that did not commit are never used: after a crash the
// sequence may lose them (postgresql.org/docs/current/functions-sequence.html), which must not look
// like a restore. Writes made while pg_dump runs are not covered: it reads the sequence outside its
// data snapshot.

// mark is what this replica has seen: the highest committed store_writes value, and the newest
// epoch.
type mark struct {
	mu     sync.Mutex
	writes int64
	epoch  int64
}

// committed raises the mark to a value of a transaction that committed.
func (m *mark) committed(writes int64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.writes = max(m.writes, writes)
}

func (m *mark) get() (writes, epoch int64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.writes, m.epoch
}

func (m *mark) sawEpoch(epoch int64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.epoch = max(m.epoch, epoch)
}

// reset follows a new epoch: the sequence went back, so the mark goes back with it.
func (m *mark) reset(writes, epoch int64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.writes, m.epoch = writes, epoch
}

// restoreLock is the advisory lock key a new epoch is started under, so replicas that see one
// restore together start one epoch. The bytes spell "byw:rest".
const restoreLock int64 = 0x6279773a72657374

// CheckRestore compares the store_writes sequence with this replica's mark; the server calls it as
// often as it syncs the deny list. A sequence below the mark means a restore: under restoreLock,
// unless another replica has started a new epoch since this one last looked, it starts one, as the
// SQLite store does at Open. It reports whether this replica started one (refresh tokens of older
// grants stopped working and every remembered consent was forgotten; the other replicas adopt the
// epoch and report false) and the current epoch.
func (s *Store) CheckRestore(ctx context.Context) (restored bool, epoch int64, err error) {
	r, err := s.checkRestore(ctx)
	return r.restored, r.epoch, err
}

// restore is what a check or a new epoch found.
type restore struct {
	restored bool
	epoch    int64
}

func (s *Store) checkRestore(ctx context.Context) (restore, error) {
	// The mark first: every value in it was taken from the sequence before the read below, so a
	// sequence that was not restored reads at least as high. Taken after, a write committing in
	// between would look like a restore.
	writes, seen := s.mark.get()
	var last, epoch int64
	var called bool
	if err := s.pool.QueryRow(ctx, "SELECT last_value, is_called, "+epochSQL+" FROM store_writes").Scan(&last, &called, &epoch); err != nil {
		return restore{}, fmt.Errorf("postgres store: restore check: %w", err)
	}
	if !called {
		last = 0 // a sequence nothing has taken from yet
	}
	if last >= writes {
		s.mark.sawEpoch(epoch)
		return restore{epoch: epoch}, nil
	}
	return s.newEpoch(ctx, seen)
}

// NewEpoch starts a new epoch whatever the sequence says: `byward store new-epoch`, the step after
// a pg_restore or a point-in-time recovery. It returns the new epoch.
func (s *Store) NewEpoch(ctx context.Context) (int64, error) {
	r, err := s.newEpoch(ctx, -1)
	return r.epoch, err
}

// newEpoch bumps the epoch past both the stored one and seen, and forgets every remembered consent
// (revocations made after the copy are lost with it), unless the stored epoch is already past seen:
// then another replica started it for the same restore, and this one adopts it. A seen of -1 always
// bumps. Either way the mark restarts from this transaction's own, committed, store_writes value.
func (s *Store) newEpoch(ctx context.Context, seen int64) (restore, error) {
	var r restore
	var writes int64
	err := retryLostRaces(ctx, func() error {
		r = restore{}
		return pgx.BeginTxFunc(ctx, s.pool, pgx.TxOptions{IsoLevel: pgx.ReadCommitted}, func(tx pgx.Tx) error {
			if _, err := tx.Exec(ctx, "SELECT pg_advisory_xact_lock($1)", restoreLock); err != nil {
				return err
			}
			var epoch int64
			if err := tx.QueryRow(ctx, "SELECT value FROM meta WHERE key = 'epoch' FOR UPDATE").Scan(&epoch); err != nil {
				return err
			}
			r.epoch = epoch
			if seen < 0 || epoch <= seen {
				r.restored, r.epoch = true, max(epoch, seen)+1
				if _, err := tx.Exec(ctx, "UPDATE meta SET value = $1 WHERE key = 'epoch'", r.epoch); err != nil {
					return err
				}
				if _, err := tx.Exec(ctx, "DELETE FROM consents"); err != nil {
					return err
				}
			}
			return tx.QueryRow(ctx, "SELECT nextval('store_writes')").Scan(&writes)
		})
	})
	if err != nil {
		return restore{}, fmt.Errorf("postgres store: new epoch: %w", err)
	}
	s.mark.reset(writes, r.epoch)
	return r, nil
}
