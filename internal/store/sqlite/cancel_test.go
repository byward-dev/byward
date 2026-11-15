package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	msqlite "modernc.org/sqlite"
	sqlite3 "modernc.org/sqlite/lib"

	"github.com/byward-dev/byward/internal/store"
)

func consentOf(subject string) store.Consent {
	return store.Consent{Key: store.ConsentKey{Issuer: "https://idp.example/v2.0", Subject: subject, ClientID: "c",
		Redirect: "http://127.0.0.1/cb", Resource: "https://mcp.example.com/mcp"}, Scopes: []string{"mcp"}, ApprovedAt: t0, ExpiresAt: t0.Add(time.Hour)}
}

// onMirror makes do run inside every write from now on, once the mirror is written and before the
// commit: the window in which a cancelled transaction would leave the mirror ahead of the database.
func onMirror(t *testing.T, do func()) {
	t.Helper()
	t.Cleanup(func() { writeMirror = writeCounter })
	writeMirror = func(path string, v int64) error {
		err := writeCounter(path, v)
		do()
		return err
	}
}

// stored reports whether the consent is in s; any error but ErrNotFound fails the test.
func stored(t *testing.T, s *Store, c store.Consent) bool {
	t.Helper()
	_, err := s.Consent(ctx, c.Key)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		t.Fatal(err)
	}
	return err == nil
}

// A client hanging up, or a shutdown, cancels a write between its mirror and its commit. The write
// is still kept and says so, and the next start is a normal one: no false restore, no new epoch, and
// the remembered consents are kept.
func TestAWriteCancelledBetweenItsMirrorAndItsCommitIsKeptAndTheNextStartIsNormal(t *testing.T) {
	dir, counter := t.TempDir(), filepath.Join(t.TempDir(), "writes")
	s := open(t, dir, counter)
	alice, bob := consentOf("tid:alice"), consentOf("tid:bob")
	must(t, s.RememberConsent(ctx, alice))
	c, cancel := context.WithCancel(ctx)
	onMirror(t, cancel)
	if err := s.RememberConsent(c, bob); err != nil {
		t.Errorf("a write cancelled after its mirror = %v, want it committed", err)
	}
	if c.Err() == nil {
		t.Fatal("the write never reached its mirror: the cancel did not run")
	}
	if !stored(t, s, bob) {
		t.Error("the write cancelled after its mirror is not stored")
	}
	must(t, s.Close())
	again := open(t, dir, counter)
	if st := again.Startup(); st != (Startup{Epoch: 1}) {
		t.Fatalf("restart after a cancelled write: %+v, want a normal start at epoch 1", st)
	}
	if !stored(t, again, alice) || !stored(t, again, bob) {
		t.Fatal("remembered consents lost across the restart")
	}
}

// endsUnseen is a context that ends without database/sql noticing: its Done never closes, so only
// an explicit Err call sees the end. The test ends it after fn; the counter update does not notice,
// so only the ctx.Err poll before the mirror can. It stands for a cancellation that lands after the
// counter update, a window too small to hit on time, and does not tell a poll placed before the
// counter update from one after it: both still mean "an error is not stored". A check written as a
// select on Done would need this fake to close Done instead.
type endsUnseen struct {
	context.Context
	ended atomic.Bool
}

func (c *endsUnseen) Err() error {
	if c.ended.Load() {
		return context.Canceled
	}
	return nil
}

// A write whose context has ended by the time the mirror would be written stores nothing and reports
// the end: an error still means "not stored", and the next start is a normal one.
func TestAWriteWhoseContextEndsBeforeTheMirrorStoresNothing(t *testing.T) {
	dir, counter := t.TempDir(), filepath.Join(t.TempDir(), "writes")
	s := open(t, dir, counter)
	c := &endsUnseen{Context: ctx}
	err := s.write(c, func(tx *sql.Tx) error {
		// The write's effect, visible to the next start: a new epoch.
		_, err := tx.ExecContext(ctx, "UPDATE meta SET value = value + 1 WHERE key = 'epoch'")
		c.ended.Store(true) // fn is done; the counter update follows and does not see the end
		return err
	})
	if !errors.Is(err, context.Canceled) {
		t.Errorf("err = %v, want context.Canceled", err)
	}
	must(t, s.Close())
	// Committed anyway, the epoch is 2; mirrored but not committed, the start is a false restore.
	if st := open(t, dir, counter).Startup(); st != (Startup{Epoch: 1}) {
		t.Fatalf("restart after the ended write: %+v, want a normal start at epoch 1", st)
	}
}

// A write whose context has already ended stores nothing and reports the end.
func TestAWriteWithAnEndedContextStoresNothing(t *testing.T) {
	s := open(t, t.TempDir(), filepath.Join(t.TempDir(), "writes"))
	c, cancel := context.WithCancel(ctx)
	cancel()
	bob := consentOf("tid:bob")
	if err := s.RememberConsent(c, bob); !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
	if stored(t, s, bob) {
		t.Fatal("a write with an ended context was stored")
	}
}

// While the one connection is busy (a long write, Collect or Ping), a write still gives up at its
// deadline: the commit is detached from the context, the wait for the connection is not.
func TestAWriteWaitingForTheConnectionEndsAtItsDeadline(t *testing.T) {
	s := open(t, t.TempDir(), filepath.Join(t.TempDir(), "writes"))
	held, err := s.db.Conn(ctx)
	must(t, err)
	c, cancel := context.WithTimeout(ctx, 50*time.Millisecond)
	defer cancel()
	bob := consentOf("tid:bob")
	done := make(chan error, 1)
	go func() { done <- s.RememberConsent(c, bob) }()
	select {
	case err := <-done:
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("err = %v, want context.DeadlineExceeded", err)
		}
	case <-time.After(10 * time.Second): // a bound on failure only; the write is due after 50 ms
		_ = held.Close()
		t.Fatalf("the write waited past its deadline for the connection (once it was free: %v)", <-done)
	}
	must(t, held.Close())
	if stored(t, s, bob) {
		t.Fatal("a write that timed out was stored")
	}
}

// A write that cannot begin, because another process holds the database's write lock past the busy
// timeout, stores nothing and reports the driver's error.
func TestAWriteThatCannotBeginStoresNothingAndReportsWhy(t *testing.T) {
	dir := t.TempDir()
	s := open(t, dir, filepath.Join(t.TempDir(), "writes"))
	other, err := rawDB(t, dir).Conn(ctx)
	must(t, err)
	t.Cleanup(func() { _ = other.Close() })
	_, err = other.ExecContext(ctx, "BEGIN IMMEDIATE")
	must(t, err)
	_, err = s.db.ExecContext(ctx, "PRAGMA busy_timeout = 0") // the store's one connection: fail at once
	must(t, err)
	bob := consentOf("tid:bob")
	err = s.RememberConsent(ctx, bob)
	var se *msqlite.Error
	if !errors.As(err, &se) || se.Code()&0xff != sqlite3.SQLITE_BUSY {
		t.Fatalf("err = %v, want the driver's SQLITE_BUSY", err)
	}
	_, err = other.ExecContext(ctx, "ROLLBACK")
	must(t, err)
	if stored(t, s, bob) {
		t.Fatal("a write that could not begin was stored")
	}
}
