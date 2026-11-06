package denylist

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/byward-dev/byward/internal/store"
)

// source is a store.Revocations whose content and failure the test controls.
type source struct {
	mu   sync.Mutex
	revs []store.Revocation
	err  error
}

func (s *source) Revocations(context.Context) ([]store.Revocation, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]store.Revocation(nil), s.revs...), s.err
}

func (s *source) set(revs []store.Revocation, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.revs, s.err = revs, err
}

var ctx = context.Background()

func mustSync(t *testing.T, l *List) {
	t.Helper()
	if err := l.Sync(ctx); err != nil {
		t.Fatal(err)
	}
}

func denied(t *testing.T, l *List, grant, subject string, iat time.Time) bool {
	t.Helper()
	d, err := l.Denied(grant, subject, iat)
	if err != nil {
		t.Fatalf("Denied: %v", err)
	}
	return d
}

func TestRefusesEverythingBeforeTheFirstSync(t *testing.T) {
	l := New(&source{}, nil)
	if _, err := l.Denied("g", "u", time.Now()); !errors.Is(err, errStale) {
		t.Fatalf("Denied before any sync = %v, want errStale", err)
	}
}

func TestDeniesRevokedGrantsAndTokensIssuedUpToTheSubjectCutOff(t *testing.T) {
	now := time.Date(2026, 11, 6, 12, 0, 0, 0, time.UTC)
	cut := now.Add(-time.Minute)
	src := &source{revs: []store.Revocation{
		{GrantID: "revoked", Before: now, At: now},
		{Subject: "tid:cut", Before: cut, At: now},
		{Subject: "tid:cut", Before: cut.Add(-time.Hour), At: now}, // the latest cut-off wins, whatever the row order
	}}
	l := New(src, func() time.Time { return now })
	mustSync(t, l)
	cases := []struct {
		name, grant, subject string
		iat                  time.Time
		want                 bool
	}{
		{"revoked grant", "revoked", "tid:other", now, true},
		{"other grant", "fine", "tid:other", now, false},
		{"issued before the cut-off", "fine", "tid:cut", cut.Add(-time.Second), true},
		{"issued at the cut-off", "fine", "tid:cut", cut, true},
		{"issued after the cut-off", "fine", "tid:cut", cut.Add(time.Second), false},
		{"cut-off of another subject", "fine", "tid:other", cut.Add(-time.Hour), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := denied(t, l, tc.grant, tc.subject, tc.iat); got != tc.want {
				t.Errorf("denied = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestListIsFreshThroughMaxStalenessAndStaleAfterUntilResynced(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		l := New(&source{}, nil)
		mustSync(t, l)
		time.Sleep(MaxStaleness) // fake time inside the bubble
		if _, err := l.Denied("g", "u", time.Now()); err != nil {
			t.Fatalf("at exactly MaxStaleness: %v, want still fresh", err)
		}
		time.Sleep(time.Nanosecond)
		if _, err := l.Denied("g", "u", time.Now()); !errors.Is(err, errStale) {
			t.Fatalf("past MaxStaleness: %v, want errStale", err)
		}
		mustSync(t, l)
		if _, err := l.Denied("g", "u", time.Now()); err != nil {
			t.Fatalf("after a new sync: %v", err)
		}
	})
}

func TestFailedSyncKeepsContentButAges(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		src := &source{revs: []store.Revocation{{GrantID: "revoked", At: time.Now()}}}
		l := New(src, nil)
		mustSync(t, l)
		src.set(nil, errors.New("store down"))
		if err := l.Sync(ctx); err == nil {
			t.Fatal("Sync succeeded although the store failed")
		}
		if !denied(t, l, "revoked", "u", time.Now()) {
			t.Fatal("a failed sync dropped what the list knew")
		}
		time.Sleep(MaxStaleness + time.Second)
		if _, err := l.Denied("fine", "u", time.Now()); !errors.Is(err, errStale) {
			t.Fatalf("store down for longer than MaxStaleness: %v, want errStale", err)
		}
	})
}

func TestLocalRevocationIsImmediateAndOutlivesALaggingStoreUntilRetentionEnds(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		src := &source{}
		l := New(src, nil)
		mustSync(t, l)
		l.Add("mine")
		if !denied(t, l, "mine", "u", time.Now()) {
			t.Fatal("a local revocation is not effective at once")
		}
		mustSync(t, l) // the store does not have it (yet, or its write failed)
		if !denied(t, l, "mine", "u", time.Now()) {
			t.Fatal("a sync dropped a local revocation the store does not have")
		}
		time.Sleep(store.RevocationRetention + time.Second)
		mustSync(t, l)
		if denied(t, l, "mine", "u", time.Now()) {
			t.Fatal("a local revocation was kept beyond RevocationRetention")
		}
	})
}

func TestRunKeepsTheListFreshAndStopsWithItsContext(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		src := &source{}
		l := New(src, nil)
		mustSync(t, l)
		runCtx, cancel := context.WithCancel(ctx)
		done := make(chan struct{})
		go func() { l.Run(runCtx, slog.New(slog.NewTextHandler(io.Discard, nil))); close(done) }()

		src.set([]store.Revocation{{GrantID: "later", At: time.Now()}}, nil)
		time.Sleep(3 * MaxStaleness)
		synctest.Wait()
		if !denied(t, l, "later", "u", time.Now()) {
			t.Fatal("Run did not pick up a new revocation")
		}
		cancel()
		<-done
	})
}
