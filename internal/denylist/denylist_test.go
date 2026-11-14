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

// revoke-all: an explicit All cut-off denies every subject's tokens issued up to it. A revocation
// that names nothing (a zero value, however it got there) denies nobody.
func TestTheRevokeAllCutOffDeniesEverySubjectAndAnEmptyRevocationNobody(t *testing.T) {
	now := time.Date(2026, 11, 6, 12, 0, 0, 0, time.UTC)
	cut := now.Add(-time.Minute)
	for _, tc := range []struct {
		name string
		revs []store.Revocation
		iat  time.Time
		want bool
	}{
		{"before the revoke-all cut-off", []store.Revocation{{All: true, Before: cut, At: now}}, cut.Add(-time.Second), true},
		{"at the revoke-all cut-off", []store.Revocation{{All: true, Before: cut, At: now}}, cut, true},
		{"after the revoke-all cut-off", []store.Revocation{{All: true, Before: cut, At: now}}, cut.Add(time.Second), false},
		{"the latest revoke-all wins", []store.Revocation{{All: true, Before: cut, At: now}, {All: true, Before: cut.Add(-time.Hour), At: now}}, cut.Add(-time.Second), true},
		{"a zero-value revocation", []store.Revocation{{}}, cut.Add(-time.Hour), false},
		{"a revocation with only times", []store.Revocation{{Before: now, At: now}}, cut.Add(-time.Hour), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			l := New(&source{revs: tc.revs}, func() time.Time { return now })
			mustSync(t, l)
			for _, subject := range []string{"tid:alice", "tid:bob"} {
				if got := denied(t, l, "fine", subject, tc.iat); got != tc.want {
					t.Errorf("%s: denied = %v, want %v", subject, got, tc.want)
				}
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

// operatorRevocations collects what the list reports through OnOperatorRevocation.
func operatorRevocations(l *List) *[]store.Revocation {
	var got []store.Revocation
	l.OnOperatorRevocation(func(r store.Revocation) { got = append(got, r) })
	return &got
}

// An operator revocation (a subject or every-subject cut-off) made while the list runs is reported
// once, at the first sync that finds it; grant revocations, which are audited where they are made,
// never are; nor is one made before the list was created (a restart), which the revoking command
// records.
func TestEachNewOperatorRevocationIsReportedOnce(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		src := &source{}
		before := time.Now().Add(-time.Minute)
		src.set([]store.Revocation{{Subject: "tid:old", Before: before, At: before}}, nil)
		l := New(src, nil)
		got := operatorRevocations(l)
		mustSync(t, l)
		if len(*got) != 0 {
			t.Fatalf("a revocation from before the list was created was reported: %v", *got)
		}
		time.Sleep(time.Second)
		now := time.Now()
		user := store.Revocation{Subject: "tid:alice", Before: now, At: now}
		all := store.Revocation{All: true, Before: now, At: now}
		grant := store.Revocation{GrantID: "g1", Before: now, At: now}
		src.set([]store.Revocation{{Subject: "tid:old", Before: before, At: before}, user, all, grant}, nil)
		mustSync(t, l)
		mustSync(t, l)
		if len(*got) != 2 || (*got)[0] != user || (*got)[1] != all {
			t.Fatalf("reported %v, want the subject and the every-subject revocation once each", *got)
		}
	})
}

// A second revocation of the same user is its own: reported too, even with the same cut-off.
func TestARepeatedRevocationOfTheSameUserIsReportedAgain(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		src := &source{}
		l := New(src, nil)
		got := operatorRevocations(l)
		mustSync(t, l)
		time.Sleep(time.Second)
		before := time.Now()
		first := store.Revocation{Subject: "tid:alice", Before: before, At: before}
		second := store.Revocation{Subject: "tid:alice", Before: before, At: before.Add(time.Second)}
		src.set([]store.Revocation{first, second}, nil)
		mustSync(t, l)
		if len(*got) != 2 {
			t.Fatalf("reported %v, want both revocations", *got)
		}
	})
}

// Setting an observer replaces the earlier one.
func TestOnOperatorRevocationReplacesTheEarlierObserver(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		src := &source{}
		l := New(src, nil)
		first := 0
		l.OnOperatorRevocation(func(store.Revocation) { first++ })
		got := operatorRevocations(l)
		mustSync(t, l)
		time.Sleep(time.Second)
		now := time.Now()
		src.set([]store.Revocation{{Subject: "tid:alice", Before: now, At: now}}, nil)
		mustSync(t, l)
		if first != 0 || len(*got) != 1 {
			t.Fatalf("the earlier observer was called %d times after it was replaced; the new one %d", first, len(*got))
		}
	})
}

// The list reports a revocation only after it denies what the revocation covers.
func TestAnOperatorRevocationIsReportedOnlyOnceItIsEnforced(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		src := &source{}
		l := New(src, nil)
		mustSync(t, l)
		time.Sleep(time.Second)
		now := time.Now()
		enforced := false
		l.OnOperatorRevocation(func(store.Revocation) { enforced = denied(t, l, "g", "tid:alice", now.Add(-time.Second)) })
		src.set([]store.Revocation{{Subject: "tid:alice", Before: now, At: now}}, nil)
		mustSync(t, l)
		if !enforced {
			t.Fatal("the revocation was reported before the list denied the user's tokens")
		}
	})
}

// A failed sync reports nothing; the next good one reports what is new.
func TestAFailedSyncReportsNoOperatorRevocation(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		src := &source{}
		l := New(src, nil)
		got := operatorRevocations(l)
		mustSync(t, l)
		time.Sleep(time.Second)
		now := time.Now()
		src.set([]store.Revocation{{Subject: "tid:alice", Before: now, At: now}}, errors.New("store down"))
		if err := l.Sync(ctx); err == nil {
			t.Fatal("the failing sync succeeded")
		}
		if len(*got) != 0 {
			t.Fatalf("a failed sync reported %v", *got)
		}
		src.set([]store.Revocation{{Subject: "tid:alice", Before: now, At: now}}, nil)
		mustSync(t, l)
		if len(*got) != 1 {
			t.Fatalf("reported %v after the store recovered, want the revocation once", *got)
		}
	})
}

// What the list remembers of reported revocations stays within the retention window: an older
// revocation is forgotten, never reported again although the store still returns it, and never
// remembered again. Forgetting has no other visible effect, so the bound is read from the field.
func TestTheReportedSetStaysWithinTheRetentionWindow(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		src := &source{}
		l := New(src, nil)
		got := operatorRevocations(l)
		mustSync(t, l)
		time.Sleep(time.Second)
		now := time.Now()
		rev := store.Revocation{Subject: "tid:alice", Before: now, At: now}
		src.set([]store.Revocation{rev}, nil)
		mustSync(t, l)
		if len(*got) != 1 {
			t.Fatalf("reported %v, want the revocation once", *got)
		}
		time.Sleep(store.RevocationRetention + time.Second)
		mustSync(t, l) // the store has not collected the row yet
		mustSync(t, l)
		if len(*got) != 1 {
			t.Fatalf("reported %v, want the expired revocation not reported again", *got)
		}
		if len(l.reported) != 0 {
			t.Fatalf("still remembering %d revocations past the retention window", len(l.reported))
		}
	})
}
