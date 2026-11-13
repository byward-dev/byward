package registration

import (
	"context"
	"crypto/sha256"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/byward-dev/byward/internal/store"
	"github.com/byward-dev/byward/internal/store/memory"
)

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time          { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *clock) advance(d time.Duration) { c.mu.Lock(); defer c.mu.Unlock(); c.t = c.t.Add(d) }

// An assertion ID is new once, a replay while it lives, and new again once it has expired.
func TestAnAssertionIDIsSpentUntilItExpires(t *testing.T) {
	c := &clock{t: now}
	cache := NewStoreJTICache(memory.New(), c.now)
	seen := func(jti string, exp time.Duration) bool {
		t.Helper()
		s, err := cache.Seen(context.Background(), jti, c.now().Add(exp))
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	if seen("a", time.Minute) || !seen("a", time.Minute) {
		t.Fatal("first use must be new, second a replay")
	}
	if seen("b", time.Hour) {
		t.Fatal("another ID reported as seen")
	}
	c.advance(2 * time.Minute)
	if seen("a", time.Minute) {
		t.Fatal("an expired ID still blocks its reuse")
	}
	if !seen("b", time.Hour) {
		t.Fatal("an unexpired ID was forgotten")
	}
}

// Two caches over one store are two replicas: an ID spent through one is a replay through the other.
func TestAnAssertionIDSpentOnOneReplicaIsAReplayOnAnother(t *testing.T) {
	st := memory.New()
	a, b := NewStoreJTICache(st, func() time.Time { return now }), NewStoreJTICache(st, func() time.Time { return now })
	if s, err := a.Seen(context.Background(), "x", now.Add(time.Minute)); err != nil || s {
		t.Fatalf("first use on A: seen=%v, %v", s, err)
	}
	if s, err := b.Seen(context.Background(), "x", now.Add(time.Minute)); err != nil || !s {
		t.Fatalf("replay on B: seen=%v, %v; want a replay", s, err)
	}
}

// recordingAssertions remembers the hashes it is given and answers with err.
type recordingAssertions struct {
	hashes [][sha256.Size]byte
	err    error
}

func (r *recordingAssertions) SpendAssertion(_ context.Context, h [sha256.Size]byte, _, _ time.Time) error {
	r.hashes = append(r.hashes, h)
	return r.err
}

// The store gets SHA-256 of what Seen is given, never the ID itself.
func TestOnlyAHashOfTheAssertionIDReachesTheStore(t *testing.T) {
	rec := &recordingAssertions{}
	if _, err := NewStoreJTICache(rec, func() time.Time { return now }).Seen(context.Background(), "client\x00jti", now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if len(rec.hashes) != 1 || rec.hashes[0] != sha256.Sum256([]byte("client\x00jti")) {
		t.Fatalf("hashes %x, want SHA-256 of the key", rec.hashes)
	}
}

// A cache without its store, or a store that fails, is an error, never "not seen": callers fail
// closed.
func TestACacheThatCannotAnswerFailsClosed(t *testing.T) {
	broken := errors.New("store down")
	for _, tc := range []struct {
		name  string
		spent store.ClientAssertions
		want  error
	}{
		{"no store yet", nil, ErrJTICacheUnbound},
		{"the store fails", &recordingAssertions{err: broken}, broken},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, err := NewStoreJTICache(tc.spent, func() time.Time { return now }).Seen(context.Background(), "x", now.Add(time.Minute))
			if s || !errors.Is(err, tc.want) {
				t.Fatalf("seen=%v, err=%v; want %v", s, err, tc.want)
			}
		})
	}
}
