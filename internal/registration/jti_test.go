package registration

import (
	"context"
	"crypto/sha256"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/byward-dev/byward/internal/store/memory"
)

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time          { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *clock) advance(d time.Duration) { c.mu.Lock(); defer c.mu.Unlock(); c.t = c.t.Add(d) }

// An assertion ID is new once, a replay while it lives, and new again once it has expired; expiry
// is judged at the now the caller passes.
func TestAnAssertionIDIsSpentUntilItExpires(t *testing.T) {
	c := &clock{t: now}
	cache := NewStoreJTICache(memory.New())
	seen := func(key string, exp time.Duration) bool {
		t.Helper()
		s, err := cache.Seen(context.Background(), key, c.now(), c.now().Add(exp))
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

// recordingAssertions remembers the hashes it is given and answers with err.
type recordingAssertions struct {
	hashes [][sha256.Size]byte
	err    error
}

func (r *recordingAssertions) SpendAssertion(_ context.Context, h [sha256.Size]byte, _, _ time.Time) error {
	r.hashes = append(r.hashes, h)
	return r.err
}

// The store gets SHA-256 of the key, never the key itself.
func TestOnlyAHashOfTheReplayKeyReachesTheStore(t *testing.T) {
	rec := &recordingAssertions{}
	if _, err := NewStoreJTICache(rec).Seen(context.Background(), "client\x00jti", now, now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if len(rec.hashes) != 1 || rec.hashes[0] != sha256.Sum256([]byte("client\x00jti")) {
		t.Fatalf("hashes %x, want SHA-256 of the key", rec.hashes)
	}
}

// A cache without its store, or a store that fails, is an error, never "not seen": callers fail
// closed.
func TestACacheThatCannotAnswerFailsClosed(t *testing.T) {
	if s, err := NewStoreJTICache(nil).Seen(context.Background(), "x", now, now.Add(time.Minute)); s || !errors.Is(err, ErrJTICacheUnbound) {
		t.Fatalf("without a store: seen=%v, err=%v; want ErrJTICacheUnbound", s, err)
	}
	broken := errors.New("store down")
	if s, err := NewStoreJTICache(&recordingAssertions{err: broken}).Seen(context.Background(), "x", now, now.Add(time.Minute)); s || !errors.Is(err, broken) {
		t.Fatalf("with a failing store: seen=%v, err=%v; want the store's error", s, err)
	}
}
