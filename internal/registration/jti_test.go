package registration

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time          { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *clock) advance(d time.Duration) { c.mu.Lock(); defer c.mu.Unlock(); c.t = c.t.Add(d) }

func TestMemoryJTICache(t *testing.T) {
	c := &clock{t: now}
	cache := NewMemoryJTICache(c.now, 2)
	ctx := context.Background()
	seen := func(jti string, exp time.Duration) bool {
		t.Helper()
		s, err := cache.Seen(ctx, jti, c.now().Add(exp))
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	if seen("a", time.Minute) || !seen("a", time.Minute) {
		t.Fatal("first use must be new, second a replay")
	}
	seen("b", time.Hour)
	if _, err := cache.Seen(ctx, "c", c.now().Add(time.Minute)); !errors.Is(err, ErrJTICacheFull) {
		t.Fatalf("full cache: %v", err)
	}
	c.advance(2 * time.Minute) // a expires, freeing a slot
	if seen("c", time.Minute) {
		t.Fatal("c reported as seen")
	}
	if !seen("b", time.Hour) {
		t.Fatal("unexpired b forgotten")
	}
	c.advance(2 * time.Minute) // c expires too
	if seen("a", time.Minute) {
		t.Fatal("expired a still blocks reuse")
	}
}

func TestMemoryJTICacheConcurrentUseCountsOnce(t *testing.T) {
	cache := NewMemoryJTICache(func() time.Time { return now }, 10)
	var wg sync.WaitGroup
	var mu sync.Mutex
	fresh := 0
	for range 16 {
		wg.Go(func() {
			s, err := cache.Seen(context.Background(), "x", now.Add(time.Minute))
			if err == nil && !s {
				mu.Lock()
				fresh++
				mu.Unlock()
			}
		})
	}
	wg.Wait()
	if fresh != 1 {
		t.Fatalf("jti accepted %d times", fresh)
	}
}
