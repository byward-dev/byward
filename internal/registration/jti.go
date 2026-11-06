package registration

import (
	"context"
	"errors"
	"sync"
	"time"
)

// ErrJTICacheFull means the in-memory cache holds MaxEntries unexpired IDs; callers fail closed.
var ErrJTICacheFull = errors.New("registration: jti cache full")

// MemoryJTICache is a JTICache for a single replica.
type MemoryJTICache struct {
	now        func() time.Time
	maxEntries int

	mu   sync.Mutex
	seen map[string]time.Time
}

// NewMemoryJTICache returns a cache holding at most maxEntries unexpired IDs; now is the clock.
func NewMemoryJTICache(now func() time.Time, maxEntries int) *MemoryJTICache {
	return &MemoryJTICache{now: now, maxEntries: maxEntries, seen: map[string]time.Time{}}
}

// Seen records jti until expiresAt and reports whether it was already recorded and unexpired.
func (c *MemoryJTICache) Seen(_ context.Context, jti string, expiresAt time.Time) (bool, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.now()
	if exp, ok := c.seen[jti]; ok && now.Before(exp) {
		return true, nil
	}
	if len(c.seen) >= c.maxEntries {
		for k, exp := range c.seen {
			if !now.Before(exp) {
				delete(c.seen, k)
			}
		}
		if len(c.seen) >= c.maxEntries {
			return false, ErrJTICacheFull
		}
	}
	c.seen[jti] = expiresAt
	return false, nil
}
