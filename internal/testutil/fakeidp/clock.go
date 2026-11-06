package fakeidp

import (
	"sync"
	"time"
)

// Clock is a settable, goroutine-safe clock for WithClock and the adapters' Now settings.
type Clock struct {
	mu sync.Mutex
	t  time.Time
}

// NewClock starts a clock at t.
func NewClock(t time.Time) *Clock { return &Clock{t: t} }

// Now returns the clock's time.
func (c *Clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

// Advance moves the clock forward by d.
func (c *Clock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}
