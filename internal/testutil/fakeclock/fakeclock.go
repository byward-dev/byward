// Package fakeclock is a settable, goroutine-safe clock for tests: pass its Now wherever code under
// test takes a func() time.Time.
package fakeclock

import (
	"sync"
	"time"
)

// Clock is a clock a test moves with Advance or Set.
type Clock struct {
	mu sync.Mutex
	t  time.Time
}

// New starts a clock at t.
func New(t time.Time) *Clock { return &Clock{t: t} }

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

// Set moves the clock to t.
func (c *Clock) Set(t time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = t
}
