package logging

import (
	"sync"
	"time"
)

// Limiter rate-limits log events per source (ADR-0021 §5): at most burst events per source in each
// window; the rest are counted and reported as `suppressed=N` on the next event that passes.
type Limiter struct {
	burst   int
	window  time.Duration
	maxKeys int
	now     func() time.Time

	mu      sync.Mutex
	sources map[string]*limit
}

type limit struct {
	start      time.Time
	passed     int
	suppressed int
}

// NewLimiter allows burst events per source per window and tracks at most maxKeys sources. When
// that many are tracked, sources whose window has ended are dropped (with any unreported
// suppressed count), and if none has ended a new source is refused: an attacker cycling addresses
// can neither flood the log nor grow the map.
func NewLimiter(burst int, window time.Duration, maxKeys int, now func() time.Time) *Limiter {
	return &Limiter{burst: burst, window: window, maxKeys: maxKeys, now: now, sources: map[string]*limit{}}
}

// Allow reports whether an event from source may be logged, and how many events from it were
// suppressed since the last one that was.
func (l *Limiter) Allow(source string) (ok bool, suppressed int) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	s := l.sources[source]
	if s == nil {
		if len(l.sources) >= l.maxKeys {
			l.dropEnded(now)
		}
		if len(l.sources) >= l.maxKeys {
			return false, 0
		}
		s = &limit{start: now}
		l.sources[source] = s
	}
	if now.Sub(s.start) >= l.window {
		s.start, s.passed = now, 0
	}
	if s.passed >= l.burst {
		s.suppressed++
		return false, 0
	}
	s.passed++
	suppressed, s.suppressed = s.suppressed, 0
	return true, suppressed
}

func (l *Limiter) dropEnded(now time.Time) {
	for k, s := range l.sources {
		if now.Sub(s.start) >= l.window {
			delete(l.sources, k)
		}
	}
}
