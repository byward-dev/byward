// Package ratelimit limits requests to the broker's OAuth endpoints per client address (ADR-0018
// §8): a token bucket per endpoint and address, with IPv6 addresses grouped by /64. MCP traffic is
// never rate-limited (ADR-0001). Limits are in-process, so each replica has its own budget.
package ratelimit

import (
	"math"
	"net/netip"
	"sync"
	"time"
)

// The broker's OAuth endpoints, the names budgets are configured under.
const (
	Authorize = "authorize"
	Consent   = "consent"
	Callback  = "callback"
	Token     = "token"
	Revoke    = "revoke"
	Register  = "register"
)

// Endpoints lists every endpoint name, in the order the docs use.
var Endpoints = []string{Authorize, Consent, Callback, Token, Revoke, Register}

// Defaults returns the per-minute budgets of ADR-0018 §8 and its 2026-11-06 amendment: /consent
// serves a GET and a POST per sign-in, the IdP callback one per sign-in.
func Defaults() map[string]int {
	return map[string]int{Authorize: 30, Consent: 60, Callback: 30, Token: 60, Revoke: 30, Register: 30}
}

// sweepEvery bounds how often a full table is scanned for idle buckets.
const sweepEvery = time.Second

// Limiter holds one table of buckets per endpoint. A nil *Limiter allows everything.
type Limiter struct {
	tables  map[string]*table
	now     func() time.Time
	onLimit func(endpoint string)
}

type table struct {
	perMinute float64
	maxKeys   int

	mu        sync.Mutex
	buckets   map[string]*bucket
	overflow  *bucket
	lastSweep time.Time
}

type bucket struct {
	tokens float64
	last   time.Time
}

// New limits each endpoint in budgets to that many requests per minute per address, with a burst of
// the same size. Each endpoint tracks at most maxKeys addresses: idle buckets (refilled) are dropped
// to make room, and when none is idle new addresses share one overflow bucket, so an
// address-cycling flood degrades to a global limit instead of growing memory or failing open.
// onLimit, if set, is told every refused request.
func New(budgets map[string]int, maxKeys int, now func() time.Time, onLimit func(endpoint string)) *Limiter {
	l := &Limiter{tables: map[string]*table{}, now: now, onLimit: onLimit}
	for ep, n := range budgets {
		l.tables[ep] = &table{perMinute: float64(n), maxKeys: maxKeys, buckets: map[string]*bucket{}}
	}
	return l
}

// Allow takes one request for endpoint from ip. When refused, retryAfter is how long until the
// bucket has a token again. Endpoints without a budget are not limited.
func (l *Limiter) Allow(endpoint, ip string) (ok bool, retryAfter time.Duration) {
	if l == nil {
		return true, 0
	}
	t := l.tables[endpoint]
	if t == nil {
		return true, 0
	}
	ok, retryAfter = t.take(Key(ip), l.now())
	if !ok && l.onLimit != nil {
		l.onLimit(endpoint)
	}
	return ok, retryAfter
}

func (t *table) take(key string, now time.Time) (bool, time.Duration) {
	t.mu.Lock()
	defer t.mu.Unlock()
	b := t.buckets[key]
	if b == nil {
		if len(t.buckets) >= t.maxKeys && now.Sub(t.lastSweep) >= sweepEvery {
			t.lastSweep = now
			for k, old := range t.buckets {
				if t.refill(old, now) >= t.perMinute {
					delete(t.buckets, k)
				}
			}
		}
		switch {
		case len(t.buckets) < t.maxKeys:
			b = &bucket{tokens: t.perMinute, last: now}
			t.buckets[key] = b
		default:
			if t.overflow == nil {
				t.overflow = &bucket{tokens: t.perMinute, last: now}
			}
			b = t.overflow
		}
	}
	if t.refill(b, now) >= 1 {
		b.tokens--
		return true, 0
	}
	// Rounded to the microsecond first, so float drift cannot push a whole-second wait just past it.
	wait := math.Round((1-b.tokens)*60/t.perMinute*1e6) / 1e6
	return false, time.Duration(math.Ceil(wait * 1e9))
}

// refill adds the tokens earned since the bucket was last used, up to its capacity.
func (t *table) refill(b *bucket, now time.Time) float64 {
	if elapsed := now.Sub(b.last).Seconds(); elapsed > 0 {
		b.tokens = math.Min(t.perMinute, b.tokens+elapsed*t.perMinute/60)
		b.last = now
	}
	return b.tokens
}

// Key is the address a budget belongs to: the IPv4 address, or the IPv6 /64 (a client can rotate
// freely within its own /64). Unparseable values are used as they are.
func Key(ip string) string {
	a, err := netip.ParseAddr(ip)
	if err != nil {
		return ip
	}
	a = a.Unmap().WithZone("")
	if a.Is4() {
		return a.String()
	}
	p, _ := a.Prefix(64)
	return p.String()
}
