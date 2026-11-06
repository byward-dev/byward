package ratelimit

import (
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type clock struct{ t time.Time }

func (c *clock) now() time.Time          { return c.t }
func (c *clock) advance(d time.Duration) { c.t = c.t.Add(d) }

func newClock() *clock { return &clock{t: time.Unix(1_800_000_000, 0)} }

func TestABurstOfTheBudgetPassesThenRetryAfterIsExact(t *testing.T) {
	c := newClock()
	var limited []string
	l := New(map[string]int{"authorize": 30}, 100, c.now, func(ep string) { limited = append(limited, ep) })
	for i := range 30 {
		if ok, _ := l.Allow("authorize", "192.0.2.1"); !ok {
			t.Fatalf("request %d of the 30/min burst was refused", i+1)
		}
	}
	ok, retry := l.Allow("authorize", "192.0.2.1")
	if ok || retry != 2*time.Second {
		t.Fatalf("31st request: ok=%v retryAfter=%v, want refused with 2s (30/min refills one every 2s)", ok, retry)
	}
	if len(limited) != 1 || limited[0] != "authorize" {
		t.Fatalf("onLimit calls = %v, want one for authorize", limited)
	}
	c.advance(2 * time.Second)
	if ok, _ := l.Allow("authorize", "192.0.2.1"); !ok {
		t.Fatal("after Retry-After the next request must pass")
	}
	if ok, _ := l.Allow("authorize", "192.0.2.1"); ok {
		t.Fatal("refill is linear: one token per 2s, not a fresh burst")
	}
}

func TestBudgetsArePerAddressAndPerEndpoint(t *testing.T) {
	c := newClock()
	l := New(map[string]int{"authorize": 1, "token": 1}, 100, c.now, nil)
	l.Allow("authorize", "192.0.2.1")
	if ok, _ := l.Allow("authorize", "192.0.2.2"); !ok {
		t.Error("another address shares the first one's budget")
	}
	if ok, _ := l.Allow("token", "192.0.2.1"); !ok {
		t.Error("another endpoint shares authorize's budget")
	}
	if ok, _ := l.Allow("metadata", "192.0.2.1"); !ok {
		t.Error("an endpoint without a budget is limited")
	}
}

// ADR-0018 §8: IPv6 is grouped by /64 (a client controls its whole /64), including IPv4-mapped forms.
func TestIPv6IsGroupedBy64(t *testing.T) {
	cases := map[string]string{
		"2001:db8:1:2:aaaa::1": "2001:db8:1:2::/64",
		"2001:db8:1:2:ffff::9": "2001:db8:1:2::/64",
		"2001:db8:1:3::1":      "2001:db8:1:3::/64",
		"192.0.2.7":            "192.0.2.7",
		"::ffff:192.0.2.7":     "192.0.2.7",
		"fe80::1%eth0":         "fe80::/64",
		"not-an-ip":            "not-an-ip",
	}
	for ip, want := range cases {
		if got := Key(ip); got != want {
			t.Errorf("Key(%q) = %q, want %q", ip, got, want)
		}
	}
	c := newClock()
	l := New(map[string]int{"token": 1}, 100, c.now, nil)
	l.Allow("token", "2001:db8:1:2:aaaa::1")
	if ok, _ := l.Allow("token", "2001:db8:1:2:bbbb::2"); ok {
		t.Error("an address in the same /64 got its own budget")
	}
}

func TestAFullTableSharesOneOverflowBucketUntilIdleBucketsAreDropped(t *testing.T) {
	c := newClock()
	l := New(map[string]int{"token": 1}, 2, c.now, nil)
	l.Allow("token", "192.0.2.1")
	l.Allow("token", "192.0.2.2")
	if ok, _ := l.Allow("token", "192.0.2.3"); !ok {
		t.Fatal("the first address over the key limit must get the overflow bucket's token")
	}
	ok, retry := l.Allow("token", "192.0.2.4")
	if ok || retry != time.Minute {
		t.Fatalf("a second address over the key limit: ok=%v retry=%v, want the shared overflow bucket to refuse with 1m", ok, retry)
	}
	c.advance(time.Minute) // every bucket is full again, so idle
	for _, ip := range []string{"192.0.2.6", "192.0.2.7"} {
		if ok, _ := l.Allow("token", ip); !ok {
			t.Fatalf("%s: idle buckets must be dropped so new addresses get their own", ip)
		}
	}
	if ok, _ := l.Allow("token", "192.0.2.7"); ok {
		t.Fatal("192.0.2.7 has its own bucket of 1 now, so its second request must be refused")
	}
	if ok, _ := l.Allow("token", "192.0.2.8"); !ok {
		t.Fatal("the table is full again: a new address shares the overflow bucket, which has refilled")
	}
	if ok, _ := l.Allow("token", "192.0.2.9"); ok {
		t.Fatal("the overflow bucket is shared: a second extra address must be refused")
	}
}

// The O(maxKeys) sweep runs at most once per sweepEvery, so an address-cycling flood cannot make
// every request scan the table.
func TestSweepsRunAtMostOncePerSweepEvery(t *testing.T) {
	c := newClock()
	l := New(map[string]int{"token": 600}, 2, c.now, nil) // 10 tokens a second
	drainOverflow := func() {
		for ok := true; ok; ok, _ = l.Allow("token", "192.0.2.3") {
		}
	}
	l.Allow("token", "192.0.2.1") // two buckets, each one token short of full
	l.Allow("token", "192.0.2.2")
	drainOverflow() // .3 finds the table full: a sweep runs now (nothing idle) and .3 uses the overflow
	c.advance(200 * time.Millisecond)
	// .1 and .2 are full again (idle), but the last sweep was 200 ms ago.
	drainOverflow()
	if ok, _ := l.Allow("token", "192.0.2.4"); ok {
		t.Fatal("a sweep ran within sweepEvery: .4 got its own bucket instead of the drained overflow")
	}
	c.advance(800 * time.Millisecond)
	drainOverflow()
	if ok, _ := l.Allow("token", "192.0.2.5"); !ok {
		t.Fatal("after sweepEvery the idle buckets must be swept so .5 gets its own bucket")
	}
}

func TestASweepKeepsBucketsThatAreStillInUse(t *testing.T) {
	c := newClock()
	l := New(map[string]int{"token": 2}, 1, c.now, nil)
	l.Allow("token", "192.0.2.1")
	l.Allow("token", "192.0.2.1")
	c.advance(2 * time.Second) // a sweep may run, but .1's bucket has refilled only a little
	l.Allow("token", "192.0.2.2")
	if ok, _ := l.Allow("token", "192.0.2.1"); ok {
		t.Fatal("192.0.2.1's bucket was swept while still empty, handing it a fresh budget")
	}
}

func TestRetryAfterHasNoFloatDrift(t *testing.T) {
	for _, perMinute := range []int{1, 3, 7, 30, 60, 600} {
		c := newClock()
		l := New(map[string]int{"token": perMinute}, 10, c.now, nil)
		for range perMinute {
			l.Allow("token", "192.0.2.1")
		}
		// Drain in uneven steps so the bucket's float state is not a round number.
		c.advance(13 * time.Millisecond)
		_, retry := l.Allow("token", "192.0.2.1")
		want := time.Minute/time.Duration(perMinute) - 13*time.Millisecond
		if d := retry - want; d < -time.Microsecond || d > time.Microsecond {
			t.Errorf("%d/min: retryAfter = %v, want %v within 1µs", perMinute, retry, want)
		}
	}
}

func TestConcurrentRequestsNeverExceedTheBudgets(t *testing.T) {
	c := newClock()
	const maxKeys, budget = 10, 3
	l := New(map[string]int{"token": budget}, maxKeys, c.now, nil)
	var wg sync.WaitGroup
	var allowed atomic.Int32
	for g := range 50 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range 20 {
				if ok, _ := l.Allow("token", fmt.Sprintf("192.0.2.%d", (g*20+i)%40)); ok {
					allowed.Add(1)
				}
			}
		}()
	}
	wg.Wait()
	// The clock does not move and every address is asked 25 times: the first maxKeys addresses drain
	// their own buckets and the rest drain the one shared overflow bucket.
	if n := allowed.Load(); n != (maxKeys+1)*budget {
		t.Fatalf("%d requests allowed, want exactly (maxKeys+1)*budget = %d", n, (maxKeys+1)*budget)
	}
}

// lockedClock may be advanced while other goroutines read it.
type lockedClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *lockedClock) now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *lockedClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

// Sweeps, evictions and overflow creation race with requests here; -race must stay quiet and
// the budget must hold for the time that passed.
func TestConcurrentRequestsWhileBucketsAreSweptStayWithinBudget(t *testing.T) {
	c := &lockedClock{t: time.Unix(1_800_000_000, 0)}
	const maxKeys, budget, rounds = 10, 3, 5
	l := New(map[string]int{"token": budget}, maxKeys, c.now, nil)
	var wg sync.WaitGroup
	var allowed atomic.Int32
	for g := range 20 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range 200 {
				if ok, _ := l.Allow("token", fmt.Sprintf("192.0.2.%d", (g*200+i)%60)); ok {
					allowed.Add(1)
				}
			}
		}()
	}
	for range rounds {
		c.advance(time.Minute) // each round every bucket refills and may be swept
	}
	wg.Wait()
	// Per minute at most maxKeys own buckets plus the overflow bucket can each spend a full budget.
	if n, ceiling := allowed.Load(), int32((rounds+1)*(maxKeys+1)*budget); n > ceiling {
		t.Fatalf("%d requests allowed over %d minutes, more than the %d the budgets permit", n, rounds, ceiling)
	}
}

func TestEveryEndpointHasADefaultBudget(t *testing.T) {
	d := Defaults()
	for _, ep := range Endpoints {
		if d[ep] < 1 {
			t.Errorf("endpoint %q has no default budget", ep)
		}
	}
	if len(d) != len(Endpoints) {
		t.Errorf("Defaults has %d endpoints, Endpoints lists %d", len(d), len(Endpoints))
	}
	d[Token] = 1
	if Defaults()[Token] == 1 {
		t.Error("Defaults must return a fresh copy each time")
	}
}

func TestNilLimiterAllowsEverything(t *testing.T) {
	var l *Limiter
	if ok, _ := l.Allow("token", "192.0.2.1"); !ok {
		t.Fatal("a nil limiter refused a request")
	}
}
