package downstream

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"
)

var t0 = time.Unix(1_800_000_000, 0)

// fakeExchange issues numbered tokens valid for life, or fails while fail is set.
type fakeExchange struct {
	mu     sync.Mutex
	calls  int
	life   time.Duration
	now    *time.Time
	fail   error
	scopes []string
}

func (f *fakeExchange) exchange(_ context.Context, tid, _ string, scopes []string) (Token, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	f.scopes = scopes
	if f.fail != nil {
		return Token{}, f.fail
	}
	return Token{AccessToken: fmt.Sprintf("%s-token-%d", tid, f.calls), ExpiresAt: f.now.Add(f.life)}, nil
}

func newCache(life time.Duration, maxEntries int) (*Cache, *fakeExchange, *time.Time) {
	now := t0
	f := &fakeExchange{life: life, now: &now}
	return New(f.exchange, []string{"https://graph.microsoft.com/User.Read"}, maxEntries, func() time.Time { return now }), f, &now
}

func user(oid string) User {
	return User{TenantID: "tid", ObjectID: oid, Assertion: "assertion", AssertionExpiresAt: t0.Add(2 * time.Hour)}
}

// ADR-0017 §4: one exchange per user while the token is valid for more than the margin; at
// exp − 60 s the next request exchanges again.
func TestTokensAreCachedUntilAMinuteBeforeTheyExpire(t *testing.T) {
	c, f, now := newCache(time.Hour, 0)
	first, hit, err := c.Token(context.Background(), user("alice"))
	if err != nil || hit {
		t.Fatalf("first: %v, hit %v", err, hit)
	}
	*now = t0.Add(time.Hour - Margin - time.Nanosecond)
	again, hit, err := c.Token(context.Background(), user("alice"))
	if err != nil || !hit || again != first || f.calls != 1 {
		t.Fatalf("just before the margin: err %v, hit %v, same %v, %d exchanges, want the cached token", err, hit, again == first, f.calls)
	}
	*now = t0.Add(time.Hour - Margin)
	if _, hit, err := c.Token(context.Background(), user("alice")); err != nil || hit || f.calls != 2 {
		t.Fatalf("at the margin: err %v, hit %v, %d exchanges, want a new exchange", err, hit, f.calls)
	}
}

// ADR-0017 §4: never beyond the assertion's expiry, even when the token lives longer.
func TestTokensAreNotCachedBeyondTheAssertion(t *testing.T) {
	c, f, now := newCache(10*time.Hour, 0)
	u := user("alice")
	u.AssertionExpiresAt = t0.Add(30 * time.Minute)
	if _, _, err := c.Token(context.Background(), u); err != nil {
		t.Fatalf("first token: %v", err)
	}
	*now = t0.Add(30 * time.Minute)
	if _, hit, err := c.Token(context.Background(), u); err != nil || hit || f.calls != 2 {
		t.Fatalf("at the assertion's expiry: err %v, hit %v, %d exchanges, want a new exchange", err, hit, f.calls)
	}
}

// An assertion without a known expiry (the IdP sent no expires_in) does not bound the cache, as it
// does not cap the proxy's access token.
func TestAnAssertionWithoutAnExpiryDoesNotDisableTheCache(t *testing.T) {
	c, f, _ := newCache(time.Hour, 0)
	u := user("alice")
	u.AssertionExpiresAt = time.Time{}
	for i := range 2 {
		if _, _, err := c.Token(context.Background(), u); err != nil {
			t.Fatalf("lookup %d: %v", i, err)
		}
	}
	if f.calls != 1 {
		t.Fatalf("%d exchanges, want 1: the token was not cached", f.calls)
	}
}

// Errors are never cached, so a request after the administrator consented simply succeeds; and a
// token already inside the margin is handed out but not kept.
func TestErrorsAndShortLivedTokensAreNotCached(t *testing.T) {
	c, f, _ := newCache(time.Hour, 0)
	f.fail = errors.New("consent required")
	if _, _, err := c.Token(context.Background(), user("alice")); err == nil {
		t.Fatal("want the exchange error")
	}
	f.fail = nil
	if _, hit, err := c.Token(context.Background(), user("alice")); err != nil || hit || f.calls != 2 {
		t.Fatalf("after an error: %v, hit %v, %d exchanges, want a fresh exchange", err, hit, f.calls)
	}

	short, g, _ := newCache(Margin, 0)
	for range 2 {
		if _, hit, _ := short.Token(context.Background(), user("bob")); hit {
			t.Fatal("a token valid for no more than the margin was cached")
		}
	}
	if g.calls != 2 || short.Len() != 0 {
		t.Fatalf("%d exchanges, %d cached, want 2 and 0", g.calls, short.Len())
	}
}

// Each user has a token of their own: the key is the tenant, the object ID and the scopes, so the
// same object ID in another tenant is another user, and a renewed assertion is the same user.
func TestCacheIsPerUser(t *testing.T) {
	alice := user("alice")
	otherTenant, renewed := alice, alice
	otherTenant.TenantID = "other-tid"
	renewed.Assertion = "renewed-assertion"
	for _, c := range []struct {
		name      string
		other     User
		share     bool
		wantCalls int
	}{
		{"another object ID", user("bob"), false, 2},
		{"the same object ID in another tenant", otherTenant, false, 2},
		{"a renewed assertion", renewed, true, 1},
	} {
		t.Run(c.name, func(t *testing.T) {
			cache, f, _ := newCache(time.Hour, 0)
			first, _, err := cache.Token(context.Background(), alice)
			if err != nil {
				t.Fatalf("first lookup (alice): %v", err)
			}
			second, hit, err := cache.Token(context.Background(), c.other)
			if err != nil {
				t.Fatalf("second lookup (%s): %v", c.name, err)
			}
			if hit != c.share || (first == second) != c.share || f.calls != c.wantCalls {
				t.Fatalf("hit %v, same token %v, %d exchanges, want shared = %v and %d exchanges", hit, first == second, f.calls, c.share, c.wantCalls)
			}
		})
	}
}

// The cache keeps at most its bound, dropping the least recently used entry.
func TestCacheIsBounded(t *testing.T) {
	c, f, _ := newCache(time.Hour, 2)
	ctx := context.Background()
	for _, oid := range []string{"alice", "bob", "alice", "carol"} { // alice is used again, so carol evicts bob
		if _, _, err := c.Token(ctx, user(oid)); err != nil {
			t.Fatalf("%s: %v", oid, err)
		}
	}
	if c.Len() != 2 {
		t.Fatalf("%d cached, want the bound of 2", c.Len())
	}
	calls := f.calls
	_, hit, err := c.Token(ctx, user("alice"))
	if err != nil {
		t.Fatalf("alice: %v", err)
	}
	if !hit {
		t.Error("alice, the recently used entry, was evicted")
	}
	_, hit, err = c.Token(ctx, user("bob"))
	if err != nil {
		t.Fatalf("bob: %v", err)
	}
	if hit {
		t.Error("bob, the least recently used entry, was served from the cache")
	}
	if f.calls != calls+1 {
		t.Errorf("bob caused %d exchanges, want 1", f.calls-calls)
	}
}

// Concurrent requests for the same user share one exchange.
func TestConcurrentRequestsShareOneExchange(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		release := make(chan struct{})
		var calls atomic.Int32
		c := New(func(context.Context, string, string, []string) (Token, error) {
			calls.Add(1)
			<-release
			return Token{AccessToken: "t", ExpiresAt: t0.Add(time.Hour)}, nil
		}, []string{"s"}, 0, func() time.Time { return t0 })
		var wg sync.WaitGroup
		results := make([]Token, 8)
		for i := range results {
			wg.Go(func() { results[i], _, _ = c.Token(context.Background(), user("alice")) })
		}
		synctest.Wait() // every request is blocked: one in the exchange, the rest waiting for it
		close(release)
		wg.Wait()
		if calls.Load() != 1 {
			t.Fatalf("%d exchanges for concurrent requests, want 1", calls.Load())
		}
		for _, r := range results {
			if r.AccessToken != "t" {
				t.Fatalf("a request got %+v", r)
			}
		}
	})
}

// The scopes reach the exchange sorted, whatever order they were configured in.
func TestScopesAreSorted(t *testing.T) {
	now := t0
	f := &fakeExchange{life: time.Hour, now: &now}
	c := New(f.exchange, []string{"b", "a"}, 0, func() time.Time { return now })
	if _, _, err := c.Token(context.Background(), user("alice")); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(f.scopes, []string{"a", "b"}) {
		t.Fatalf("exchange got scopes %v from configured [b a], want [a b]", f.scopes)
	}
}

// The exchange is shared, so the request that started it giving up does not fail the others: it
// alone gets its context's error, and the token is still obtained and cached.
func TestARequestGivingUpDoesNotFailTheOthers(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		release := make(chan struct{})
		var calls atomic.Int32
		c := New(func(ctx context.Context, _, _ string, _ []string) (Token, error) {
			calls.Add(1)
			select {
			case <-release:
				return Token{AccessToken: "t", ExpiresAt: t0.Add(time.Hour)}, nil
			case <-ctx.Done():
				return Token{}, ctx.Err()
			}
		}, []string{"s"}, 0, func() time.Time { return t0 })
		leader, cancel := context.WithCancel(context.Background())
		var leaderErr, otherErr error
		var other Token
		var wg sync.WaitGroup
		wg.Go(func() { _, _, leaderErr = c.Token(leader, user("alice")) })
		synctest.Wait() // the leader's exchange is in flight
		wg.Go(func() { other, _, otherErr = c.Token(context.Background(), user("alice")) })
		synctest.Wait()
		cancel()
		synctest.Wait()
		close(release)
		wg.Wait()
		if !errors.Is(leaderErr, context.Canceled) {
			t.Errorf("the request that gave up: %v, want its own cancellation", leaderErr)
		}
		if otherErr != nil || other.AccessToken != "t" {
			t.Errorf("the other request: %+v, %v, want the shared exchange's token", other, otherErr)
		}
		if calls.Load() != 1 || c.Len() != 1 {
			t.Errorf("%d exchanges, %d cached, want 1 and 1", calls.Load(), c.Len())
		}
	})
}

// An exchange that hangs ends at ExchangeTimeout, even when its caller waits forever.
func TestAHangingExchangeTimesOut(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		c := New(func(ctx context.Context, _, _ string, _ []string) (Token, error) {
			<-ctx.Done()
			return Token{}, ctx.Err()
		}, []string{"s"}, 0, func() time.Time { return t0 })
		start := time.Now()
		_, _, err := c.Token(context.Background(), user("alice"))
		if !errors.Is(err, context.DeadlineExceeded) || time.Since(start) != ExchangeTimeout {
			t.Fatalf("err %v after %v, want the deadline after %v", err, time.Since(start), ExchangeTimeout)
		}
	})
}
