// Package downstream gets the tokens an upstream needs to call a downstream API on the user's
// behalf (ADR-0017): one exchange per user and scopes, kept in a bounded in-memory cache until
// shortly before the token or the assertion it came from expires. Tokens are never stored or
// logged.
package downstream

import (
	"container/list"
	"context"
	"slices"
	"strings"
	"sync"
	"time"
)

// Margin is how long before its expiry a cached token is no longer handed out (ADR-0017 §4).
const Margin = 60 * time.Second

// ExchangeTimeout bounds one exchange, which runs on after the caller that started it gives up.
const ExchangeTimeout = 30 * time.Second

// DefaultMaxEntries bounds the cache; the least recently used entry goes first.
const DefaultMaxEntries = 10_000

// Token is a downstream API access token; opaque to byward.
type Token struct {
	AccessToken string
	ExpiresAt   time.Time
}

// User is whom a token is for: the user key's tenant and object IDs (ADR-0012), and the
// assertion the exchange presents with its expiry.
type User struct {
	TenantID, ObjectID string
	Assertion          string
	AssertionExpiresAt time.Time
}

// Exchange obtains a token for the scopes on the user's behalf (Entra On-Behalf-Of).
type Exchange func(ctx context.Context, tenantID, assertion string, scopes []string) (Token, error)

// Cache hands out downstream tokens for one set of scopes. It is safe for concurrent use;
// concurrent requests for the same user share one exchange, and errors are never cached.
type Cache struct {
	exchange Exchange
	scopes   []string
	max      int
	now      func() time.Time

	mu       sync.Mutex
	entries  map[string]*list.Element // of *entry
	order    *list.List               // most recently used first
	inFlight map[string]*call
}

type entry struct {
	key   string
	token Token
	until time.Time
}

type call struct {
	done  chan struct{}
	token Token
	until time.Time
	err   error
}

// New returns a cache for scopes. max ≤ 0 means DefaultMaxEntries; now is the clock.
func New(exchange Exchange, scopes []string, maxEntries int, now func() time.Time) *Cache {
	if maxEntries <= 0 {
		maxEntries = DefaultMaxEntries
	}
	sorted := slices.Clone(scopes)
	slices.Sort(sorted)
	return &Cache{exchange: exchange, scopes: sorted, max: maxEntries, now: now,
		entries: map[string]*list.Element{}, order: list.New(), inFlight: map[string]*call{}}
}

// Token returns a token for u, from the cache while it is valid for at least Margin and its
// assertion has not expired, otherwise from a new exchange. It reports whether it came from the
// cache.
func (c *Cache) Token(ctx context.Context, u User) (Token, bool, error) {
	key := u.TenantID + "\x00" + u.ObjectID + "\x00" + strings.Join(c.scopes, " ")
	c.mu.Lock()
	if el, ok := c.entries[key]; ok {
		e := el.Value.(*entry)
		if c.now().Before(e.until) {
			c.order.MoveToFront(el)
			c.mu.Unlock()
			return e.token, true, nil
		}
		c.remove(el)
	}
	cl, ok := c.inFlight[key]
	if !ok {
		cl = &call{done: make(chan struct{})}
		c.inFlight[key] = cl
		// The exchange is shared, so no one caller's cancellation ends it.
		go c.run(context.WithoutCancel(ctx), key, u, cl)
	}
	c.mu.Unlock()
	select {
	case <-cl.done:
		return cl.token, false, cl.err
	case <-ctx.Done():
		return Token{}, false, ctx.Err()
	}
}

// run performs the exchange for key, caches its token, and wakes every caller waiting for it.
func (c *Cache) run(ctx context.Context, key string, u User, cl *call) {
	ctx, cancel := context.WithTimeout(ctx, ExchangeTimeout)
	defer cancel()
	cl.token, cl.err = c.exchange(ctx, u.TenantID, u.Assertion, c.scopes)
	cl.until = cl.token.ExpiresAt.Add(-Margin)
	if u.AssertionExpiresAt.Before(cl.until) {
		cl.until = u.AssertionExpiresAt
	}

	c.mu.Lock()
	delete(c.inFlight, key)
	if cl.err == nil && c.now().Before(cl.until) {
		c.add(key, cl.token, cl.until)
	}
	c.mu.Unlock()
	close(cl.done)
}

// Len is the number of cached tokens.
func (c *Cache) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.entries)
}

func (c *Cache) add(key string, t Token, until time.Time) {
	if el, ok := c.entries[key]; ok {
		c.remove(el)
	}
	for c.order.Len() >= c.max {
		c.remove(c.order.Back())
	}
	c.entries[key] = c.order.PushFront(&entry{key: key, token: t, until: until})
}

func (c *Cache) remove(el *list.Element) {
	delete(c.entries, el.Value.(*entry).key)
	c.order.Remove(el)
}
