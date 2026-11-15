// Package downstream gets the tokens an upstream needs to call a downstream API on the user's
// behalf (ADR-0017): one exchange per user and scopes, kept in a bounded in-memory cache until
// shortly before the token or the assertion it came from expires. Tokens are never stored or
// logged.
package downstream

import (
	"container/list"
	"context"
	"errors"
	"fmt"
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

// Outcomes of a request for a downstream token, each a byward_downstream_tokens_total label. The four
// refusals (ConsentRequired, InteractionRequired, Unavailable, Failed) are also the
// downstream_token_refused audit reason and the data.downstream of a refused request, and every
// outcome but Cached and Issued is also a token socket error code (ADR-0029,
// docs/reference/observability.md), so the strings never change.
const (
	Cached              = "cached"               // handed out from the cache
	Issued              = "issued"               // a new exchange
	ConsentRequired     = "consent_required"     // the downstream API's permissions are not consented
	InteractionRequired = "interaction_required" // Conditional Access needs the user
	Unavailable         = "unavailable"          // the IdP is unavailable: try later
	Failed              = "failed"               // anything else
	NoUser              = "no_user"              // no signed-in user to act for, such as an app-only caller
	SignInExpired       = "sign_in_expired"      // the grant's sign-in has ended: the next request brings a new one
)

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
	AssertionExpiresAt time.Time // zero when the IdP gave none: then only the token's own expiry counts
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

// errUnfinished is the waiters' error when the exchange ends its goroutine without returning or
// panicking (runtime.Goexit), so they never get an empty token without an error.
var errUnfinished = errors.New("downstream: the exchange did not finish")

// run performs the exchange for key, caches its token, and wakes every caller waiting for it. No
// HTTP handler's recover protects this goroutine, so a panicking exchange becomes the waiters' error
// instead of ending the process, as the JWKS refetch and the CIMD fetch do.
func (c *Cache) run(ctx context.Context, key string, u User, cl *call) {
	ctx, cancel := context.WithTimeout(ctx, ExchangeTimeout)
	defer cancel()
	defer func() {
		if p := recover(); p != nil {
			cl.token, cl.err = Token{}, fmt.Errorf("downstream: the exchange panicked: %v", p)
		}
		c.mu.Lock()
		delete(c.inFlight, key)
		if cl.err == nil && c.now().Before(cl.until) {
			c.add(key, cl.token, cl.until)
		}
		c.mu.Unlock()
		close(cl.done)
	}()
	cl.err = errUnfinished // a return or a panic replaces it; runtime.Goexit leaves it
	cl.token, cl.err = c.exchange(ctx, u.TenantID, u.Assertion, c.scopes)
	cl.until = cl.token.ExpiresAt.Add(-Margin)
	if !u.AssertionExpiresAt.IsZero() && u.AssertionExpiresAt.Before(cl.until) { // zero: the IdP gave no expiry
		cl.until = u.AssertionExpiresAt
	}
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
