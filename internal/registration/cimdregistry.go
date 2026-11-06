package registration

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/go-jose/go-jose/v4"

	"github.com/byward-dev/byward/internal/idp"
	"github.com/byward-dev/byward/internal/ssrfguard"
)

// ErrUnavailable means a client's metadata, or the keys at its jwks_uri, could not be fetched for
// now (network trouble, a 5xx, a rate limit) and no valid copy is cached: /token answers 503
// (draft -03 §6.1), /authorize an error page. It is never a reason to redirect to the client.
var ErrUnavailable = errors.New("registration: client metadata temporarily unavailable")

// ErrMetadataRefused wraps ErrUnknownClient when a client's metadata document was fetched (or its
// fetch definitely refused) and found unacceptable: not for a disabled CIMD, a host off the
// allowlist or a malformed client ID, which say nothing about the document. Refresh revokes the
// grant behind a token only for this (draft -03 §6.1).
var ErrMetadataRefused = fmt.Errorf("%w: client metadata refused", ErrUnknownClient)

// CIMD cache rules (ADR-0008 §4; draft -03 §6.1-6.2).
const (
	// MinCIMDTTL and MaxCIMDTTL clamp the cache lifetime a document's Cache-Control asks for. A
	// no-store or no-cache document is still reused for MinCIMDTTL: the per-URL rate limit that
	// §6.2 allows ("even if that results in fetching the URL less often than requested").
	MinCIMDTTL = time.Minute
	MaxCIMDTTL = 24 * time.Hour
	// MaxCIMDStale is how long after its fetch a valid copy may still be served while refetches
	// fail transiently (§6.1): network trouble, a timeout, a 5xx, 408 or 429. Another 4xx or an
	// invalid document drops it at once.
	MaxCIMDStale = 24 * time.Hour
	// MinCIMDRetry is the shortest interval between fetch attempts for one URL.
	MinCIMDRetry = 10 * time.Second
	// MaxCIMDEntries bounds the cache; MaxCIMDInFlight the concurrent fetches.
	MaxCIMDEntries  = 1000
	MaxCIMDInFlight = 16
)

// Fetch outcomes, for metrics (fixed values).
const (
	FetchOK          = "ok"
	FetchInvalid     = "invalid"     // the document failed validation
	FetchRefused     = "refused"     // the guard refused the address, or another 4xx, a redirect or an oversize body
	FetchUnavailable = "unavailable" // network trouble, a timeout, a 5xx, 408 or 429
	FetchRateLimited = "rate_limited"
	FetchBusy        = "busy" // MaxCIMDInFlight fetches already running
)

// MetadataFetcher fetches a client-supplied URL through the SSRF guard (ssrfguard.Fetcher).
type MetadataFetcher interface {
	Get(ctx context.Context, url string, maxBytes int64) (*ssrfguard.Response, error)
}

// CIMDConfig configures the CIMD registry.
type CIMDConfig struct {
	Fetch MetadataFetcher
	// KeysClient fetches jwks_uri; it must be the SSRF guard's client.
	KeysClient *http.Client
	// TrustedHosts are CIMD hosts the operator vouches for (trust level verified); AllowedHosts,
	// when non-empty, are the only other hosts accepted. Exact, lower-case ASCII host names.
	TrustedHosts, AllowedHosts []string
	// Deny is the operator's denylist; nil denies nothing.
	Deny *Denylist
	JTI  JTICache
	Now  func() time.Time
	// Observe counts each fetch attempt by outcome (one of the Fetch* values); nil ignores them.
	Observe func(outcome string)
}

// CIMDRegistry resolves clients whose ID is a Client ID Metadata Document URL.
type CIMDRegistry struct {
	cfg              CIMDConfig
	trusted, allowed map[string]bool
	slots            chan struct{}

	mu       sync.Mutex
	entries  map[string]*cimdEntry
	attempts map[string]attempt // last fetch attempt per URL, for URLs with no valid copy
	inflight map[string]*cimdCall
}

type cimdEntry struct {
	client           *cimdClient
	fetched, expires time.Time
	attempted        time.Time
}

// attempt is a fetch of a URL with no valid copy. A definite failure's error is repeated, not
// refetched, until MinCIMDRetry has passed: the per-URL rate limit §6.2 allows, which must not turn
// a refused client into a temporarily unavailable one.
type attempt struct {
	at  time.Time
	err error
}

type cimdCall struct {
	done    chan struct{}
	waiters int // lookups waiting on this fetch, under r.mu (observable in tests)
	client  *cimdClient
	err     error
}

// NewCIMDRegistry returns a CIMD registry.
func NewCIMDRegistry(c CIMDConfig) *CIMDRegistry {
	set := func(hosts []string) map[string]bool {
		m := map[string]bool{}
		for _, h := range hosts {
			m[strings.ToLower(h)] = true
		}
		return m
	}
	return &CIMDRegistry{cfg: c, trusted: set(c.TrustedHosts), allowed: set(c.AllowedHosts), slots: make(chan struct{}, MaxCIMDInFlight),
		entries: map[string]*cimdEntry{}, attempts: map[string]attempt{}, inflight: map[string]*cimdCall{}}
}

// Client returns the client for a CIMD URL: from the cache while fresh, otherwise fetched once
// however many requests ask at the same time. An unacceptable URL, host or document wraps
// ErrUnknownClient; a transient failure with no usable copy wraps ErrUnavailable.
func (r *CIMDRegistry) Client(ctx context.Context, id string) (Client, error) {
	if !IsCIMDURL(id) {
		return nil, ErrUnknownClient
	}
	if err := ValidateCIMDURL(id); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrUnknownClient, err)
	}
	if r.cfg.Deny.DeniesClient(id) {
		return nil, fmt.Errorf("%w: client %s is on the operator's denylist", ErrUnknownClient, id)
	}
	host := cimdHost(id)
	if len(r.allowed) > 0 && !r.allowed[host] && !r.trusted[host] {
		return nil, fmt.Errorf("%w: CIMD host %s is not allowed", ErrUnknownClient, host)
	}
	now := r.cfg.Now()
	r.mu.Lock()
	e := r.entries[id]
	if e != nil && now.Before(e.expires) {
		r.mu.Unlock()
		return e.client, nil
	}
	if call := r.inflight[id]; call != nil {
		call.waiters++
		r.mu.Unlock()
		return wait(ctx, call)
	}
	a := r.attempts[id]
	last := a.at
	if e != nil {
		last = e.attempted
	}
	if now.Sub(last) < MinCIMDRetry {
		r.mu.Unlock()
		r.observe(FetchRateLimited)
		if c := stale(e, now); c != nil {
			return c, nil
		}
		if a.err != nil {
			return nil, a.err
		}
		return nil, fmt.Errorf("%w: fetch attempts for %s are rate-limited", ErrUnavailable, host)
	}
	call := &cimdCall{done: make(chan struct{})}
	r.inflight[id] = call
	if e != nil {
		e.attempted = now
	} else {
		r.attempts[id] = attempt{at: now}
		r.pruneAttempts(now)
	}
	r.mu.Unlock()

	call.client, call.err = r.fetch(context.WithoutCancel(ctx), id, host, now)
	r.mu.Lock()
	delete(r.inflight, id)
	r.mu.Unlock()
	close(call.done)
	return call.client, call.err
}

func (r *CIMDRegistry) observe(outcome string) {
	if r.cfg.Observe != nil {
		r.cfg.Observe(outcome)
	}
}

func wait(ctx context.Context, call *cimdCall) (Client, error) {
	select {
	case <-call.done:
		if call.err != nil {
			return nil, call.err
		}
		return call.client, nil
	case <-ctx.Done():
		return nil, fmt.Errorf("%w: %v", ErrUnavailable, ctx.Err())
	}
}

func stale(e *cimdEntry, now time.Time) *cimdClient {
	if e != nil && now.Before(e.fetched.Add(MaxCIMDStale)) {
		return e.client
	}
	return nil
}

// fetch runs one fetch and records its outcome: a valid document is cached; a definite failure
// (refused, another 4xx, too large, invalid) drops any cached copy; a transient one (ssrfguard.Transient)
// keeps it (§6.1-6.2).
func (r *CIMDRegistry) fetch(ctx context.Context, id, host string, now time.Time) (*cimdClient, error) {
	select {
	case r.slots <- struct{}{}:
		defer func() { <-r.slots }()
	default:
		r.observe(FetchBusy)
		return r.staleOr(id, now, fmt.Errorf("%w: too many client metadata fetches in flight", ErrUnavailable))
	}
	res, err := r.cfg.Fetch.Get(ctx, id, MaxCIMDDocBytes)
	if err != nil {
		if ssrfguard.Transient(err) {
			r.observe(FetchUnavailable)
			return r.staleOr(id, now, fmt.Errorf("%w: %v", ErrUnavailable, err))
		}
		r.observe(FetchRefused)
		return nil, r.drop(id, fmt.Errorf("%w: %v", ErrMetadataRefused, err))
	}
	meta, err := parseCIMD(id, res.Body)
	if err != nil {
		r.observe(FetchInvalid)
		return nil, r.drop(id, fmt.Errorf("%w: %s: %v", ErrMetadataRefused, host, err))
	}
	c := r.build(id, host, meta)
	r.observe(FetchOK)
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.attempts, id)
	if len(r.entries) >= MaxCIMDEntries && r.entries[id] == nil {
		r.evictOne()
	}
	r.entries[id] = &cimdEntry{client: c, fetched: now, expires: now.Add(cacheTTL(res.Header)), attempted: now}
	return c, nil
}

func (r *CIMDRegistry) staleOr(id string, now time.Time, err error) (*cimdClient, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if c := stale(r.entries[id], now); c != nil {
		return c, nil
	}
	return nil, err
}

func (r *CIMDRegistry) drop(id string, err error) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	a := r.attempts[id]
	if e := r.entries[id]; e != nil {
		a.at = e.attempted
		delete(r.entries, id)
	}
	a.err = err
	r.attempts[id] = a
	return err
}

// evictOne removes the entry that expires first. Callers hold r.mu.
func (r *CIMDRegistry) evictOne() {
	var oldest string
	for id, e := range r.entries {
		if oldest == "" || e.expires.Before(r.entries[oldest].expires) {
			oldest = id
		}
	}
	delete(r.entries, oldest)
}

// pruneAttempts keeps the attempt log bounded. Callers hold r.mu.
func (r *CIMDRegistry) pruneAttempts(now time.Time) {
	if len(r.attempts) <= MaxCIMDEntries {
		return
	}
	for id, a := range r.attempts {
		if now.Sub(a.at) >= MinCIMDRetry {
			delete(r.attempts, id)
		}
	}
}

func (r *CIMDRegistry) build(id, host string, m *clientMetadata) *cimdClient {
	trust := Domain
	if r.trusted[host] {
		trust = Verified
	}
	return &cimdClient{metadataClient: newMetadataClient(id, m, trust, r.cfg.Deny, r.cfg.KeysClient, r.cfg.JTI, r.cfg.Now), host: host}
}

// clientKeys applies the registered-JWKS rules (public keys, RSA at least MinRSABits) to keys
// fetched from a jwks_uri.
type clientKeys struct{ idp.KeySource }

func (k clientKeys) Key(ctx context.Context, kid string) (*jose.JSONWebKey, error) {
	key, err := k.KeySource.Key(ctx, kid)
	if err != nil {
		return nil, err
	}
	if err := checkClientKey(*key); err != nil {
		return nil, fmt.Errorf("%w: jwks_uri: %v", ErrKeysRefused, err)
	}
	return key, nil
}

// cacheTTL is the document's Cache-Control lifetime clamped to MinCIMDTTL..MaxCIMDTTL; no-store,
// no-cache and a missing header get the minimum.
func cacheTTL(h http.Header) time.Duration {
	ttl := time.Duration(0)
	for _, d := range strings.Split(strings.ToLower(h.Get("Cache-Control")), ",") {
		d = strings.TrimSpace(d)
		switch {
		case d == "no-store", d == "no-cache":
			return MinCIMDTTL
		case strings.HasPrefix(d, "max-age="):
			if n, err := strconv.Atoi(strings.TrimPrefix(d, "max-age=")); err == nil && n > 0 {
				ttl = time.Duration(n) * time.Second
			}
		}
	}
	return min(max(ttl, MinCIMDTTL), MaxCIMDTTL)
}

// cimdClient is a client described by a Client ID Metadata Document.
type cimdClient struct {
	metadataClient
	host string
}

// MetadataHost is the host that published the client's metadata document, for the consent page.
func (c *cimdClient) MetadataHost() string { return c.host }

// Chain looks a client up in each registry in turn; the first that knows it answers.
type Chain []Registry

// Client returns the first answer that is not ErrUnknownClient; otherwise the error of the registry
// that owns the ID, the first that gave a reason (it still wraps ErrUnknownClient, so a CIMD
// refusal stays ErrMetadataRefused whatever follows it in the chain).
func (ch Chain) Client(ctx context.Context, id string) (Client, error) {
	err := ErrUnknownClient
	for _, r := range ch {
		c, e := r.Client(ctx, id)
		if !errors.Is(e, ErrUnknownClient) {
			return c, e
		}
		if err == ErrUnknownClient && e != ErrUnknownClient {
			err = e
		}
	}
	return nil, err
}
