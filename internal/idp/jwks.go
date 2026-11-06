package idp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/go-jose/go-jose/v4"
)

// MinJWKSRefresh is the shortest interval between JWKS refetches for an unknown `kid`
// (ADR-0011 §7: rate-limited, unlike go-oidc's RemoteKeySet).
const MinJWKSRefresh = time.Minute

// refetchTimeout bounds one background refetch: the Fetcher's retries at its 5 s timeout.
const refetchTimeout = 20 * time.Second

// ErrKeysUnavailable wraps every failure to fetch the JWKS; adapters class it Unavailable, not
// Fatal (ADR-0011 §1).
var ErrKeysUnavailable = errors.New("idp: JWKS unavailable")

// KeySet caches an IdP's JWKS. An unknown kid triggers a refetch at most once per MinJWKSRefresh;
// the last good set stays in use when a refetch fails. The refetch runs once at a time in the
// background, detached from any caller's context, so a caller that goes away neither cancels it
// nor uses up the interval; cached lookups never wait for it.
type KeySet struct {
	fetch *Fetcher
	url   string
	now   func() time.Time

	mu      sync.Mutex
	keys    jose.JSONWebKeySet
	fetched time.Time
	have    bool
	lastErr error         // the last refetch's error, nil after a success
	running chan struct{} // closed when the in-flight refetch ends; nil when none runs
}

// NewKeySet caches the JWKS at url.
func NewKeySet(f *Fetcher, url string, now func() time.Time) *KeySet {
	return &KeySet{fetch: f, url: url, now: now}
}

// Key returns the public key for kid ("" matches a set with a single key).
func (k *KeySet) Key(ctx context.Context, kid string) (*jose.JSONWebKey, error) {
	k.mu.Lock()
	if key := k.lookup(kid); key != nil {
		k.mu.Unlock()
		return key, nil
	}
	running := k.running
	if running == nil {
		if (k.have || k.lastErr != nil) && k.now().Sub(k.fetched) < MinJWKSRefresh {
			err := k.missing(kid)
			k.mu.Unlock()
			return nil, err
		}
		running = make(chan struct{})
		k.running = running
		// Detached from cancellation so a departing caller cannot abort the shared refetch.
		go k.refetch(context.WithoutCancel(ctx), running)
	}
	k.mu.Unlock()

	select {
	case <-running:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	if key := k.lookup(kid); key != nil {
		return key, nil
	}
	return nil, k.missing(kid)
}

// missing is the error for an absent kid; it wraps ErrKeysUnavailable when the last refetch
// failed. Caller holds k.mu.
func (k *KeySet) missing(kid string) error {
	if k.lastErr != nil {
		return fmt.Errorf("idp: key id %q not found: %w: %w", kid, ErrKeysUnavailable, k.lastErr)
	}
	return fmt.Errorf("idp: unknown key id %q", kid)
}

// refetch loads the JWKS and stores the result; it closes done when finished.
func (k *KeySet) refetch(parent context.Context, done chan struct{}) {
	ctx, cancel := context.WithTimeout(parent, refetchTimeout)
	defer cancel()
	set, err := k.load(ctx)
	k.mu.Lock()
	defer k.mu.Unlock()
	k.fetched, k.lastErr = k.now(), err
	if err == nil {
		k.keys, k.have = set, true
	}
	k.running = nil
	close(done)
}

// load fetches the JWKS (see ParseJWKS).
func (k *KeySet) load(ctx context.Context) (jose.JSONWebKeySet, error) {
	var raw json.RawMessage
	if err := k.fetch.GetJSON(ctx, k.url, &raw); err != nil {
		return jose.JSONWebKeySet{}, err
	}
	return ParseJWKS(raw)
}

// ParseJWKS parses a JWK Set, keeping each key that parses; keys of unknown or unsupported types
// are ignored rather than failing the whole set (RFC 7517 §5).
func ParseJWKS(data []byte) (jose.JSONWebKeySet, error) {
	var raw struct {
		Keys []json.RawMessage `json:"keys"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return jose.JSONWebKeySet{}, fmt.Errorf("idp: JWKS: %w", JSONError(err))
	}
	var set jose.JSONWebKeySet
	for _, r := range raw.Keys {
		var key jose.JSONWebKey
		if err := key.UnmarshalJSON(r); err == nil {
			set.Keys = append(set.Keys, key)
		}
	}
	return set, nil
}

// KeySource finds the public key for a JWT's kid.
type KeySource interface {
	Key(ctx context.Context, kid string) (*jose.JSONWebKey, error)
}

// StaticKeys is a fixed key set, e.g. a static client's registered JWKS. It applies the same
// signing-key filter as KeySet.
type StaticKeys jose.JSONWebKeySet

// Key returns the signing key for kid ("" matches a set with a single signing key).
func (s StaticKeys) Key(_ context.Context, kid string) (*jose.JSONWebKey, error) {
	if key := lookup(jose.JSONWebKeySet(s), kid); key != nil {
		return key, nil
	}
	return nil, fmt.Errorf("idp: unknown key id %q", kid)
}

// SigningKeys counts the keys in set that can verify signatures.
func SigningKeys(set jose.JSONWebKeySet) int {
	n := 0
	for i := range set.Keys {
		if signingKey(&set.Keys[i]) {
			n++
		}
	}
	return n
}

func (k *KeySet) lookup(kid string) *jose.JSONWebKey { return lookup(k.keys, kid) }

func lookup(set jose.JSONWebKeySet, kid string) *jose.JSONWebKey {
	var found *jose.JSONWebKey
	for i := range set.Keys {
		key := &set.Keys[i]
		if !signingKey(key) || (kid != "" && key.KeyID != kid) {
			continue
		}
		if kid != "" {
			return key
		}
		if found != nil {
			return nil // no kid and more than one candidate
		}
		found = key
	}
	return found
}

func signingKey(key *jose.JSONWebKey) bool {
	return (key.Use == "" || key.Use == "sig") && key.Valid() && key.IsPublic()
}
