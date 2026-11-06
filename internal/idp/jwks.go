package idp

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/go-jose/go-jose/v4"
)

// MinJWKSRefresh is the shortest interval between JWKS refetches for an unknown `kid`
// (ADR-0011 §7: rate-limited, unlike go-oidc's RemoteKeySet).
const MinJWKSRefresh = time.Minute

// KeySet caches an IdP's JWKS. An unknown kid triggers a refetch at most once per MinJWKSRefresh;
// the last good set stays in use when a refetch fails.
type KeySet struct {
	fetch *Fetcher
	url   string
	now   func() time.Time

	mu      sync.Mutex
	keys    jose.JSONWebKeySet
	fetched time.Time
	have    bool
}

// NewKeySet caches the JWKS at url.
func NewKeySet(f *Fetcher, url string, now func() time.Time) *KeySet {
	return &KeySet{fetch: f, url: url, now: now}
}

// Key returns the public key for kid ("" matches a set with a single key).
func (k *KeySet) Key(ctx context.Context, kid string) (*jose.JSONWebKey, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if key := k.lookup(kid); key != nil {
		return key, nil
	}
	if k.have && k.now().Sub(k.fetched) < MinJWKSRefresh {
		return nil, fmt.Errorf("idp: unknown key id %q", kid)
	}
	set, err := k.load(ctx)
	k.fetched = k.now()
	if err != nil {
		if k.have {
			return nil, fmt.Errorf("idp: unknown key id %q (JWKS refresh failed: %w)", kid, err)
		}
		return nil, fmt.Errorf("idp: fetch JWKS: %w", err)
	}
	k.keys, k.have = set, true
	if key := k.lookup(kid); key != nil {
		return key, nil
	}
	return nil, fmt.Errorf("idp: unknown key id %q", kid)
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
