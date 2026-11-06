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

// load fetches the JWKS and keeps each key that parses; keys of unknown or unsupported types are
// ignored rather than failing the whole set (RFC 7517 §5).
func (k *KeySet) load(ctx context.Context) (jose.JSONWebKeySet, error) {
	var raw struct {
		Keys []json.RawMessage `json:"keys"`
	}
	if err := k.fetch.GetJSON(ctx, k.url, &raw); err != nil {
		return jose.JSONWebKeySet{}, err
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

func (k *KeySet) lookup(kid string) *jose.JSONWebKey {
	var found *jose.JSONWebKey
	for i := range k.keys.Keys {
		key := &k.keys.Keys[i]
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
