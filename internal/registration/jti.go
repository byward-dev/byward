package registration

import (
	"context"
	"crypto/sha256"
	"errors"
	"time"

	"github.com/byward-dev/byward/internal/store"
)

// ErrJTICacheUnbound means Seen ran before Bind gave the cache its store; callers fail closed.
var ErrJTICacheUnbound = errors.New("registration: jti cache has no store yet")

// StoreJTICache is the JTICache over the store (ADR-0008 §6, #227), so an assertion spent on one
// replica is refused on every other. The store gets only SHA-256 of the key Seen is given.
type StoreJTICache struct {
	spent store.ClientAssertions
}

// NewStoreJTICache returns a cache over spent, which may be nil until Bind.
func NewStoreJTICache(spent store.ClientAssertions) *StoreJTICache {
	return &StoreJTICache{spent: spent}
}

// Bind gives the cache its store once it is open, before the first Seen: the static clients that
// hold the cache are built before the store opens, and `byward check --offline` builds them without
// one.
func (c *StoreJTICache) Bind(spent store.ClientAssertions) { c.spent = spent }

// Seen implements JTICache.
func (c *StoreJTICache) Seen(ctx context.Context, key string, now, expiresAt time.Time) (bool, error) {
	if c.spent == nil {
		return false, ErrJTICacheUnbound
	}
	switch err := c.spent.SpendAssertion(ctx, sha256.Sum256([]byte(key)), now, expiresAt); {
	case err == nil:
		return false, nil
	case errors.Is(err, store.ErrConsumed):
		return true, nil
	default:
		return false, err
	}
}
