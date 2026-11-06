// Package store is the broker's persistent state (ADR-0007): one narrow interface split by
// concern, with a conformance suite (storetest) every adapter must pass. Adapters live in
// internal/store/<impl>; only internal/server picks one.
package store

import (
	"context"
	"crypto/sha256"
	"errors"
	"time"
)

// Errors every adapter returns for these cases.
var (
	ErrNotFound = errors.New("store: not found")
	// ErrConsumed: an authorization code was already used. ADR-0006 §5: the caller revokes the
	// code's grant.
	ErrConsumed = errors.New("store: already consumed")
)

// Store is everything the broker keeps.
type Store interface {
	Grants
	Codes
	RefreshTokens
	Revocations
}

// Grant is one user's authorization of one MCP client (CONTEXT.md "Grant").
type Grant struct {
	ID       string
	ClientID string
	Subject  string // the IdP user key (`tid:oid` for Entra)
	Issuer   string // the IdP issuer
	Resource string
	Scopes   []string
	// IdPTokens are the IdP tokens, already encrypted by the caller (ADR-0006 §1, §8); the store
	// never sees them in clear. Nil when there are none.
	IdPTokens []byte
	CreatedAt time.Time
	ExpiresAt time.Time // absolute lifetime (ADR-0006 §5)
	Epoch     int64     // ADR-0007 §9; set by the store on create
}

// Grants stores grants.
type Grants interface {
	CreateGrant(ctx context.Context, g Grant) (Grant, error)
	Grant(ctx context.Context, id string) (Grant, error)
	// RevokeGrant deletes the grant with its codes and refresh tokens, and records a revocation.
	RevokeGrant(ctx context.Context, id string, at time.Time) error
}

// PendingCode is what an authorization code stands for until /token redeems it. The code given to
// the client is sealed (internal/token, type Code) and carries the grant ID; this record holds the
// rest and makes the code single-use.
type PendingCode struct {
	GrantID       string
	ClientID      string
	RedirectURI   string
	CodeChallenge string // S256
	Scopes        []string
	ExpiresAt     time.Time
}

// Codes stores pending authorization codes.
type Codes interface {
	PutCode(ctx context.Context, c PendingCode) error
	// ConsumeCode returns the code exactly once (an atomic conditional update). A second call
	// returns ErrConsumed; an unknown or expired code ErrNotFound.
	ConsumeCode(ctx context.Context, grantID string, now time.Time) (PendingCode, error)
}

// RefreshToken is a stored refresh token: only its hash (ADR-0006 §4).
type RefreshToken struct {
	Hash          [sha256.Size]byte
	GrantID       string
	ClientID      string
	CreatedAt     time.Time
	IdleExpiresAt time.Time // 14 days idle by default (ADR-0006 §5)
}

// RefreshTokens stores refresh tokens. Rotation and reuse detection arrive with slice 1.6.
type RefreshTokens interface {
	PutRefreshToken(ctx context.Context, t RefreshToken) error
	RefreshToken(ctx context.Context, hash [sha256.Size]byte) (RefreshToken, error)
}

// Revocation is one entry of the deny list (ADR-0006 §3): a revoked grant, or every grant of a
// subject issued before a time.
type Revocation struct {
	GrantID string // empty for a subject cut-off
	Subject string // empty for a single grant
	Before  time.Time
	At      time.Time
}

// Revocations feeds the in-memory deny list.
type Revocations interface {
	RevocationsSince(ctx context.Context, since time.Time) ([]Revocation, error)
}
