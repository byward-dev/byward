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
	// ErrExists: a grant ID, a grant's code or a refresh-token hash is already stored.
	ErrExists = errors.New("store: already exists")
	// ErrInvalid: a grant without an ID, client, subject or a lifetime, or a subject cut-off
	// without a subject. An empty subject in a Revocation must never reach the deny list.
	ErrInvalid = errors.New("store: invalid argument")
	// ErrRevoked: CreateGrant for a subject whose retained cut-off covers the grant (a login that
	// was in flight when revoke-user ran).
	ErrRevoked = errors.New("store: subject revoked")
)

// RevocationRetention is how long revocations are kept: the longest access-token lifetime
// (ADR-0006 §3, §5). After it, every token a revocation covers has expired anyway. It must stay
// at least the configured maximum access-token lifetime.
//
// Adapters may keep times at microsecond precision (PostgreSQL timestamptz); callers must not
// rely on finer differences.
const RevocationRetention = time.Hour

// Store is everything the broker keeps.
//
// Values passed in and returned are copies: changing a slice after a call never changes what is
// stored. Codes and refresh tokens belong to a grant that must exist (ErrNotFound otherwise) and go
// when it goes.
type Store interface {
	Grants
	Codes
	RefreshTokens
	Revocations
	Collector
}

// Collector removes expired rows (ADR-0007 §1).
type Collector interface {
	// Collect deletes codes (pending or consumed) with ExpiresAt <= now, refresh tokens with
	// IdleExpiresAt <= now, grants with ExpiresAt <= now together with their codes and refresh
	// tokens, and revocations with At <= now - RevocationRetention.
	Collect(ctx context.Context, now time.Time) error
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
	// CreateGrant stores g and returns it with Epoch set. An existing ID is ErrExists; an empty ID,
	// ClientID or Subject, or an ExpiresAt not after CreatedAt, is ErrInvalid; a retained subject
	// cut-off with Before after g.CreatedAt is ErrRevoked. The cut-off check and the insert are one
	// atomic step, so a grant never outlives a RevokeSubject that should have covered it.
	//
	// SQL adapters must serialize CreateGrant and RevokeSubject per subject: under READ COMMITTED
	// each can miss the other's uncommitted row and both commit (write skew). PostgreSQL: take
	// pg_advisory_xact_lock(hashtext(subject)) first in both, or run them SERIALIZABLE and retry
	// on 40001. SQLite: one writer, and both start with BEGIN IMMEDIATE.
	CreateGrant(ctx context.Context, g Grant) (Grant, error)
	// Grant returns the grant, or ErrNotFound. It does not check ExpiresAt.
	Grant(ctx context.Context, id string) (Grant, error)
	// RevokeGrant deletes the grant with its codes and refresh tokens, and records
	// Revocation{GrantID: id, Before: at, At: at}. An unknown grant is ErrNotFound and records
	// nothing.
	RevokeGrant(ctx context.Context, id string, at time.Time) error
	// RevokeSubject is revoke-user (ADR-0006 §9): it records Revocation{Subject: subject, Before:
	// before, At: at} and deletes the subject's grants created before `before`, with their codes,
	// refresh tokens and IdP tokens. It records the cut-off even when the subject has no grants. An
	// empty subject is ErrInvalid.
	RevokeSubject(ctx context.Context, subject string, before, at time.Time) error
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
	// PutCode stores the grant's code. A grant has at most one code, pending or consumed:
	// another is ErrExists. An unknown grant is ErrNotFound.
	PutCode(ctx context.Context, c PendingCode) error
	// ConsumeCode returns the code exactly once (an atomic conditional update). A consumed code is
	// kept until it expires, so a second call returns ErrConsumed; an unknown code, or one with
	// ExpiresAt <= now, is ErrNotFound.
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
	// PutRefreshToken stores t. An existing hash is ErrExists; an unknown grant ErrNotFound.
	PutRefreshToken(ctx context.Context, t RefreshToken) error
	// RefreshToken returns the token with this hash; an unknown one, one with
	// IdleExpiresAt <= now, or one whose grant's Epoch is older than the store's current epoch
	// (the store was restored since, ADR-0007 §9) is ErrNotFound.
	RefreshToken(ctx context.Context, hash [sha256.Size]byte, now time.Time) (RefreshToken, error)
}

// Revocation is one entry of the deny list (ADR-0006 §3): a revoked grant, or every grant of a
// subject issued before a time.
type Revocation struct {
	GrantID string // empty for a subject cut-off
	Subject string // empty for a single grant
	Before  time.Time
	At      time.Time
}

// Revocations feeds the in-memory deny list. Revocations are written by Grants.RevokeGrant and
// Grants.RevokeSubject, in the same transaction that deletes the grants they cover.
type Revocations interface {
	// Revocations returns every retained revocation, oldest At first (ties in any order). The deny
	// list is rebuilt from it on each sync: a cursor would miss rows that commit out of At order
	// on another replica. Retention keeps the set small.
	Revocations(ctx context.Context) ([]Revocation, error)
}
