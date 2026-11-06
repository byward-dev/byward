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
	// ErrReused: a rotated refresh token was presented again outside the grace window, or was not
	// the immediate predecessor of the current one. The store has already revoked the grant
	// (ADR-0006 §4).
	ErrReused = errors.New("store: refresh token reused")
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
	// cut-off, for g's subject or for all subjects, with Before after g.CreatedAt is ErrRevoked. The
	// cut-off check and the insert are one atomic step, so a grant never outlives a RevokeSubject or
	// RevokeAll that should have covered it.
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
	// UpdateGrant sets a grant's ExpiresAt, for example when its authorization code is redeemed.
	// An unknown grant is ErrNotFound; an ExpiresAt not after CreatedAt is ErrInvalid.
	UpdateGrant(ctx context.Context, id string, expiresAt time.Time) error
	// RevokeSubject is revoke-user (ADR-0006 §9): it records Revocation{Subject: subject, Before:
	// before, At: at} and deletes the subject's grants created before `before`, with their codes,
	// refresh tokens and IdP tokens. It records the cut-off even when the subject has no grants. An
	// empty subject is ErrInvalid.
	RevokeSubject(ctx context.Context, subject string, before, at time.Time) error
	// RevokeAll is revoke-all (ADR-0006 §9, incident response): it records Revocation{All: true,
	// Before: before, At: at} and deletes every grant created before `before`, with their codes,
	// refresh tokens and IdP tokens, in one atomic step.
	RevokeAll(ctx context.Context, before, at time.Time) error
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
	// RotatedAt is when the token was rotated away; zero while it is the grant's current token.
	// The store sets it; it is ignored on Put.
	RotatedAt time.Time
}

// RotateRequest rotates one refresh token (ADR-0006 §4).
type RotateRequest struct {
	Old  [sha256.Size]byte // the presented token's hash
	Next RefreshToken      // the replacement, for the same grant
	// IdPTokens, when not nil, replace the grant's IdP tokens in the same transaction: the IdP may
	// have rotated its own refresh token during this refresh.
	IdPTokens []byte
	Now       time.Time
	Grace     time.Duration // reuse of the immediate predecessor within Grace is allowed
}

// RefreshTokens stores refresh tokens, rotated on every use.
type RefreshTokens interface {
	// PutRefreshToken stores t. An existing hash is ErrExists; an unknown grant ErrNotFound.
	PutRefreshToken(ctx context.Context, t RefreshToken) error
	// RefreshToken returns the token with this hash; an unknown one, one with
	// IdleExpiresAt <= now, or one whose grant's Epoch is older than the store's current epoch
	// (the store was restored since, ADR-0007 §9) is ErrNotFound.
	RefreshToken(ctx context.Context, hash [sha256.Size]byte, now time.Time) (RefreshToken, error)
	// RotateRefreshToken is one atomic step. If Old is current, it is marked rotated and Next
	// becomes current. If Old was rotated less than Grace ago and its successor is still current
	// (a retried refresh whose response was lost), that successor is rotated to Next instead. Any
	// other reuse revokes the grant and returns ErrReused. Old unknown, idle-expired or from an
	// older epoch is ErrNotFound; Next for another grant is ErrInvalid; an existing Next hash is
	// ErrExists.
	RotateRefreshToken(ctx context.Context, r RotateRequest) error
}

// Revocation is one entry of the deny list (ADR-0006 §3): a revoked grant, every grant of a subject
// issued before a time, or every grant of every subject issued before a time. Exactly one of
// GrantID, Subject and All says which; a revocation naming none of them revokes nothing, so a zero
// value can never revoke everyone by mistake.
type Revocation struct {
	GrantID string // a single grant
	Subject string // a subject cut-off (revoke-user)
	All     bool   // a cut-off for every subject (revoke-all); set only by Grants.RevokeAll
	Before  time.Time
	At      time.Time
}

// Revocations feeds the in-memory deny list. Revocations are written by Grants.RevokeGrant,
// Grants.RevokeSubject and Grants.RevokeAll, in the same transaction that deletes the grants they
// cover.
type Revocations interface {
	// Revocations returns every retained revocation, oldest At first (ties in any order). The deny
	// list is rebuilt from it on each sync: a cursor would miss rows that commit out of At order
	// on another replica. Retention keeps the set small.
	Revocations(ctx context.Context) ([]Revocation, error)
}
