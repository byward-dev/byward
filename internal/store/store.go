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
	// ErrFull: CreateClient found the cap of live client registrations reached (ADR-0008 §3).
	ErrFull = errors.New("store: client registrations full")
)

// UnusedClientLifetime is how long a dynamically registered client that never redeemed a code is
// kept (ADR-0008 §3): Collect deletes it after this, whatever its ExpiresAt.
const UnusedClientLifetime = 24 * time.Hour

// RevocationRetention is how long revocations are kept (ADR-0006 §3, §5). After it, every token a
// revocation covers has expired anyway. It must exceed the longest access-token lifetime plus the
// clock leeway the validator allows on `exp` (30 s): an hour and a minute leaves 30 s of margin
// for clock skew between replicas.
//
// Adapters may keep times at microsecond precision (PostgreSQL timestamptz); callers must not
// rely on finer differences.
const RevocationRetention = time.Hour + time.Minute

// Store is everything the broker keeps.
//
// Values passed in and returned are copies: changing a slice after a call never changes what is
// stored. Codes and refresh tokens belong to a grant that must exist (ErrNotFound otherwise) and go
// when it goes.
type Store interface {
	Grants
	Codes
	Logins
	ClientAssertions
	RefreshTokens
	Revocations
	Clients
	Consents
	Collector
}

// Collector removes expired rows (ADR-0007 §1).
type Collector interface {
	// Collect deletes codes (pending or consumed) with ExpiresAt <= now, refresh tokens with
	// IdleExpiresAt <= now, grants with ExpiresAt <= now together with their codes and refresh
	// tokens, revocations with At <= now - RevocationRetention, clients with ExpiresAt <= now or
	// never used and CreatedAt <= now - UnusedClientLifetime, consents with ExpiresAt <= now, and
	// spent logins and spent client assertions with expiresAt <= now. An expired spent login or
	// assertion already counts as absent, so the shared suite cannot see it collected: each adapter
	// tests that with its own row count. A store
	// shared by several replicas may return nil having deleted nothing while another replica
	// collects; the rows go at a later call.
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
	// SQL adapters must serialize CreateGrant with RevokeSubject per subject, and with RevokeAll for
	// every subject: under READ COMMITTED each can miss the other's uncommitted row and both commit
	// (write skew). PostgreSQL: CreateGrant and RevokeSubject take pg_advisory_xact_lock(
	// hashtext(subject)) and pg_advisory_xact_lock_shared(<revoke-all key>), RevokeAll takes
	// pg_advisory_xact_lock(<revoke-all key>); or run all three SERIALIZABLE and retry on 40001.
	// SQLite: one writer, and all three start with BEGIN IMMEDIATE.
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
	// SetIdPTokens replaces a grant's sealed IdP tokens, for a refresh that renewed them at the IdP
	// but failed afterwards (the IdP may have revoked the old refresh token). An unknown or revoked
	// grant is ErrNotFound and nothing is written, so it never restores a deleted grant; empty
	// tokens are ErrInvalid.
	SetIdPTokens(ctx context.Context, id string, sealed []byte) error
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

// Logins records the logins in progress a callback has used (#150). The login itself lives only in
// a sealed cookie (ADR-0007 §3); this makes it single use on the server too, whatever the browser
// keeps. Only a hash of the login's IdP state is stored.
type Logins interface {
	// SpendLogin records the login with this hash as spent until expiresAt, in one atomic step: the
	// first call is nil, a later one before expiresAt ErrConsumed. A record past its expiry counts
	// as absent. An expiresAt not after now is ErrInvalid.
	SpendLogin(ctx context.Context, hash [sha256.Size]byte, now, expiresAt time.Time) error
}

// ClientAssertions records the private_key_jwt client assertions /token has accepted (ADR-0008 §6,
// #227), so an assertion is single use across every replica. Only a hash of its replay key is
// stored, never the jti itself.
type ClientAssertions interface {
	// SpendAssertion records the assertion with this hash as spent until expiresAt, in one atomic
	// step: the first call is nil, a later one before expiresAt ErrConsumed. A record past its expiry
	// counts as absent. An expiresAt not after now is ErrInvalid.
	SpendAssertion(ctx context.Context, hash [sha256.Size]byte, now, expiresAt time.Time) error
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

// Client is a dynamically registered MCP client (ADR-0008 §2-3). Metadata is the registered client
// metadata as the registration package encodes it; the store does not interpret it.
type Client struct {
	ID        string
	Metadata  []byte
	CreatedAt time.Time
	UsedAt    time.Time // zero until the client first redeems a code
	ExpiresAt time.Time
}

// Clients are dynamic client registrations, with a sliding expiry (ADR-0008 §3).
type Clients interface {
	// CreateClient stores c. An existing ID is ErrExists; an empty ID or Metadata, a non-zero
	// UsedAt, or an ExpiresAt not after CreatedAt is ErrInvalid. When max > 0 and max clients with
	// ExpiresAt after c.CreatedAt are already stored, it is ErrFull; the count and the insert are one
	// atomic step, so concurrent registrations never exceed max.
	CreateClient(ctx context.Context, c Client, max int) error
	// Client returns the client, or ErrNotFound. It does not check ExpiresAt.
	Client(ctx context.Context, id string) (Client, error)
	// UseClient records a use at now: it sets UsedAt to now if it is zero, and extends ExpiresAt to
	// expires if that is at least minExtension later than the stored one, so a busy client does not
	// write on every use. An unknown client is ErrNotFound. It never shortens ExpiresAt.
	UseClient(ctx context.Context, id string, now, expires time.Time, minExtension time.Duration) error
}

// ConsentKey says what a remembered consent covers (ADR-0010 §3): one user of one IdP, one client,
// one redirect key and one resource. The redirect key is the redirect URI as the caller compares
// it; for loopback the caller drops the port (ADR-0009 §2).
type ConsentKey struct {
	Issuer   string
	Subject  string
	ClientID string
	Redirect string
	Resource string
}

// Consent is a user's remembered Allow: the scopes approved, and until when it counts.
type Consent struct {
	Key        ConsentKey
	Scopes     []string
	ApprovedAt time.Time
	ExpiresAt  time.Time
}

// Consents is the remembered-consent registry (ADR-0010 §2-3). Revoking forgets, in the same
// transaction that deletes the grants: RevokeGrant and a refresh-token reuse forget the consents of
// the grant's user and client, RevokeSubject the subject's consents approved before its cut-off,
// RevokeAll every consent approved before its cut-off. A grant that merely expires forgets nothing.
// A store restored from an older copy forgets every consent: revocations made after the copy are
// lost with it (ADR-0007 §9).
type Consents interface {
	// RememberConsent stores c, replacing a consent with the same key (scopes and lifetime too).
	// An empty key field, no scopes, or ExpiresAt not after ApprovedAt is ErrInvalid.
	RememberConsent(ctx context.Context, c Consent) error
	// Consent returns the consent for k, or ErrNotFound. It does not check ExpiresAt.
	Consent(ctx context.Context, k ConsentKey) (Consent, error)
}
