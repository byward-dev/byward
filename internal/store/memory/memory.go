// Package memory is an in-memory store adapter: for tests and single-node development. State is
// lost on restart, so it has no restore detection and a constant epoch.
package memory

import (
	"context"
	"crypto/sha256"
	"slices"
	"sort"
	"sync"
	"time"

	"github.com/byward-dev/byward/internal/store"
)

// epoch is constant: an in-memory store is never restored from a backup (ADR-0007 §9).
const epoch = 1

// Store implements store.Store with one mutex; every method is one critical section, which makes
// ConsumeCode's conditional update atomic.
type Store struct {
	mu       sync.Mutex
	grants   map[string]store.Grant
	codes    map[string]*code // by grant ID: a grant has at most one code
	tokens   map[[sha256.Size]byte]*token
	revs     []store.Revocation
	clients  map[string]store.Client
	consents map[store.ConsentKey]store.Consent
	logins   map[[sha256.Size]byte]time.Time // spent logins, by hash, until their expiry
	asserts  map[[sha256.Size]byte]time.Time // spent client assertions, by hash, until their expiry
}

// token is a stored refresh token with its successor, set when it is rotated.
type token struct {
	t         store.RefreshToken
	successor [sha256.Size]byte
}

type code struct {
	c        store.PendingCode
	consumed bool
}

var _ store.Store = (*Store)(nil)

// New returns an empty store.
func New() *Store {
	return &Store{
		grants:   map[string]store.Grant{},
		codes:    map[string]*code{},
		tokens:   map[[sha256.Size]byte]*token{},
		clients:  map[string]store.Client{},
		consents: map[store.ConsentKey]store.Consent{},
		logins:   map[[sha256.Size]byte]time.Time{},
		asserts:  map[[sha256.Size]byte]time.Time{},
	}
}

// SpendLogin implements store.Logins.
func (s *Store) SpendLogin(_ context.Context, hash [sha256.Size]byte, now, expiresAt time.Time) error {
	if !expiresAt.After(now) {
		return store.ErrInvalid
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if until, ok := s.logins[hash]; ok && now.Before(until) {
		return store.ErrConsumed
	}
	s.logins[hash] = expiresAt
	return nil
}

// SpendAssertion implements store.ClientAssertions.
func (s *Store) SpendAssertion(_ context.Context, hash [sha256.Size]byte, now, expiresAt time.Time) error {
	if !expiresAt.After(now) {
		return store.ErrInvalid
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if until, ok := s.asserts[hash]; ok && now.Before(until) {
		return store.ErrConsumed
	}
	s.asserts[hash] = expiresAt
	return nil
}

// CreateGrant implements store.Grants.
func (s *Store) CreateGrant(_ context.Context, g store.Grant) (store.Grant, error) {
	if g.ID == "" || g.ClientID == "" || g.Subject == "" || !g.ExpiresAt.After(g.CreatedAt) {
		return store.Grant{}, store.ErrInvalid
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.grants[g.ID]; ok {
		return store.Grant{}, store.ErrExists
	}
	for _, r := range s.revs {
		if (r.All || r.Subject == g.Subject) && r.Before.After(g.CreatedAt) {
			return store.Grant{}, store.ErrRevoked
		}
	}
	g = cloneGrant(g)
	g.Epoch = epoch
	s.grants[g.ID] = g
	return cloneGrant(g), nil
}

// Grant implements store.Grants.
func (s *Store) Grant(_ context.Context, id string) (store.Grant, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	g, ok := s.grants[id]
	if !ok {
		return store.Grant{}, store.ErrNotFound
	}
	return cloneGrant(g), nil
}

// RevokeGrant implements store.Grants.
func (s *Store) RevokeGrant(_ context.Context, id string, at time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	g, ok := s.grants[id]
	if !ok {
		return store.ErrNotFound
	}
	s.deleteGrantLocked(id)
	s.forgetGrantLocked(g)
	s.revs = append(s.revs, store.Revocation{GrantID: id, Before: at, At: at})
	return nil
}

// UpdateGrant implements store.Grants.
func (s *Store) UpdateGrant(_ context.Context, id string, expiresAt time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	g, ok := s.grants[id]
	if !ok {
		return store.ErrNotFound
	}
	if !expiresAt.After(g.CreatedAt) {
		return store.ErrInvalid
	}
	g.ExpiresAt = expiresAt
	s.grants[id] = g
	return nil
}

// SetIdPTokens implements store.Grants.
func (s *Store) SetIdPTokens(_ context.Context, id string, sealed []byte) error {
	if len(sealed) == 0 {
		return store.ErrInvalid
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	g, ok := s.grants[id]
	if !ok {
		return store.ErrNotFound
	}
	g.IdPTokens = slices.Clone(sealed)
	s.grants[id] = g
	return nil
}

// RevokeSubject implements store.Grants.
func (s *Store) RevokeSubject(_ context.Context, subject string, before, at time.Time) error {
	if subject == "" {
		return store.ErrInvalid
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, g := range s.grants {
		if g.Subject == subject && g.CreatedAt.Before(before) {
			s.deleteGrantLocked(id)
		}
	}
	for k, c := range s.consents {
		if k.Subject == subject && c.ApprovedAt.Before(before) {
			delete(s.consents, k)
		}
	}
	s.revs = append(s.revs, store.Revocation{Subject: subject, Before: before, At: at})
	return nil
}

// RevokeAll implements store.Grants.
func (s *Store) RevokeAll(_ context.Context, before, at time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, g := range s.grants {
		if g.CreatedAt.Before(before) {
			s.deleteGrantLocked(id)
		}
	}
	for k, c := range s.consents {
		if c.ApprovedAt.Before(before) {
			delete(s.consents, k)
		}
	}
	s.revs = append(s.revs, store.Revocation{All: true, Before: before, At: at})
	return nil
}

// PutCode implements store.Codes.
func (s *Store) PutCode(_ context.Context, c store.PendingCode) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.grants[c.GrantID]; !ok {
		return store.ErrNotFound
	}
	if _, ok := s.codes[c.GrantID]; ok {
		return store.ErrExists
	}
	s.codes[c.GrantID] = &code{c: cloneCode(c)}
	return nil
}

// ConsumeCode implements store.Codes.
func (s *Store) ConsumeCode(_ context.Context, grantID string, now time.Time) (store.PendingCode, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.codes[grantID]
	if !ok || !now.Before(c.c.ExpiresAt) {
		return store.PendingCode{}, store.ErrNotFound
	}
	if c.consumed {
		return store.PendingCode{}, store.ErrConsumed
	}
	c.consumed = true
	return cloneCode(c.c), nil
}

// PutRefreshToken implements store.RefreshTokens.
func (s *Store) PutRefreshToken(_ context.Context, t store.RefreshToken) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.grants[t.GrantID]; !ok {
		return store.ErrNotFound
	}
	if _, ok := s.tokens[t.Hash]; ok {
		return store.ErrExists
	}
	t.RotatedAt = time.Time{}
	s.tokens[t.Hash] = &token{t: t}
	return nil
}

// RefreshToken implements store.RefreshTokens.
func (s *Store) RefreshToken(_ context.Context, hash [sha256.Size]byte, now time.Time) (store.RefreshToken, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, ok := s.tokens[hash]
	if !ok || !now.Before(t.t.IdleExpiresAt) {
		return store.RefreshToken{}, store.ErrNotFound
	}
	return t.t, nil
}

// RotateRefreshToken implements store.RefreshTokens.
func (s *Store) RotateRefreshToken(_ context.Context, r store.RotateRequest) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	old, ok := s.tokens[r.Old]
	if !ok || !r.Now.Before(old.t.IdleExpiresAt) {
		return store.ErrNotFound
	}
	g, ok := s.grants[old.t.GrantID]
	if !ok {
		return store.ErrNotFound
	}
	if r.Next.GrantID != old.t.GrantID {
		return store.ErrInvalid
	}
	if _, ok := s.tokens[r.Next.Hash]; ok {
		return store.ErrExists
	}
	rotating := old
	if !old.t.RotatedAt.IsZero() {
		cur, ok := s.tokens[old.successor]
		if !ok || !cur.t.RotatedAt.IsZero() || r.Now.Sub(old.t.RotatedAt) >= r.Grace {
			s.deleteGrantLocked(g.ID)
			s.forgetGrantLocked(g)
			s.revs = append(s.revs, store.Revocation{GrantID: g.ID, Before: r.Now, At: r.Now})
			return store.ErrReused
		}
		rotating = cur
		old.successor = r.Next.Hash // a further retry within the same window still works
	}
	rotating.t.RotatedAt, rotating.successor = r.Now, r.Next.Hash
	next := r.Next
	next.RotatedAt = time.Time{}
	s.tokens[next.Hash] = &token{t: next}
	if r.IdPTokens != nil {
		g.IdPTokens = slices.Clone(r.IdPTokens)
		s.grants[g.ID] = g
	}
	return nil
}

// Revocations implements store.Revocations.
func (s *Store) Revocations(context.Context) ([]store.Revocation, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := slices.Clone(s.revs)
	sort.SliceStable(out, func(i, j int) bool { return out[i].At.Before(out[j].At) })
	return out, nil
}

// Collect implements store.Collector.
func (s *Store) Collect(_ context.Context, now time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, g := range s.grants {
		if !now.Before(g.ExpiresAt) {
			s.deleteGrantLocked(id)
		}
	}
	for id, c := range s.codes {
		if !now.Before(c.c.ExpiresAt) {
			delete(s.codes, id)
		}
	}
	for h, t := range s.tokens {
		if !now.Before(t.t.IdleExpiresAt) {
			delete(s.tokens, h)
		}
	}
	cutoff := now.Add(-store.RevocationRetention)
	s.revs = slices.DeleteFunc(s.revs, func(r store.Revocation) bool { return !r.At.After(cutoff) })
	for k, c := range s.consents {
		if !now.Before(c.ExpiresAt) {
			delete(s.consents, k)
		}
	}
	for _, spent := range []map[[sha256.Size]byte]time.Time{s.logins, s.asserts} {
		for h, until := range spent {
			if !now.Before(until) {
				delete(spent, h)
			}
		}
	}
	unused := now.Add(-store.UnusedClientLifetime)
	for id, c := range s.clients {
		if !now.Before(c.ExpiresAt) || (c.UsedAt.IsZero() && !c.CreatedAt.After(unused)) {
			delete(s.clients, id)
		}
	}
	return nil
}

// CreateClient implements store.Clients.
func (s *Store) CreateClient(_ context.Context, c store.Client, max int) error {
	if c.ID == "" || len(c.Metadata) == 0 || !c.UsedAt.IsZero() || !c.ExpiresAt.After(c.CreatedAt) {
		return store.ErrInvalid
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.clients[c.ID]; ok {
		return store.ErrExists
	}
	if max > 0 {
		live := 0
		for _, o := range s.clients {
			if o.ExpiresAt.After(c.CreatedAt) {
				live++
			}
		}
		if live >= max {
			return store.ErrFull
		}
	}
	c.Metadata = slices.Clone(c.Metadata)
	s.clients[c.ID] = c
	return nil
}

// Client implements store.Clients.
func (s *Store) Client(_ context.Context, id string) (store.Client, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.clients[id]
	if !ok {
		return store.Client{}, store.ErrNotFound
	}
	c.Metadata = slices.Clone(c.Metadata)
	return c, nil
}

// UseClient implements store.Clients.
func (s *Store) UseClient(_ context.Context, id string, now, expires time.Time, minExtension time.Duration) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.clients[id]
	if !ok {
		return store.ErrNotFound
	}
	if c.UsedAt.IsZero() {
		c.UsedAt = now
	}
	if !expires.Before(c.ExpiresAt.Add(minExtension)) {
		c.ExpiresAt = expires
	}
	s.clients[id] = c
	return nil
}

// RememberConsent implements store.Consents.
func (s *Store) RememberConsent(_ context.Context, c store.Consent) error {
	k := c.Key
	if k.Issuer == "" || k.Subject == "" || k.ClientID == "" || k.Redirect == "" || k.Resource == "" || len(c.Scopes) == 0 || !c.ExpiresAt.After(c.ApprovedAt) {
		return store.ErrInvalid
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	c.Scopes = slices.Clone(c.Scopes)
	s.consents[k] = c
	return nil
}

// Consent implements store.Consents.
func (s *Store) Consent(_ context.Context, k store.ConsentKey) (store.Consent, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.consents[k]
	if !ok {
		return store.Consent{}, store.ErrNotFound
	}
	c.Scopes = slices.Clone(c.Scopes)
	return c, nil
}

// forgetGrantLocked forgets the consents of a revoked grant's user and client. Callers hold s.mu.
func (s *Store) forgetGrantLocked(g store.Grant) {
	for k := range s.consents {
		if k.Issuer == g.Issuer && k.Subject == g.Subject && k.ClientID == g.ClientID {
			delete(s.consents, k)
		}
	}
}

// deleteGrantLocked removes a grant with its code and refresh tokens. Callers hold s.mu.
func (s *Store) deleteGrantLocked(id string) {
	delete(s.grants, id)
	delete(s.codes, id)
	for h, t := range s.tokens {
		if t.t.GrantID == id {
			delete(s.tokens, h)
		}
	}
}

func cloneGrant(g store.Grant) store.Grant {
	g.Scopes = slices.Clone(g.Scopes)
	g.IdPTokens = slices.Clone(g.IdPTokens)
	return g
}

func cloneCode(c store.PendingCode) store.PendingCode {
	c.Scopes = slices.Clone(c.Scopes)
	return c
}
