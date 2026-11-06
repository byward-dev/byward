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

	"github.com/corker/mcp-authproxy/internal/store"
)

// epoch is constant: an in-memory store is never restored from a backup (ADR-0007 §9).
const epoch = 1

// Store implements store.Store with one mutex; every method is one critical section, which makes
// ConsumeCode's conditional update atomic.
type Store struct {
	mu     sync.Mutex
	grants map[string]store.Grant
	codes  map[string]*code // by grant ID: a grant has at most one code
	tokens map[[sha256.Size]byte]store.RefreshToken
	revs   []store.Revocation
}

type code struct {
	c        store.PendingCode
	consumed bool
}

var _ store.Store = (*Store)(nil)

// New returns an empty store.
func New() *Store {
	return &Store{
		grants: map[string]store.Grant{},
		codes:  map[string]*code{},
		tokens: map[[sha256.Size]byte]store.RefreshToken{},
	}
}

// CreateGrant implements store.Grants.
func (s *Store) CreateGrant(_ context.Context, g store.Grant) (store.Grant, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.grants[g.ID]; ok {
		return store.Grant{}, store.ErrExists
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
	if _, ok := s.grants[id]; !ok {
		return store.ErrNotFound
	}
	s.deleteGrantLocked(id)
	s.revs = append(s.revs, store.Revocation{GrantID: id, Before: at, At: at})
	return nil
}

// RevokeSubject implements store.Grants.
func (s *Store) RevokeSubject(_ context.Context, subject string, before, at time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, g := range s.grants {
		if g.Subject == subject && g.CreatedAt.Before(before) {
			s.deleteGrantLocked(id)
		}
	}
	s.revs = append(s.revs, store.Revocation{Subject: subject, Before: before, At: at})
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
	s.tokens[t.Hash] = t
	return nil
}

// RefreshToken implements store.RefreshTokens.
func (s *Store) RefreshToken(_ context.Context, hash [sha256.Size]byte, now time.Time) (store.RefreshToken, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, ok := s.tokens[hash]
	if !ok || !now.Before(t.IdleExpiresAt) {
		return store.RefreshToken{}, store.ErrNotFound
	}
	return t, nil
}

// RevocationsSince implements store.Revocations.
func (s *Store) RevocationsSince(_ context.Context, since time.Time) ([]store.Revocation, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []store.Revocation
	for _, r := range s.revs {
		if !r.At.Before(since) {
			out = append(out, r)
		}
	}
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
		if !now.Before(t.IdleExpiresAt) {
			delete(s.tokens, h)
		}
	}
	cutoff := now.Add(-store.RevocationRetention)
	s.revs = slices.DeleteFunc(s.revs, func(r store.Revocation) bool { return !r.At.After(cutoff) })
	return nil
}

// deleteGrantLocked removes a grant with its code and refresh tokens. Callers hold s.mu.
func (s *Store) deleteGrantLocked(id string) {
	delete(s.grants, id)
	delete(s.codes, id)
	for h, t := range s.tokens {
		if t.GrantID == id {
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
