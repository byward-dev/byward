// Package memstore is the in-memory store with failures a test switches on per method, so a test
// that needs a new failure calls Fail instead of adding a field to a shared fake. Calling the
// embedded Store directly bypasses every failure.
package memstore

import (
	"context"
	"crypto/sha256"
	"slices"
	"sync"
	"time"

	"github.com/byward-dev/byward/internal/store"
	"github.com/byward-dev/byward/internal/store/memory"
)

// Store is memory.Store with per-method failures and a record of the grants it created.
type Store struct {
	*memory.Store
	mu            sync.Mutex
	fail          map[string]error // by method name
	down          error            // every method
	onCreateGrant func(*store.Grant)
	grantIDs      []string
}

// New returns an empty store with no failures.
func New() *Store { return &Store{Store: memory.New(), fail: map[string]error{}} }

// Fail makes the named methods return err (store.ErrReused for RotateRefreshToken reports reuse
// without recording it, as when another replica won the race); a nil err clears them.
func (s *Store) Fail(err error, methods ...string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, m := range methods {
		if err == nil {
			delete(s.fail, m)
		} else {
			s.fail[m] = err
		}
	}
}

// Down makes every method return err, as in a store outage; nil ends the outage.
func (s *Store) Down(err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.down = err
}

// OnCreateGrant runs f on every grant before it is stored, e.g. to rewrite its sealed IdP tokens
// as an older proxy wrote them.
func (s *Store) OnCreateGrant(f func(*store.Grant)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.onCreateGrant = f
}

// GrantIDs are the IDs of the grants created so far, oldest first.
func (s *Store) GrantIDs() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.grantIDs)
}

func (s *Store) err(method string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.down != nil {
		return s.down
	}
	return s.fail[method]
}

func (s *Store) Collect(ctx context.Context, now time.Time) error {
	if err := s.err("Collect"); err != nil {
		return err
	}
	return s.Store.Collect(ctx, now)
}

func (s *Store) CreateGrant(ctx context.Context, g store.Grant) (store.Grant, error) {
	if err := s.err("CreateGrant"); err != nil {
		return store.Grant{}, err
	}
	s.mu.Lock()
	hook := s.onCreateGrant
	s.mu.Unlock()
	if hook != nil {
		hook(&g)
	}
	got, err := s.Store.CreateGrant(ctx, g)
	if err == nil {
		s.mu.Lock()
		s.grantIDs = append(s.grantIDs, g.ID)
		s.mu.Unlock()
	}
	return got, err
}

func (s *Store) Grant(ctx context.Context, id string) (store.Grant, error) {
	if err := s.err("Grant"); err != nil {
		return store.Grant{}, err
	}
	return s.Store.Grant(ctx, id)
}

func (s *Store) RevokeGrant(ctx context.Context, id string, at time.Time) error {
	if err := s.err("RevokeGrant"); err != nil {
		return err
	}
	return s.Store.RevokeGrant(ctx, id, at)
}

func (s *Store) UpdateGrant(ctx context.Context, id string, expiresAt time.Time) error {
	if err := s.err("UpdateGrant"); err != nil {
		return err
	}
	return s.Store.UpdateGrant(ctx, id, expiresAt)
}

// SetIdPTokens also fails on a cancelled context, as the SQL store does.
func (s *Store) SetIdPTokens(ctx context.Context, id string, sealed []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := s.err("SetIdPTokens"); err != nil {
		return err
	}
	return s.Store.SetIdPTokens(ctx, id, sealed)
}

func (s *Store) RevokeSubject(ctx context.Context, subject string, before, at time.Time) error {
	if err := s.err("RevokeSubject"); err != nil {
		return err
	}
	return s.Store.RevokeSubject(ctx, subject, before, at)
}

func (s *Store) RevokeAll(ctx context.Context, before, at time.Time) error {
	if err := s.err("RevokeAll"); err != nil {
		return err
	}
	return s.Store.RevokeAll(ctx, before, at)
}

func (s *Store) PutCode(ctx context.Context, c store.PendingCode) error {
	if err := s.err("PutCode"); err != nil {
		return err
	}
	return s.Store.PutCode(ctx, c)
}

func (s *Store) ConsumeCode(ctx context.Context, grantID string, now time.Time) (store.PendingCode, error) {
	if err := s.err("ConsumeCode"); err != nil {
		return store.PendingCode{}, err
	}
	return s.Store.ConsumeCode(ctx, grantID, now)
}

func (s *Store) SpendLogin(ctx context.Context, hash [sha256.Size]byte, now, expiresAt time.Time) error {
	if err := s.err("SpendLogin"); err != nil {
		return err
	}
	return s.Store.SpendLogin(ctx, hash, now, expiresAt)
}

func (s *Store) PutRefreshToken(ctx context.Context, t store.RefreshToken) error {
	if err := s.err("PutRefreshToken"); err != nil {
		return err
	}
	return s.Store.PutRefreshToken(ctx, t)
}

func (s *Store) RefreshToken(ctx context.Context, hash [sha256.Size]byte, now time.Time) (store.RefreshToken, error) {
	if err := s.err("RefreshToken"); err != nil {
		return store.RefreshToken{}, err
	}
	return s.Store.RefreshToken(ctx, hash, now)
}

func (s *Store) RotateRefreshToken(ctx context.Context, r store.RotateRequest) error {
	if err := s.err("RotateRefreshToken"); err != nil {
		return err
	}
	return s.Store.RotateRefreshToken(ctx, r)
}

func (s *Store) Revocations(ctx context.Context) ([]store.Revocation, error) {
	if err := s.err("Revocations"); err != nil {
		return nil, err
	}
	return s.Store.Revocations(ctx)
}

func (s *Store) CreateClient(ctx context.Context, c store.Client, maxClients int) error {
	if err := s.err("CreateClient"); err != nil {
		return err
	}
	return s.Store.CreateClient(ctx, c, maxClients)
}

func (s *Store) Client(ctx context.Context, id string) (store.Client, error) {
	if err := s.err("Client"); err != nil {
		return store.Client{}, err
	}
	return s.Store.Client(ctx, id)
}

func (s *Store) UseClient(ctx context.Context, id string, now, expires time.Time, minExtension time.Duration) error {
	if err := s.err("UseClient"); err != nil {
		return err
	}
	return s.Store.UseClient(ctx, id, now, expires, minExtension)
}

func (s *Store) RememberConsent(ctx context.Context, c store.Consent) error {
	if err := s.err("RememberConsent"); err != nil {
		return err
	}
	return s.Store.RememberConsent(ctx, c)
}

func (s *Store) Consent(ctx context.Context, k store.ConsentKey) (store.Consent, error) {
	if err := s.err("Consent"); err != nil {
		return store.Consent{}, err
	}
	return s.Store.Consent(ctx, k)
}

var _ store.Store = (*Store)(nil)
