// Package memstore is the in-memory store with failures a test switches on per method, so a test
// that needs a new failure calls Fail instead of adding a field to a shared fake. Calling the
// embedded Store directly bypasses every failure.
package memstore

import (
	"context"
	"crypto/sha256"
	"reflect"
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
	fail          map[string]error  // by method name
	after         map[string]func() // by method name, run once the call returns
	down          error             // every method
	sqlContext    bool              // a call under an ended context fails, as on a SQL store
	onCreateGrant func(*store.Grant)
	grantIDs      []string
}

// New returns an empty store with no failures.
func New() *Store {
	return &Store{Store: memory.New(), fail: map[string]error{}, after: map[string]func(){}}
}

// methods are store.Store's method names; Fail refuses any other, so a typo cannot silently
// inject nothing.
var methods = func() map[string]bool {
	t := reflect.TypeFor[store.Store]()
	m := make(map[string]bool, t.NumMethod())
	for i := range t.NumMethod() {
		m[t.Method(i).Name] = true
	}
	return m
}()

// Fail makes the named methods return err (store.ErrReused for RotateRefreshToken reports reuse
// without recording it, as when another replica won the race); a nil err clears them. A name that
// is not a store.Store method panics.
func (s *Store) Fail(err error, names ...string) {
	for _, m := range names {
		if !methods[m] {
			panic("memstore: Fail: " + m + " is not a store.Store method")
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, m := range names {
		if err == nil {
			delete(s.fail, m)
		} else {
			s.fail[m] = err
		}
	}
}

// SQLContext makes a call under an ended context fail with the context's error and change nothing,
// as on the SQL stores (and memory.Store). Until then the store ignores a request's end, as the
// broker tests written before #693 assume.
func (s *Store) SQLContext() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sqlContext = true
}

// AfterCall runs f each time the named method returns, before its caller sees the result: a test
// ends a request there, between the call that detects a misuse and the revocation that follows.
// A name that is not a store.Store method panics.
func (s *Store) AfterCall(name string, f func()) {
	if !methods[name] {
		panic("memstore: AfterCall: " + name + " is not a store.Store method")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.after[name] = f
}

// inner is the context a call passes to memory.Store: ctx under SQLContext, else ctx with its
// ending removed.
func (s *Store) inner(ctx context.Context) context.Context {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.sqlContext {
		return ctx
	}
	return context.WithoutCancel(ctx)
}

// ran runs the AfterCall hook of method, if any.
func (s *Store) ran(method string) {
	s.mu.Lock()
	f := s.after[method]
	s.mu.Unlock()
	if f != nil {
		f()
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
	defer s.ran("Collect")
	return s.Store.Collect(s.inner(ctx), now)
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
	defer s.ran("CreateGrant")
	got, err := s.Store.CreateGrant(s.inner(ctx), g)
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
	defer s.ran("Grant")
	return s.Store.Grant(s.inner(ctx), id)
}

func (s *Store) RevokeGrant(ctx context.Context, id string, at time.Time) error {
	if err := s.err("RevokeGrant"); err != nil {
		return err
	}
	defer s.ran("RevokeGrant")
	return s.Store.RevokeGrant(s.inner(ctx), id, at)
}

func (s *Store) UpdateGrant(ctx context.Context, id string, expiresAt time.Time) error {
	if err := s.err("UpdateGrant"); err != nil {
		return err
	}
	defer s.ran("UpdateGrant")
	return s.Store.UpdateGrant(s.inner(ctx), id, expiresAt)
}

// SetIdPTokens also fails on a cancelled context, as the SQL store does.
func (s *Store) SetIdPTokens(ctx context.Context, id string, sealed []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := s.err("SetIdPTokens"); err != nil {
		return err
	}
	defer s.ran("SetIdPTokens")
	return s.Store.SetIdPTokens(s.inner(ctx), id, sealed)
}

func (s *Store) RevokeSubject(ctx context.Context, subject string, before, at time.Time) error {
	if err := s.err("RevokeSubject"); err != nil {
		return err
	}
	defer s.ran("RevokeSubject")
	return s.Store.RevokeSubject(s.inner(ctx), subject, before, at)
}

func (s *Store) RevokeAll(ctx context.Context, before, at time.Time) error {
	if err := s.err("RevokeAll"); err != nil {
		return err
	}
	defer s.ran("RevokeAll")
	return s.Store.RevokeAll(s.inner(ctx), before, at)
}

func (s *Store) PutCode(ctx context.Context, c store.PendingCode) error {
	if err := s.err("PutCode"); err != nil {
		return err
	}
	defer s.ran("PutCode")
	return s.Store.PutCode(s.inner(ctx), c)
}

func (s *Store) ConsumeCode(ctx context.Context, grantID string, now time.Time) (store.PendingCode, error) {
	if err := s.err("ConsumeCode"); err != nil {
		return store.PendingCode{}, err
	}
	defer s.ran("ConsumeCode")
	return s.Store.ConsumeCode(s.inner(ctx), grantID, now)
}

func (s *Store) SpendLogin(ctx context.Context, hash [sha256.Size]byte, now, expiresAt time.Time) error {
	if err := s.err("SpendLogin"); err != nil {
		return err
	}
	defer s.ran("SpendLogin")
	return s.Store.SpendLogin(s.inner(ctx), hash, now, expiresAt)
}

func (s *Store) SpendAssertion(ctx context.Context, hash [sha256.Size]byte, now, expiresAt time.Time) error {
	if err := s.err("SpendAssertion"); err != nil {
		return err
	}
	defer s.ran("SpendAssertion")
	return s.Store.SpendAssertion(s.inner(ctx), hash, now, expiresAt)
}

func (s *Store) PutRefreshToken(ctx context.Context, t store.RefreshToken) error {
	if err := s.err("PutRefreshToken"); err != nil {
		return err
	}
	defer s.ran("PutRefreshToken")
	return s.Store.PutRefreshToken(s.inner(ctx), t)
}

func (s *Store) RefreshToken(ctx context.Context, hash [sha256.Size]byte, now time.Time) (store.RefreshToken, error) {
	if err := s.err("RefreshToken"); err != nil {
		return store.RefreshToken{}, err
	}
	defer s.ran("RefreshToken")
	return s.Store.RefreshToken(s.inner(ctx), hash, now)
}

func (s *Store) RotateRefreshToken(ctx context.Context, r store.RotateRequest) error {
	if err := s.err("RotateRefreshToken"); err != nil {
		return err
	}
	defer s.ran("RotateRefreshToken")
	return s.Store.RotateRefreshToken(s.inner(ctx), r)
}

func (s *Store) Revocations(ctx context.Context) ([]store.Revocation, error) {
	if err := s.err("Revocations"); err != nil {
		return nil, err
	}
	defer s.ran("Revocations")
	return s.Store.Revocations(s.inner(ctx))
}

func (s *Store) CreateClient(ctx context.Context, c store.Client, maxClients int) error {
	if err := s.err("CreateClient"); err != nil {
		return err
	}
	defer s.ran("CreateClient")
	return s.Store.CreateClient(s.inner(ctx), c, maxClients)
}

func (s *Store) Client(ctx context.Context, id string) (store.Client, error) {
	if err := s.err("Client"); err != nil {
		return store.Client{}, err
	}
	defer s.ran("Client")
	return s.Store.Client(s.inner(ctx), id)
}

func (s *Store) UseClient(ctx context.Context, id string, now, expires time.Time, minExtension time.Duration) error {
	if err := s.err("UseClient"); err != nil {
		return err
	}
	defer s.ran("UseClient")
	return s.Store.UseClient(s.inner(ctx), id, now, expires, minExtension)
}

func (s *Store) RememberConsent(ctx context.Context, c store.Consent) error {
	if err := s.err("RememberConsent"); err != nil {
		return err
	}
	defer s.ran("RememberConsent")
	return s.Store.RememberConsent(s.inner(ctx), c)
}

func (s *Store) Consent(ctx context.Context, k store.ConsentKey) (store.Consent, error) {
	if err := s.err("Consent"); err != nil {
		return store.Consent{}, err
	}
	defer s.ran("Consent")
	return s.Store.Consent(s.inner(ctx), k)
}

var _ store.Store = (*Store)(nil)
