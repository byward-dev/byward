package storetest

import (
	"context"
	"crypto/sha256"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/byward-dev/byward/internal/store"
)

// callsUnderAnEndedContextFailAndChangeNothing: every method called under a context that has ended
// (a request whose client went away, or the proxy's shutdown) returns the context's error and
// changes nothing, as database/sql and pgxpool take no connection for it (#693). So a write that
// must happen whatever its request's end, a grant's revocation, cannot run on the request's
// context: the broker detaches it. A store.Store method with no call here fails the test, so a new
// method is held to the same contract.
func callsUnderAnEndedContextFailAndChangeNothing(t *testing.T, s store.Store) {
	g, other := mustCreate(t, s, grant("g1", "tid:alice")), mustCreate(t, s, grant("g2", "tid:bob"))
	must(t, s.PutCode(ctx, pendingCode(g.ID)))
	rt := refresh(g.ID, 1)
	must(t, s.PutRefreshToken(ctx, rt))
	c := client("dcr-1")
	must(t, s.CreateClient(ctx, c, 10))
	k := consent(g.ID, g.Subject, "http://127.0.0.1/cb")
	must(t, s.RememberConsent(ctx, k))
	login, assertion := sha256.Sum256([]byte("login")), sha256.Sum256([]byte("assertion"))
	at, later := t0.Add(30*time.Second), t0.Add(48*time.Hour) // at is inside the code's minute

	ended, cancel := context.WithCancel(ctx)
	cancel()
	calls := map[string]func() error{
		"CreateGrant":    func() error { _, err := s.CreateGrant(ended, grant("g3", "tid:carol")); return err },
		"Grant":          func() error { _, err := s.Grant(ended, g.ID); return err },
		"RevokeGrant":    func() error { return s.RevokeGrant(ended, g.ID, at) },
		"UpdateGrant":    func() error { return s.UpdateGrant(ended, g.ID, later) },
		"SetIdPTokens":   func() error { return s.SetIdPTokens(ended, g.ID, []byte("replaced")) },
		"RevokeSubject":  func() error { return s.RevokeSubject(ended, g.Subject, later, at) },
		"RevokeAll":      func() error { return s.RevokeAll(ended, later, at) },
		"PutCode":        func() error { return s.PutCode(ended, pendingCode(other.ID)) },
		"ConsumeCode":    func() error { _, err := s.ConsumeCode(ended, g.ID, at); return err },
		"SpendLogin":     func() error { return s.SpendLogin(ended, login, at, later) },
		"SpendAssertion": func() error { return s.SpendAssertion(ended, assertion, at, later) },
		"PutRefreshToken": func() error {
			return s.PutRefreshToken(ended, refresh(other.ID, 1))
		},
		"RefreshToken":       func() error { _, err := s.RefreshToken(ended, rt.Hash, at); return err },
		"RotateRefreshToken": func() error { return s.RotateRefreshToken(ended, rotation(rt, refresh(g.ID, 2), at)) },
		"Revocations":        func() error { _, err := s.Revocations(ended); return err },
		"Collect":            func() error { return s.Collect(ended, t0.Add(365*24*time.Hour)) },
		"CreateClient":       func() error { return s.CreateClient(ended, client("dcr-2"), 10) },
		"Client":             func() error { _, err := s.Client(ended, c.ID); return err },
		"UseClient":          func() error { return s.UseClient(ended, c.ID, at, later.Add(90*24*time.Hour), time.Hour) },
		"RememberConsent":    func() error { return s.RememberConsent(ended, consent(other.ID, other.Subject, "http://127.0.0.1/cb")) },
		"Consent":            func() error { _, err := s.Consent(ended, k.Key); return err },
	}
	var methods []string
	typ := reflect.TypeFor[store.Store]()
	for i := range typ.NumMethod() {
		methods = append(methods, typ.Method(i).Name)
	}
	for _, m := range methods {
		call, ok := calls[m]
		if !ok {
			t.Errorf("store.Store.%s has no call under an ended context here: add one", m)
			continue
		}
		if err := call(); !errors.Is(err, context.Canceled) {
			t.Errorf("%s under an ended context: err = %v, want context.Canceled", m, err)
		}
	}
	if len(calls) != len(methods) {
		t.Errorf("%d calls for %d store.Store methods", len(calls), len(methods))
	}

	// Nothing changed: every row is as it was, and nothing new was written or spent.
	if got, err := s.Grant(ctx, g.ID); err != nil || !grantsEqual(got, g) {
		t.Errorf("grant %s after the calls: %+v, %v; want it unchanged", g.ID, got, err)
	}
	if _, err := s.Grant(ctx, "g3"); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("a grant created under an ended context: err = %v, want ErrNotFound", err)
	}
	if revs, err := s.Revocations(ctx); err != nil || len(revs) != 0 {
		t.Errorf("revocations after the calls: %v, %v; want none", revs, err)
	}
	if got, err := s.RefreshToken(ctx, rt.Hash, at); err != nil || !got.RotatedAt.IsZero() {
		t.Errorf("refresh token after the calls: %+v, %v; want it current, not rotated", got, err)
	}
	if _, err := s.RefreshToken(ctx, refresh(other.ID, 1).Hash, at); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("a refresh token put under an ended context: err = %v, want ErrNotFound", err)
	}
	if got, err := s.ConsumeCode(ctx, g.ID, at); err != nil || !codesEqual(got, pendingCode(g.ID)) {
		t.Errorf("the code after the calls: %+v, %v; want it unspent", got, err)
	}
	if _, err := s.ConsumeCode(ctx, other.ID, at); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("a code put under an ended context: err = %v, want ErrNotFound", err)
	}
	must(t, s.SpendLogin(ctx, login, at, later))         // not spent under the ended context
	must(t, s.SpendAssertion(ctx, assertion, at, later)) // nor this
	if got, err := s.Client(ctx, c.ID); err != nil || !clientsEqual(got, c) {
		t.Errorf("client after the calls: %+v, %v; want it unchanged (not used)", got, err)
	}
	if _, err := s.Client(ctx, "dcr-2"); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("a client created under an ended context: err = %v, want ErrNotFound", err)
	}
	if _, err := s.Consent(ctx, k.Key); err != nil {
		t.Errorf("the consent after the calls: %v; want it kept", err)
	}
	if _, err := s.Consent(ctx, consent(other.ID, other.Subject, "http://127.0.0.1/cb").Key); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("a consent remembered under an ended context: err = %v, want ErrNotFound", err)
	}
}
