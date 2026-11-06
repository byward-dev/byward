// Package storetest is the conformance suite every store adapter must pass (ADR-0007 §1). An
// adapter's test calls Run with a constructor for a fresh, empty store.
package storetest

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/corker/mcp-authproxy/internal/store"
)

// t0 is a fixed instant; every time in the suite is relative to it.
var t0 = time.Date(2026, 11, 6, 12, 0, 0, 0, time.UTC)

// tick is the smallest time difference the suite relies on. Adapters may store microseconds
// (PostgreSQL) or milliseconds; nothing finer is tested.
const tick = time.Millisecond

// otherZone checks that adapters compare instants, not wall-clock text.
var otherZone = time.FixedZone("UTC+2", 2*60*60)

// Run runs every contract of store.Store against stores from newStore, one fresh store per test.
func Run(t *testing.T, newStore func(t *testing.T) store.Store) {
	tests := []struct {
		name string
		fn   func(*testing.T, store.Store)
	}{
		{"CreateGrantSetsEpochAndRoundTrips", createGrantSetsEpochAndRoundTrips},
		{"GrantIgnoresExpiry", grantIgnoresExpiry},
		{"GrantIDsAreUnique", grantIDsAreUnique},
		{"UnknownGrantIsNotFound", unknownGrantIsNotFound},
		{"IncompleteGrantsAndCutOffsAreInvalid", incompleteGrantsAndCutOffsAreInvalid},
		{"StoredValuesAreCopies", storedValuesAreCopies},
		{"CodeIsConsumedOnce", codeIsConsumedOnce},
		{"ConcurrentConsumeHasOneWinner", concurrentConsumeHasOneWinner},
		{"ExpiredCodeIsNotFound", expiredCodeIsNotFound},
		{"CodeNeedsAGrantAndIsUniquePerGrant", codeNeedsAGrantAndIsUniquePerGrant},
		{"RefreshTokenRoundTripsAndIdleExpires", refreshTokenRoundTripsAndIdleExpires},
		{"RefreshTokenNeedsAGrantAndAUniqueHash", refreshTokenNeedsAGrantAndAUniqueHash},
		{"RevokeGrantDeletesItsRowsAndRecordsARevocation", revokeGrantDeletesItsRowsAndRecordsARevocation},
		{"RevokeUnknownGrantRecordsNothing", revokeUnknownGrantRecordsNothing},
		{"RevokeSubjectCutsOffEarlierGrants", revokeSubjectCutsOffEarlierGrants},
		{"RevocationsAreOldestFirst", revocationsAreOldestFirst},
		{"CutOffRefusesLaterCreatedEarlierGrants", cutOffRefusesLaterCreatedEarlierGrants},
		{"RevokeSubjectAndCreateGrantNeverLeaveACoveredGrant", revokeSubjectAndCreateGrantNeverLeaveACoveredGrant},
		{"CollectRemovesExpiredRowsOnly", collectRemovesExpiredRowsOnly},
		{"CollectRemovesOldRevocations", collectRemovesOldRevocations},
		{"ConcurrentUseIsSafe", concurrentUseIsSafe},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) { tc.fn(t, newStore(t)) })
	}
}

var ctx = context.Background()

func grant(id, subject string) store.Grant {
	return store.Grant{
		ID: id, ClientID: "client-" + id, Subject: subject, Issuer: "https://idp.example/v2.0",
		Resource: "https://mcp.example.com/mcp", Scopes: []string{"mcp"}, IdPTokens: []byte("sealed-idp-" + id),
		CreatedAt: t0, ExpiresAt: t0.Add(30 * 24 * time.Hour),
	}
}

func pendingCode(grantID string) store.PendingCode {
	return store.PendingCode{
		GrantID: grantID, ClientID: "client-" + grantID, RedirectURI: "http://127.0.0.1:33418/callback",
		CodeChallenge: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM", Scopes: []string{"mcp"}, ExpiresAt: t0.Add(time.Minute),
	}
}

func refresh(grantID string, n int) store.RefreshToken {
	return store.RefreshToken{
		Hash: sha256.Sum256(fmt.Appendf(nil, "%s-%d", grantID, n)), GrantID: grantID, ClientID: "client-" + grantID,
		CreatedAt: t0, IdleExpiresAt: t0.Add(14 * 24 * time.Hour),
	}
}

func mustCreate(t *testing.T, s store.Store, g store.Grant) store.Grant {
	t.Helper()
	got, err := s.CreateGrant(ctx, g)
	if err != nil {
		t.Fatalf("CreateGrant(%s): %v", g.ID, err)
	}
	return got
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func wantErr(t *testing.T, what string, err, want error) {
	t.Helper()
	if !errors.Is(err, want) {
		t.Fatalf("%s: err = %v, want %v", what, err, want)
	}
}

func grantsEqual(a, b store.Grant) bool {
	return a.ID == b.ID && a.ClientID == b.ClientID && a.Subject == b.Subject && a.Issuer == b.Issuer &&
		a.Resource == b.Resource && slices.Equal(a.Scopes, b.Scopes) && bytes.Equal(a.IdPTokens, b.IdPTokens) &&
		a.CreatedAt.Equal(b.CreatedAt) && a.ExpiresAt.Equal(b.ExpiresAt) && a.Epoch == b.Epoch
}

func codesEqual(a, b store.PendingCode) bool {
	return a.GrantID == b.GrantID && a.ClientID == b.ClientID && a.RedirectURI == b.RedirectURI &&
		a.CodeChallenge == b.CodeChallenge && slices.Equal(a.Scopes, b.Scopes) && a.ExpiresAt.Equal(b.ExpiresAt)
}

func createGrantSetsEpochAndRoundTrips(t *testing.T, s store.Store) {
	in := grant("g1", "tid:alice")
	in.Epoch = -7 // the caller's value is ignored
	created := mustCreate(t, s, in)
	if created.Epoch <= 0 {
		t.Fatalf("Epoch = %d, want a positive epoch set by the store", created.Epoch)
	}
	in.Epoch = created.Epoch
	if !grantsEqual(created, in) {
		t.Fatalf("CreateGrant returned %+v, want %+v", created, in)
	}
	got, err := s.Grant(ctx, "g1")
	must(t, err)
	if !grantsEqual(got, created) {
		t.Fatalf("Grant = %+v, want %+v", got, created)
	}
	noIdP := grant("g2", "tid:alice")
	noIdP.IdPTokens = nil
	mustCreate(t, s, noIdP)
	if got, _ := s.Grant(ctx, "g2"); len(got.IdPTokens) != 0 {
		t.Fatalf("IdPTokens = %q, want none", got.IdPTokens)
	}
}

func grantIgnoresExpiry(t *testing.T, s store.Store) {
	long := grant("expired-long-ago", "tid:alice")
	long.CreatedAt, long.ExpiresAt = time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC), time.Date(2000, 2, 1, 0, 0, 0, 0, time.UTC)
	mustCreate(t, s, long)
	if _, err := s.Grant(ctx, long.ID); err != nil {
		t.Fatalf("Grant of an expired, uncollected grant: %v (expiry is the caller's check)", err)
	}
}

func grantIDsAreUnique(t *testing.T, s store.Store) {
	mustCreate(t, s, grant("g1", "tid:alice"))
	_, err := s.CreateGrant(ctx, grant("g1", "tid:bob"))
	wantErr(t, "second CreateGrant with the same ID", err, store.ErrExists)
	if got, _ := s.Grant(ctx, "g1"); got.Subject != "tid:alice" {
		t.Fatalf("existing grant overwritten: subject %q", got.Subject)
	}
}

func unknownGrantIsNotFound(t *testing.T, s store.Store) {
	_, err := s.Grant(ctx, "nope")
	wantErr(t, "Grant", err, store.ErrNotFound)
}

func incompleteGrantsAndCutOffsAreInvalid(t *testing.T, s store.Store) {
	for name, edit := range map[string]func(*store.Grant){
		"no ID":                func(g *store.Grant) { g.ID = "" },
		"no client":            func(g *store.Grant) { g.ClientID = "" },
		"no subject":           func(g *store.Grant) { g.Subject = "" },
		"no lifetime":          func(g *store.Grant) { g.ExpiresAt = time.Time{} },
		"expires when created": func(g *store.Grant) { g.ExpiresAt = g.CreatedAt },
	} {
		t.Run(name, func(t *testing.T) {
			g := grant("g-"+name, "tid:alice")
			edit(&g)
			_, err := s.CreateGrant(ctx, g)
			wantErr(t, "CreateGrant", err, store.ErrInvalid)
		})
	}
	wantErr(t, "RevokeSubject without a subject", s.RevokeSubject(ctx, "", t0, t0), store.ErrInvalid)
	if revs, err := s.Revocations(ctx); err != nil || len(revs) != 0 {
		t.Fatalf("revocations = %+v, %v; want none", revs, err)
	}
}

func storedValuesAreCopies(t *testing.T, s store.Store) {
	g := grant("g1", "tid:alice")
	mustCreate(t, s, g)
	g.Scopes[0], g.IdPTokens[0] = "changed", 'X'
	got, _ := s.Grant(ctx, "g1")
	if got.Scopes[0] != "mcp" || got.IdPTokens[0] != 's' {
		t.Fatal("changing the caller's grant after CreateGrant changed the stored one")
	}
	got.Scopes[0], got.IdPTokens[0] = "changed", 'X'
	if again, _ := s.Grant(ctx, "g1"); again.Scopes[0] != "mcp" || again.IdPTokens[0] != 's' {
		t.Fatal("changing a returned grant changed the stored one")
	}
	c := pendingCode("g1")
	must(t, s.PutCode(ctx, c))
	c.Scopes[0] = "changed"
	consumed, err := s.ConsumeCode(ctx, "g1", t0)
	must(t, err)
	if consumed.Scopes[0] != "mcp" {
		t.Fatal("changing the caller's code after PutCode changed the stored one")
	}
}

func codeIsConsumedOnce(t *testing.T, s store.Store) {
	mustCreate(t, s, grant("g1", "tid:alice"))
	want := pendingCode("g1")
	must(t, s.PutCode(ctx, want))
	got, err := s.ConsumeCode(ctx, "g1", t0)
	must(t, err)
	if !codesEqual(got, want) {
		t.Fatalf("ConsumeCode = %+v, want %+v", got, want)
	}
	_, err = s.ConsumeCode(ctx, "g1", t0)
	wantErr(t, "second ConsumeCode", err, store.ErrConsumed)
	_, err = s.ConsumeCode(ctx, "unknown", t0)
	wantErr(t, "ConsumeCode of an unknown grant", err, store.ErrNotFound)
}

func concurrentConsumeHasOneWinner(t *testing.T, s store.Store) {
	mustCreate(t, s, grant("g1", "tid:alice"))
	must(t, s.PutCode(ctx, pendingCode("g1")))
	const n = 32
	errs := make([]error, n)
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := range n {
		wg.Go(func() {
			<-start
			_, errs[i] = s.ConsumeCode(ctx, "g1", t0)
		})
	}
	close(start)
	wg.Wait()
	wins := 0
	for _, err := range errs {
		switch {
		case err == nil:
			wins++
		case !errors.Is(err, store.ErrConsumed):
			t.Fatalf("loser got %v, want ErrConsumed", err)
		}
	}
	if wins != 1 {
		t.Fatalf("%d goroutines consumed the code, want exactly 1", wins)
	}
}

func expiredCodeIsNotFound(t *testing.T, s store.Store) {
	mustCreate(t, s, grant("g1", "tid:alice"))
	c := pendingCode("g1")
	must(t, s.PutCode(ctx, c))
	_, err := s.ConsumeCode(ctx, "g1", c.ExpiresAt)
	wantErr(t, "ConsumeCode at ExpiresAt", err, store.ErrNotFound)
	if _, err := s.ConsumeCode(ctx, "g1", c.ExpiresAt.Add(-tick)); err != nil {
		t.Fatalf("ConsumeCode just before ExpiresAt: %v (an expired attempt must not consume it)", err)
	}
	_, err = s.ConsumeCode(ctx, "g1", c.ExpiresAt.Add(time.Hour))
	wantErr(t, "consumed code after it expired", err, store.ErrNotFound)
}

func codeNeedsAGrantAndIsUniquePerGrant(t *testing.T, s store.Store) {
	wantErr(t, "PutCode for an unknown grant", s.PutCode(ctx, pendingCode("nope")), store.ErrNotFound)
	mustCreate(t, s, grant("g1", "tid:alice"))
	must(t, s.PutCode(ctx, pendingCode("g1")))
	wantErr(t, "second pending code", s.PutCode(ctx, pendingCode("g1")), store.ErrExists)
	_, err := s.ConsumeCode(ctx, "g1", t0)
	must(t, err)
	wantErr(t, "new code after the first was consumed", s.PutCode(ctx, pendingCode("g1")), store.ErrExists)
}

func refreshTokenRoundTripsAndIdleExpires(t *testing.T, s store.Store) {
	mustCreate(t, s, grant("g1", "tid:alice"))
	want := refresh("g1", 1)
	must(t, s.PutRefreshToken(ctx, want))
	must(t, s.PutRefreshToken(ctx, refresh("g1", 2)))
	got, err := s.RefreshToken(ctx, want.Hash, t0)
	must(t, err)
	if got.Hash != want.Hash || got.GrantID != want.GrantID || got.ClientID != want.ClientID ||
		!got.CreatedAt.Equal(want.CreatedAt) || !got.IdleExpiresAt.Equal(want.IdleExpiresAt) {
		t.Fatalf("RefreshToken = %+v, want %+v", got, want)
	}
	_, err = s.RefreshToken(ctx, sha256.Sum256([]byte("other")), t0)
	wantErr(t, "unknown hash", err, store.ErrNotFound)
	_, err = s.RefreshToken(ctx, want.Hash, want.IdleExpiresAt.In(otherZone))
	wantErr(t, "RefreshToken at IdleExpiresAt (in another zone)", err, store.ErrNotFound)
	if _, err := s.RefreshToken(ctx, want.Hash, want.IdleExpiresAt.Add(-tick)); err != nil {
		t.Fatalf("RefreshToken just before IdleExpiresAt: %v", err)
	}
}

func refreshTokenNeedsAGrantAndAUniqueHash(t *testing.T, s store.Store) {
	wantErr(t, "PutRefreshToken for an unknown grant", s.PutRefreshToken(ctx, refresh("nope", 1)), store.ErrNotFound)
	mustCreate(t, s, grant("g1", "tid:alice"))
	mustCreate(t, s, grant("g2", "tid:bob"))
	rt := refresh("g1", 1)
	must(t, s.PutRefreshToken(ctx, rt))
	dup := rt
	dup.GrantID = "g2"
	wantErr(t, "same hash again", s.PutRefreshToken(ctx, dup), store.ErrExists)
	if got, _ := s.RefreshToken(ctx, rt.Hash, t0); got.GrantID != "g1" {
		t.Fatalf("existing token overwritten: grant %q", got.GrantID)
	}
}

func revokeGrantDeletesItsRowsAndRecordsARevocation(t *testing.T, s store.Store) {
	mustCreate(t, s, grant("g1", "tid:alice"))
	mustCreate(t, s, grant("g2", "tid:alice"))
	for _, id := range []string{"g1", "g2"} {
		must(t, s.PutCode(ctx, pendingCode(id)))
		must(t, s.PutRefreshToken(ctx, refresh(id, 1)))
	}
	at := t0.Add(time.Minute)
	must(t, s.RevokeGrant(ctx, "g1", at))

	_, err := s.Grant(ctx, "g1")
	wantErr(t, "revoked grant", err, store.ErrNotFound)
	_, err = s.ConsumeCode(ctx, "g1", t0)
	wantErr(t, "code of a revoked grant", err, store.ErrNotFound)
	_, err = s.RefreshToken(ctx, refresh("g1", 1).Hash, t0)
	wantErr(t, "refresh token of a revoked grant", err, store.ErrNotFound)

	if _, err := s.Grant(ctx, "g2"); err != nil {
		t.Fatalf("other grant: %v", err)
	}
	if _, err := s.ConsumeCode(ctx, "g2", t0); err != nil {
		t.Fatalf("other grant's code: %v", err)
	}
	if _, err := s.RefreshToken(ctx, refresh("g2", 1).Hash, t0); err != nil {
		t.Fatalf("other grant's refresh token: %v", err)
	}
	revs, err := s.Revocations(ctx)
	must(t, err)
	if want := (store.Revocation{GrantID: "g1", Before: at, At: at}); len(revs) != 1 || !revEqual(revs[0], want) {
		t.Fatalf("revocations = %+v, want [%+v]", revs, want)
	}
}

func revokeUnknownGrantRecordsNothing(t *testing.T, s store.Store) {
	wantErr(t, "RevokeGrant of an unknown grant", s.RevokeGrant(ctx, "nope", t0), store.ErrNotFound)
	if revs, err := s.Revocations(ctx); err != nil || len(revs) != 0 {
		t.Fatalf("revocations = %+v, %v; want none", revs, err)
	}
}

func revokeSubjectCutsOffEarlierGrants(t *testing.T, s store.Store) {
	before := t0.Add(time.Hour)
	old := grant("old", "tid:alice")
	newer := grant("newer", "tid:alice")
	newer.CreatedAt = before // not before the cut-off: kept
	other := grant("other", "tid:bob")
	for _, g := range []store.Grant{old, newer, other} {
		mustCreate(t, s, g)
		must(t, s.PutCode(ctx, pendingCode(g.ID)))
		must(t, s.PutRefreshToken(ctx, refresh(g.ID, 1)))
	}
	at := before.Add(time.Second)
	must(t, s.RevokeSubject(ctx, "tid:alice", before, at))

	_, err := s.Grant(ctx, "old")
	wantErr(t, "grant before the cut-off", err, store.ErrNotFound)
	_, err = s.ConsumeCode(ctx, "old", t0)
	wantErr(t, "its code", err, store.ErrNotFound)
	_, err = s.RefreshToken(ctx, refresh("old", 1).Hash, t0)
	wantErr(t, "its refresh token", err, store.ErrNotFound)
	for _, id := range []string{"newer", "other"} {
		if _, err := s.Grant(ctx, id); err != nil {
			t.Fatalf("grant %s: %v", id, err)
		}
		if _, err := s.RefreshToken(ctx, refresh(id, 1).Hash, t0); err != nil {
			t.Fatalf("refresh token of %s: %v", id, err)
		}
	}
	must(t, s.RevokeSubject(ctx, "tid:nobody", before, at.Add(time.Second)))
	revs, err := s.Revocations(ctx)
	must(t, err)
	want := []store.Revocation{{Subject: "tid:alice", Before: before, At: at}, {Subject: "tid:nobody", Before: before, At: at.Add(time.Second)}}
	if len(revs) != 2 || !revEqual(revs[0], want[0]) || !revEqual(revs[1], want[1]) {
		t.Fatalf("revocations = %+v, want %+v (a cut-off is recorded even without grants)", revs, want)
	}
}

func revocationsAreOldestFirst(t *testing.T, s store.Store) {
	for i, at := range []time.Duration{3, 1, 2, 5} { // recorded out of order
		id := fmt.Sprintf("g%d", i)
		mustCreate(t, s, grant(id, "tid:alice"))
		must(t, s.RevokeGrant(ctx, id, t0.Add(at*time.Minute)))
	}
	revs, err := s.Revocations(ctx)
	must(t, err)
	var got []string
	for _, r := range revs {
		got = append(got, r.GrantID)
	}
	if want := []string{"g1", "g2", "g0", "g3"}; !slices.Equal(got, want) {
		t.Fatalf("Revocations = %v, want %v, oldest first", got, want)
	}
}

func cutOffRefusesLaterCreatedEarlierGrants(t *testing.T, s store.Store) {
	before := t0.Add(time.Hour)
	must(t, s.RevokeSubject(ctx, "tid:alice", before, before))
	inFlight := grant("in-flight", "tid:alice")
	inFlight.CreatedAt = before.Add(-time.Minute) // the login started before revoke-user
	_, err := s.CreateGrant(ctx, inFlight)
	wantErr(t, "CreateGrant covered by a cut-off", err, store.ErrRevoked)
	if _, err := s.Grant(ctx, "in-flight"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("refused grant was stored: %v", err)
	}
	after := grant("after", "tid:alice")
	after.CreatedAt, after.ExpiresAt = before, before.Add(time.Hour) // not before the cut-off
	mustCreate(t, s, after)
	mustCreate(t, s, grant("other-user", "tid:bob"))
}

// Whatever the interleaving, a grant created before the cut-off never survives it: either it is
// stored first and RevokeSubject deletes it, or CreateGrant sees the cut-off and refuses.
func revokeSubjectAndCreateGrantNeverLeaveACoveredGrant(t *testing.T, s store.Store) {
	const rounds = 50
	before := t0.Add(time.Hour)
	var wg sync.WaitGroup
	for i := range rounds {
		subject := fmt.Sprintf("tid:user-%d", i)
		start := make(chan struct{})
		wg.Go(func() {
			<-start
			_, err := s.CreateGrant(ctx, grant(subject, subject)) // CreatedAt t0, before the cut-off
			if err != nil && !errors.Is(err, store.ErrRevoked) {
				t.Errorf("CreateGrant %s: %v", subject, err)
			}
		})
		wg.Go(func() {
			<-start
			if err := s.RevokeSubject(ctx, subject, before, before); err != nil {
				t.Errorf("RevokeSubject %s: %v", subject, err)
			}
		})
		close(start)
	}
	wg.Wait()
	for i := range rounds {
		id := fmt.Sprintf("tid:user-%d", i)
		if _, err := s.Grant(ctx, id); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("grant %s survived its subject's cut-off: %v", id, err)
		}
	}
}

func collectRemovesExpiredRowsOnly(t *testing.T, s store.Store) {
	now := t0.Add(10 * time.Minute)
	expired := grant("expired", "tid:alice")
	expired.ExpiresAt = now
	live := grant("live", "tid:alice")
	mustCreate(t, s, expired)
	mustCreate(t, s, live)
	must(t, s.PutRefreshToken(ctx, refresh("expired", 1)))
	expiring := pendingCode("live")
	expiring.ExpiresAt = now // the boundary: collected
	must(t, s.PutCode(ctx, expiring))
	consumedLive := grant("consumed", "tid:alice")
	mustCreate(t, s, consumedLive)
	usedCode := pendingCode("consumed")
	usedCode.ExpiresAt = now
	must(t, s.PutCode(ctx, usedCode))
	if _, err := s.ConsumeCode(ctx, "consumed", t0); err != nil {
		t.Fatal(err)
	}
	idle := refresh("live", 1)
	idle.IdleExpiresAt = now
	fresh := refresh("live", 2)
	must(t, s.PutRefreshToken(ctx, idle))
	must(t, s.PutRefreshToken(ctx, fresh))

	must(t, s.Collect(ctx, now.In(otherZone)))

	_, err := s.Grant(ctx, "expired")
	wantErr(t, "expired grant after Collect", err, store.ErrNotFound)
	_, err = s.RefreshToken(ctx, refresh("expired", 1).Hash, t0)
	wantErr(t, "refresh token of a collected grant", err, store.ErrNotFound)
	if _, err := s.Grant(ctx, "live"); err != nil {
		t.Fatalf("live grant collected: %v", err)
	}
	// Expired codes are gone, pending or consumed, so each grant can hold a new one.
	must(t, s.PutCode(ctx, pendingCode("live")))
	must(t, s.PutCode(ctx, pendingCode("consumed")))
	// The idle-expired token is gone, so its hash can be stored again; the fresh one stays.
	must(t, s.PutRefreshToken(ctx, idle))
	if _, err := s.RefreshToken(ctx, fresh.Hash, now); err != nil {
		t.Fatalf("live refresh token collected: %v", err)
	}
}

func collectRemovesOldRevocations(t *testing.T, s store.Store) {
	now := t0.Add(2 * time.Hour)
	for id, at := range map[string]time.Time{
		"old":      now.Add(-store.RevocationRetention - time.Second),
		"boundary": now.Add(-store.RevocationRetention),
		"recent":   now.Add(-time.Minute),
	} {
		mustCreate(t, s, grant(id, "tid:alice"))
		must(t, s.RevokeGrant(ctx, id, at))
	}
	must(t, s.Collect(ctx, now))
	revs, err := s.Revocations(ctx)
	must(t, err)
	if len(revs) != 1 || revs[0].GrantID != "recent" {
		t.Fatalf("revocations after Collect = %+v, want only the one within RevocationRetention", revs)
	}
}

func concurrentUseIsSafe(t *testing.T, s store.Store) {
	var wg sync.WaitGroup
	for i := range 16 {
		wg.Go(func() {
			id := fmt.Sprintf("g%d", i)
			if _, err := s.CreateGrant(ctx, grant(id, "tid:alice")); err != nil {
				t.Error(err)
				return
			}
			check := func(what string, err error) {
				if err != nil {
					t.Errorf("%s %s: %v", what, id, err)
				}
			}
			check("PutCode", s.PutCode(ctx, pendingCode(id)))
			check("PutRefreshToken", s.PutRefreshToken(ctx, refresh(id, 1)))
			_, err := s.Grant(ctx, id)
			check("Grant", err)
			_, err = s.Revocations(ctx)
			check("Revocations", err)
			if i%2 == 0 {
				check("RevokeGrant", s.RevokeGrant(ctx, id, t0))
			}
			check("Collect", s.Collect(ctx, t0))
		})
	}
	wg.Wait()
	revs, err := s.Revocations(ctx)
	must(t, err)
	if len(revs) != 8 {
		t.Fatalf("%d revocations, want 8", len(revs))
	}
}

func revEqual(a, b store.Revocation) bool {
	return a.GrantID == b.GrantID && a.Subject == b.Subject && a.Before.Equal(b.Before) && a.At.Equal(b.At)
}
