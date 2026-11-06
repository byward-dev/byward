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

	"github.com/byward-dev/byward/internal/store"
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
		{"NilScopesComeBackNil", nilScopesComeBackNil},
		{"CodeIsConsumedOnce", codeIsConsumedOnce},
		{"ConcurrentConsumeHasOneWinner", concurrentConsumeHasOneWinner},
		{"ExpiredCodeIsNotFound", expiredCodeIsNotFound},
		{"CodeNeedsAGrantAndIsUniquePerGrant", codeNeedsAGrantAndIsUniquePerGrant},
		{"RefreshTokenRoundTripsAndIdleExpires", refreshTokenRoundTripsAndIdleExpires},
		{"RefreshTokenNeedsAGrantAndAUniqueHash", refreshTokenNeedsAGrantAndAUniqueHash},
		{"RevokeGrantDeletesItsRowsAndRecordsARevocation", revokeGrantDeletesItsRowsAndRecordsARevocation},
		{"UpdateGrantSetsExpiryAndRefusesBadInput", updateGrantSetsExpiryAndRefusesBadInput},
		{"SetIdPTokensReplacesALiveGrantsTokensOnly", setIdPTokensReplacesALiveGrantsTokensOnly},
		{"SetIdPTokensAndRevokeSubjectNeverRestoreAGrant", setIdPTokensAndRevokeSubjectNeverRestoreAGrant},
		{"RotateMakesTheNextTokenCurrent", rotateMakesTheNextTokenCurrent},
		{"RetryWithinGraceRotatesTheSuccessor", retryWithinGraceRotatesTheSuccessor},
		{"ReuseRevokesTheGrant", reuseRevokesTheGrant},
		{"RotateRefusesBadRequests", rotateRefusesBadRequests},
		{"PutRefreshTokenIgnoresRotatedAt", putRefreshTokenIgnoresRotatedAt},
		{"ConcurrentRotationWithoutGraceHasOneWinner", concurrentRotationWithoutGraceHasOneWinner},
		{"RevokeUnknownGrantRecordsNothing", revokeUnknownGrantRecordsNothing},
		{"RevokeSubjectCutsOffEarlierGrants", revokeSubjectCutsOffEarlierGrants},
		{"RevocationsAreOldestFirst", revocationsAreOldestFirst},
		{"CutOffRefusesLaterCreatedEarlierGrants", cutOffRefusesLaterCreatedEarlierGrants},
		{"RevokeSubjectAndCreateGrantNeverLeaveACoveredGrant", revokeSubjectAndCreateGrantNeverLeaveACoveredGrant},
		{"RevokeAllCutsOffEveryEarlierGrant", revokeAllCutsOffEveryEarlierGrant},
		{"RevokeAllRefusesLaterCreatedEarlierGrantsOfAnySubject", revokeAllRefusesLaterCreatedEarlierGrantsOfAnySubject},
		{"RevokeAllAndCreateGrantNeverLeaveACoveredGrant", revokeAllAndCreateGrantNeverLeaveACoveredGrant},
		{"AnEmptySubjectRevokesNobody", anEmptySubjectRevokesNobody},
		{"CollectRemovesExpiredRowsOnly", collectRemovesExpiredRowsOnly},
		{"CollectRemovesOldRevocations", collectRemovesOldRevocations},
		{"ConcurrentUseIsSafe", concurrentUseIsSafe},
		{"ClientRoundTripsAsACopy", clientRoundTripsAsACopy},
		{"ClientIDsAreUniqueAndIncompleteClientsInvalid", clientIDsAreUniqueAndIncompleteClientsInvalid},
		{"CreateClientEnforcesTheCapOnLiveClients", createClientEnforcesTheCapOnLiveClients},
		{"ConcurrentCreateClientNeverExceedsTheCap", concurrentCreateClientNeverExceedsTheCap},
		{"UseClientMarksUseAndExtendsWithoutShortening", useClientMarksUseAndExtendsWithoutShortening},
		{"CollectRemovesExpiredClientsAndClientsUnusedForTheirFirstDay", collectRemovesExpiredClientsAndClientsUnusedForTheirFirstDay},
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

// A nil slice is returned as nil, not as an empty one: callers that compare with reflect.DeepEqual
// or encode JSON (null versus []) see the same value from every adapter.
func nilScopesComeBackNil(t *testing.T, s store.Store) {
	g := grant("g1", "tid:alice")
	g.Scopes = nil
	mustCreate(t, s, g)
	if got, err := s.Grant(ctx, "g1"); err != nil || got.Scopes != nil {
		t.Fatalf("Grant Scopes = %#v (%v), want nil", got.Scopes, err)
	}
	c := pendingCode("g1")
	c.Scopes = nil
	must(t, s.PutCode(ctx, c))
	if got, err := s.ConsumeCode(ctx, "g1", t0); err != nil || got.Scopes != nil {
		t.Fatalf("ConsumeCode Scopes = %#v (%v), want nil", got.Scopes, err)
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
	must(t, s.RevokeSubject(ctx, "tid:alice", before.In(otherZone), before))
	inFlight := grant("in-flight", "tid:alice")
	inFlight.CreatedAt = before.Add(-tick) // the login started just before revoke-user
	_, err := s.CreateGrant(ctx, inFlight)
	wantErr(t, "CreateGrant covered by a cut-off", err, store.ErrRevoked)
	if _, err := s.Grant(ctx, "in-flight"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("refused grant was stored: %v", err)
	}
	after := grant("after", "tid:alice")
	after.CreatedAt, after.ExpiresAt = before, before.Add(time.Hour) // not before the cut-off
	mustCreate(t, s, after)
	mustCreate(t, s, grant("other-user", "tid:bob"))

	// Once Collect drops the cut-off it no longer refuses: only retained cut-offs count.
	must(t, s.Collect(ctx, before.Add(store.RevocationRetention)))
	late := grant("late", "tid:alice")
	late.CreatedAt, late.ExpiresAt = before.Add(-time.Minute), before.Add(48*time.Hour)
	mustCreate(t, s, late)
}

// Whatever the interleaving, a grant created before the cut-off never survives it: either it is
// stored first and RevokeSubject deletes it, or CreateGrant sees the cut-off and refuses.
// Passing is not proof for SQL adapters: the write-skew window is narrow, so an adapter's own
// tests must also cover its per-subject lock or serialization retry (see Grants.CreateGrant).
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

func revokeAllCutsOffEveryEarlierGrant(t *testing.T, s store.Store) {
	before := t0.Add(time.Hour)
	newer := grant("newer", "tid:carol")
	newer.CreatedAt = before // not before the cut-off: kept
	for _, g := range []store.Grant{grant("alice", "tid:alice"), grant("bob", "tid:bob"), newer} {
		mustCreate(t, s, g)
		must(t, s.PutCode(ctx, pendingCode(g.ID)))
		must(t, s.PutRefreshToken(ctx, refresh(g.ID, 1)))
	}
	at := before.Add(time.Second)
	must(t, s.RevokeAll(ctx, before, at))
	for _, id := range []string{"alice", "bob"} {
		_, err := s.Grant(ctx, id)
		wantErr(t, "grant "+id+" before the cut-off", err, store.ErrNotFound)
		_, err = s.ConsumeCode(ctx, id, t0)
		wantErr(t, "its code", err, store.ErrNotFound)
		_, err = s.RefreshToken(ctx, refresh(id, 1).Hash, t0)
		wantErr(t, "its refresh token", err, store.ErrNotFound)
	}
	if _, err := s.Grant(ctx, "newer"); err != nil {
		t.Fatalf("grant created at the cut-off: %v", err)
	}
	revs, err := s.Revocations(ctx)
	must(t, err)
	if want := (store.Revocation{All: true, Before: before, At: at}); len(revs) != 1 || !revEqual(revs[0], want) {
		t.Fatalf("revocations = %+v, want one %+v", revs, want)
	}
}

func revokeAllRefusesLaterCreatedEarlierGrantsOfAnySubject(t *testing.T, s store.Store) {
	before := t0.Add(time.Hour)
	must(t, s.RevokeAll(ctx, before.In(otherZone), before))
	for _, subject := range []string{"tid:alice", "tid:someone-new"} {
		inFlight := grant("in-flight-"+subject, subject)
		inFlight.CreatedAt = before.Add(-tick) // a login that started just before revoke-all
		_, err := s.CreateGrant(ctx, inFlight)
		wantErr(t, "CreateGrant for "+subject+" covered by revoke-all", err, store.ErrRevoked)
	}
	after := grant("after", "tid:alice")
	after.CreatedAt, after.ExpiresAt = before, before.Add(time.Hour)
	mustCreate(t, s, after)
}

// As for RevokeSubject: whatever the interleaving, a grant created before the cut-off never
// survives revoke-all.
func revokeAllAndCreateGrantNeverLeaveACoveredGrant(t *testing.T, s store.Store) {
	const rounds = 50
	before := t0.Add(time.Hour)
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := range rounds {
		id := fmt.Sprintf("tid:user-%d", i)
		wg.Go(func() {
			<-start
			_, err := s.CreateGrant(ctx, grant(id, id)) // CreatedAt t0, before the cut-off
			if err != nil && !errors.Is(err, store.ErrRevoked) {
				t.Errorf("CreateGrant %s: %v", id, err)
			}
		})
	}
	wg.Go(func() {
		<-start
		if err := s.RevokeAll(ctx, before, before); err != nil {
			t.Errorf("RevokeAll: %v", err)
		}
	})
	close(start)
	wg.Wait()
	for i := range rounds {
		id := fmt.Sprintf("tid:user-%d", i)
		if _, err := s.Grant(ctx, id); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("grant %s survived revoke-all: %v", id, err)
		}
	}
}

// Only RevokeAll revokes every subject. An empty subject is refused, records nothing and leaves
// every grant and every later login alone, so a zero value can never revoke everyone by mistake.
func anEmptySubjectRevokesNobody(t *testing.T, s store.Store) {
	mustCreate(t, s, grant("alice", "tid:alice"))
	wantErr(t, "RevokeSubject without a subject", s.RevokeSubject(ctx, "", t0.Add(time.Hour), t0.Add(time.Hour)), store.ErrInvalid)
	if _, err := s.Grant(ctx, "alice"); err != nil {
		t.Fatalf("grant after a refused empty revocation: %v", err)
	}
	mustCreate(t, s, grant("bob", "tid:bob"))
	if revs, err := s.Revocations(ctx); err != nil || len(revs) != 0 {
		t.Fatalf("revocations = %+v, %v; want none", revs, err)
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
	return a.GrantID == b.GrantID && a.Subject == b.Subject && a.All == b.All && a.Before.Equal(b.Before) && a.At.Equal(b.At)
}

const grace = 30 * time.Second

func rotation(old, next store.RefreshToken, now time.Time) store.RotateRequest {
	next.CreatedAt = now
	return store.RotateRequest{Old: old.Hash, Next: next, Now: now, Grace: grace}
}

func updateGrantSetsExpiryAndRefusesBadInput(t *testing.T, s store.Store) {
	g := grant("g1", "tid:alice")
	g.ExpiresAt = t0.Add(10 * time.Minute) // a login whose code is not redeemed yet
	mustCreate(t, s, g)
	later := t0.Add(30 * 24 * time.Hour)
	must(t, s.UpdateGrant(ctx, "g1", later))
	if got, _ := s.Grant(ctx, "g1"); !got.ExpiresAt.Equal(later) {
		t.Fatalf("ExpiresAt = %v, want %v", got.ExpiresAt, later)
	}
	wantErr(t, "UpdateGrant of an unknown grant", s.UpdateGrant(ctx, "nope", later), store.ErrNotFound)
	wantErr(t, "UpdateGrant to CreatedAt", s.UpdateGrant(ctx, "g1", g.CreatedAt), store.ErrInvalid)
}

// SetIdPTokens replaces a live grant's sealed IdP tokens with a copy; an unknown or revoked grant is
// ErrNotFound and nothing is written; empty tokens are ErrInvalid.
func setIdPTokensReplacesALiveGrantsTokensOnly(t *testing.T, s store.Store) {
	mustCreate(t, s, grant("g1", "tid:alice"))
	fresh := []byte("refreshed-idp-tokens")
	must(t, s.SetIdPTokens(ctx, "g1", fresh))
	fresh[0] = 'X'
	if got, _ := s.Grant(ctx, "g1"); string(got.IdPTokens) != "refreshed-idp-tokens" {
		t.Fatalf("IdPTokens = %q, want the replacement, as a copy", got.IdPTokens)
	}
	wantErr(t, "SetIdPTokens without tokens", s.SetIdPTokens(ctx, "g1", nil), store.ErrInvalid)
	wantErr(t, "SetIdPTokens of an unknown grant", s.SetIdPTokens(ctx, "nope", []byte("t")), store.ErrNotFound)
	must(t, s.RevokeGrant(ctx, "g1", t0.Add(time.Minute)))
	wantErr(t, "SetIdPTokens of a revoked grant", s.SetIdPTokens(ctx, "g1", []byte("t")), store.ErrNotFound)
	wantErr(t, "the revoked grant after SetIdPTokens", func() error { _, err := s.Grant(ctx, "g1"); return err }(), store.ErrNotFound)
}

// Whatever the interleaving, SetIdPTokens never brings back a grant RevokeSubject deletes: it
// either lands first and the grant is then deleted, or it finds the grant gone (ErrNotFound).
// A probabilistic smoke test for check-then-act across lock sections; the guarantee is the
// sequential ErrNotFound case in setIdPTokensReplacesALiveGrantsTokensOnly.
func setIdPTokensAndRevokeSubjectNeverRestoreAGrant(t *testing.T, s store.Store) {
	const rounds = 50
	before := t0.Add(time.Hour)
	for i := range rounds {
		id := fmt.Sprintf("tid:user-%d", i)
		mustCreate(t, s, grant(id, id))
	}
	var wg sync.WaitGroup
	for i := range rounds {
		id := fmt.Sprintf("tid:user-%d", i)
		start := make(chan struct{})
		wg.Go(func() {
			<-start
			if err := s.SetIdPTokens(ctx, id, []byte("refreshed")); err != nil && !errors.Is(err, store.ErrNotFound) {
				t.Errorf("SetIdPTokens %s: %v", id, err)
			}
		})
		wg.Go(func() {
			<-start
			if err := s.RevokeSubject(ctx, id, before, before); err != nil {
				t.Errorf("RevokeSubject %s: %v", id, err)
			}
		})
		close(start)
	}
	wg.Wait()
	for i := range rounds {
		id := fmt.Sprintf("tid:user-%d", i)
		if _, err := s.Grant(ctx, id); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("grant %s survived its subject's revocation: %v", id, err)
		}
	}
}

func rotateMakesTheNextTokenCurrent(t *testing.T, s store.Store) {
	mustCreate(t, s, grant("g1", "tid:alice"))
	t1, t2 := refresh("g1", 1), refresh("g1", 2)
	must(t, s.PutRefreshToken(ctx, t1))
	at := t0.Add(time.Minute)
	req := rotation(t1, t2, at)
	req.IdPTokens = []byte("rotated-idp-tokens")
	must(t, s.RotateRefreshToken(ctx, req))

	old, err := s.RefreshToken(ctx, t1.Hash, at)
	must(t, err)
	if !old.RotatedAt.Equal(at) {
		t.Fatalf("old token RotatedAt = %v, want %v", old.RotatedAt, at)
	}
	cur, err := s.RefreshToken(ctx, t2.Hash, at)
	must(t, err)
	if !cur.RotatedAt.IsZero() || cur.Hash != t2.Hash || cur.GrantID != "g1" || cur.ClientID != t2.ClientID ||
		!cur.CreatedAt.Equal(at) || !cur.IdleExpiresAt.Equal(t2.IdleExpiresAt) {
		t.Fatalf("next token = %+v, want the requested one, current, for g1", cur)
	}
	if g, _ := s.Grant(ctx, "g1"); string(g.IdPTokens) != "rotated-idp-tokens" {
		t.Fatalf("IdP tokens = %q, want them replaced in the same step", g.IdPTokens)
	}
	// Without IdPTokens the grant keeps its own.
	must(t, s.RotateRefreshToken(ctx, rotation(t2, refresh("g1", 3), at.Add(time.Minute))))
	if g, _ := s.Grant(ctx, "g1"); string(g.IdPTokens) != "rotated-idp-tokens" {
		t.Fatalf("IdP tokens = %q after a rotation without new ones", g.IdPTokens)
	}
}

func retryWithinGraceRotatesTheSuccessor(t *testing.T, s store.Store) {
	mustCreate(t, s, grant("g1", "tid:alice"))
	t1, t2, t3, t4 := refresh("g1", 1), refresh("g1", 2), refresh("g1", 3), refresh("g1", 4)
	must(t, s.PutRefreshToken(ctx, t1))
	at := t0.Add(time.Minute)
	must(t, s.RotateRefreshToken(ctx, rotation(t1, t2, at)))
	// The response carrying t2 was lost; the client retries with t1 just inside the window.
	must(t, s.RotateRefreshToken(ctx, rotation(t1, t3, at.Add(grace-tick))))
	got, err := s.RefreshToken(ctx, t2.Hash, at)
	must(t, err)
	if got.RotatedAt.IsZero() {
		t.Fatal("t2 is still current after the retry; it must be rotated away")
	}
	got, err = s.RefreshToken(ctx, t3.Hash, at)
	must(t, err)
	if !got.RotatedAt.IsZero() {
		t.Fatal("t3 is not current after the retry")
	}
	// A second retry in the window also works, and the window is not extended by the retries: it
	// ends grace after the first rotation.
	must(t, s.RotateRefreshToken(ctx, rotation(t1, t4, at.Add(grace-tick))))
	wantErr(t, "retry at the end of the original window", s.RotateRefreshToken(ctx, rotation(t1, refresh("g1", 5), at.Add(grace))), store.ErrReused)
}

func reuseRevokesTheGrant(t *testing.T, s store.Store) {
	cases := []struct {
		name  string
		reuse func(t *testing.T, s store.Store, g string) error
	}{
		{"at the end of the grace window", func(t *testing.T, s store.Store, g string) error {
			t1 := refresh(g, 1)
			must(t, s.PutRefreshToken(ctx, t1))
			at := t0.Add(time.Minute)
			must(t, s.RotateRefreshToken(ctx, rotation(t1, refresh(g, 2), at)))
			return s.RotateRefreshToken(ctx, rotation(t1, refresh(g, 3), at.Add(grace)))
		}},
		{"an older token within the window", func(t *testing.T, s store.Store, g string) error {
			t1, t2 := refresh(g, 1), refresh(g, 2)
			must(t, s.PutRefreshToken(ctx, t1))
			at := t0.Add(time.Minute)
			must(t, s.RotateRefreshToken(ctx, rotation(t1, t2, at)))
			must(t, s.RotateRefreshToken(ctx, rotation(t2, refresh(g, 3), at.Add(time.Second))))
			return s.RotateRefreshToken(ctx, rotation(t1, refresh(g, 4), at.Add(2*time.Second)))
		}},
		{"with no grace at all", func(t *testing.T, s store.Store, g string) error {
			t1 := refresh(g, 1)
			must(t, s.PutRefreshToken(ctx, t1))
			at := t0.Add(time.Minute)
			req := rotation(t1, refresh(g, 2), at)
			req.Grace = 0
			must(t, s.RotateRefreshToken(ctx, req))
			req.Next = refresh(g, 3)
			return s.RotateRefreshToken(ctx, req)
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			g := "g-" + tc.name // one store for all cases: a grant each
			mustCreate(t, s, grant(g, "tid:alice"))
			wantErr(t, "reuse", tc.reuse(t, s, g), store.ErrReused)
			_, err := s.Grant(ctx, g)
			wantErr(t, "grant after reuse", err, store.ErrNotFound)
			revs, err := s.Revocations(ctx)
			must(t, err)
			if !slices.ContainsFunc(revs, func(r store.Revocation) bool { return r.GrantID == g }) {
				t.Fatalf("revocations = %+v, want one for %s", revs, g)
			}
		})
	}
}

func rotateRefusesBadRequests(t *testing.T, s store.Store) {
	mustCreate(t, s, grant("g1", "tid:alice"))
	mustCreate(t, s, grant("g2", "tid:bob"))
	t1 := refresh("g1", 1)
	must(t, s.PutRefreshToken(ctx, t1))
	must(t, s.PutRefreshToken(ctx, refresh("g1", 9)))
	at := t0.Add(time.Minute)
	wantErr(t, "unknown token", s.RotateRefreshToken(ctx, rotation(refresh("g1", 5), refresh("g1", 6), at)), store.ErrNotFound)
	wantErr(t, "idle-expired token", s.RotateRefreshToken(ctx, rotation(t1, refresh("g1", 6), t1.IdleExpiresAt)), store.ErrNotFound)
	wantErr(t, "next for another grant", s.RotateRefreshToken(ctx, rotation(t1, refresh("g2", 6), at)), store.ErrInvalid)
	wantErr(t, "next hash already stored", s.RotateRefreshToken(ctx, rotation(t1, refresh("g1", 9), at)), store.ErrExists)
	got, err := s.RefreshToken(ctx, t1.Hash, at)
	must(t, err)
	if !got.RotatedAt.IsZero() {
		t.Fatal("a refused rotation changed the token")
	}
}

// RotatedAt belongs to the store: a token stored with it set is still current.
func putRefreshTokenIgnoresRotatedAt(t *testing.T, s store.Store) {
	mustCreate(t, s, grant("g1", "tid:alice"))
	pre := refresh("g1", 7)
	pre.RotatedAt = t0
	must(t, s.PutRefreshToken(ctx, pre))
	got, err := s.RefreshToken(ctx, pre.Hash, t0)
	must(t, err)
	if !got.RotatedAt.IsZero() {
		t.Fatal("PutRefreshToken kept the caller's RotatedAt")
	}
}

func concurrentRotationWithoutGraceHasOneWinner(t *testing.T, s store.Store) {
	mustCreate(t, s, grant("g1", "tid:alice"))
	t1 := refresh("g1", 1)
	must(t, s.PutRefreshToken(ctx, t1))
	const n = 16
	errs := make([]error, n)
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := range n {
		wg.Go(func() {
			<-start
			req := rotation(t1, refresh("g1", 100+i), t0.Add(time.Minute))
			req.Grace = 0
			errs[i] = s.RotateRefreshToken(ctx, req)
		})
	}
	close(start)
	wg.Wait()
	wins := 0
	for _, err := range errs {
		switch {
		case err == nil:
			wins++
		case !errors.Is(err, store.ErrReused) && !errors.Is(err, store.ErrNotFound):
			t.Fatalf("loser got %v, want ErrReused (or ErrNotFound once the grant is gone)", err)
		}
	}
	if wins != 1 {
		t.Fatalf("%d rotations of one token succeeded, want exactly 1", wins)
	}
}

func client(id string) store.Client {
	return store.Client{ID: id, Metadata: []byte(`{"client_name":"` + id + `"}`), CreatedAt: t0, ExpiresAt: t0.Add(90 * 24 * time.Hour)}
}

func clientsEqual(a, b store.Client) bool {
	return a.ID == b.ID && bytes.Equal(a.Metadata, b.Metadata) && a.CreatedAt.Equal(b.CreatedAt) && a.UsedAt.Equal(b.UsedAt) && a.ExpiresAt.Equal(b.ExpiresAt)
}

func clientRoundTripsAsACopy(t *testing.T, s store.Store) {
	c := client("dcr-a")
	must(t, s.CreateClient(ctx, c, 0))
	c.Metadata[0] = 'X' // changing the caller's slice changes nothing stored
	got, err := s.Client(ctx, "dcr-a")
	must(t, err)
	if !clientsEqual(got, client("dcr-a")) || !got.UsedAt.IsZero() {
		t.Fatalf("client = %+v, want %+v", got, client("dcr-a"))
	}
	got.Metadata[0] = 'Y'
	if again, _ := s.Client(ctx, "dcr-a"); !clientsEqual(again, client("dcr-a")) {
		t.Fatalf("a returned slice changed the stored client: %+v", again)
	}
	_, err = s.Client(ctx, "nobody")
	wantErr(t, "unknown client", err, store.ErrNotFound)
}

func clientIDsAreUniqueAndIncompleteClientsInvalid(t *testing.T, s store.Store) {
	must(t, s.CreateClient(ctx, client("dcr-a"), 0))
	wantErr(t, "duplicate ID", s.CreateClient(ctx, client("dcr-a"), 0), store.ErrExists)
	for name, c := range map[string]store.Client{
		"no ID":                  {Metadata: []byte("{}"), CreatedAt: t0, ExpiresAt: t0.Add(time.Hour)},
		"no metadata":            {ID: "x", CreatedAt: t0, ExpiresAt: t0.Add(time.Hour)},
		"already used":           {ID: "x", Metadata: []byte("{}"), CreatedAt: t0, UsedAt: t0, ExpiresAt: t0.Add(time.Hour)},
		"expires at creation":    {ID: "x", Metadata: []byte("{}"), CreatedAt: t0, ExpiresAt: t0},
		"expires before created": {ID: "x", Metadata: []byte("{}"), CreatedAt: t0, ExpiresAt: t0.Add(-time.Second)},
	} {
		wantErr(t, name, s.CreateClient(ctx, c, 0), store.ErrInvalid)
	}
}

// Only clients that are still live at the new client's CreatedAt count towards the cap.
func createClientEnforcesTheCapOnLiveClients(t *testing.T, s store.Store) {
	old := client("dcr-old")
	old.CreatedAt, old.ExpiresAt = t0.Add(-2*time.Hour), t0 // expired exactly at t0: not live
	must(t, s.CreateClient(ctx, old, 2))
	must(t, s.CreateClient(ctx, client("dcr-a"), 2))
	must(t, s.CreateClient(ctx, client("dcr-b"), 2))
	wantErr(t, "a third live client", s.CreateClient(ctx, client("dcr-c"), 2), store.ErrFull)
	must(t, s.CreateClient(ctx, client("dcr-d"), 0)) // max 0: no cap
}

func concurrentCreateClientNeverExceedsTheCap(t *testing.T, s store.Store) {
	const n, max = 32, 5
	errs := make([]error, n)
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := range n {
		wg.Go(func() {
			<-start
			errs[i] = s.CreateClient(ctx, client(fmt.Sprintf("dcr-%d", i)), max)
		})
	}
	close(start)
	wg.Wait()
	ok := 0
	for _, err := range errs {
		switch {
		case err == nil:
			ok++
		case !errors.Is(err, store.ErrFull):
			t.Fatalf("a registration failed with %v, want ErrFull", err)
		}
	}
	if ok != max {
		t.Fatalf("%d registrations stored, want exactly %d", ok, max)
	}
}

func useClientMarksUseAndExtendsWithoutShortening(t *testing.T, s store.Store) {
	c := client("dcr-a")
	must(t, s.CreateClient(ctx, c, 0))
	day := 24 * time.Hour
	used := t0.Add(time.Hour)
	// The first use is recorded even when the expiry does not move.
	must(t, s.UseClient(ctx, "dcr-a", used, c.ExpiresAt.Add(time.Hour), day))
	got, _ := s.Client(ctx, "dcr-a")
	if !got.UsedAt.Equal(used) || !got.ExpiresAt.Equal(c.ExpiresAt) {
		t.Fatalf("after the first use: used %v, expires %v; want %v, %v (an hour is less than the minimum extension)", got.UsedAt, got.ExpiresAt, used, c.ExpiresAt)
	}
	// A later use keeps the first UsedAt and extends by at least the minimum.
	must(t, s.UseClient(ctx, "dcr-a", used.Add(day), c.ExpiresAt.Add(day), day))
	got, _ = s.Client(ctx, "dcr-a")
	if !got.UsedAt.Equal(used) || !got.ExpiresAt.Equal(c.ExpiresAt.Add(day)) {
		t.Fatalf("after a day: used %v, expires %v; want %v, %v", got.UsedAt, got.ExpiresAt, used, c.ExpiresAt.Add(day))
	}
	// It never shortens.
	must(t, s.UseClient(ctx, "dcr-a", used.Add(2*day), t0.Add(time.Hour), 0))
	if again, _ := s.Client(ctx, "dcr-a"); !again.ExpiresAt.Equal(c.ExpiresAt.Add(day)) {
		t.Fatalf("expiry shortened to %v", again.ExpiresAt)
	}
	wantErr(t, "unknown client", s.UseClient(ctx, "nobody", t0, t0, 0), store.ErrNotFound)
}

func collectRemovesExpiredClientsAndClientsUnusedForTheirFirstDay(t *testing.T, s store.Store) {
	now := t0.Add(store.UnusedClientLifetime)
	fresh := client("dcr-fresh")
	fresh.CreatedAt = now.Add(-time.Second) // never used, but younger than the limit
	expired := client("dcr-expired")
	expired.ExpiresAt = now
	for _, c := range []store.Client{client("dcr-unused"), client("dcr-used"), fresh, expired} {
		must(t, s.CreateClient(ctx, c, 0))
	}
	must(t, s.UseClient(ctx, "dcr-used", t0.Add(time.Minute), t0, 0))
	must(t, s.UseClient(ctx, "dcr-expired", t0.Add(time.Minute), t0, 0))
	must(t, s.Collect(ctx, now))
	for id, kept := range map[string]bool{"dcr-unused": false, "dcr-expired": false, "dcr-used": true, "dcr-fresh": true} {
		_, err := s.Client(ctx, id)
		if (err == nil) != kept {
			t.Errorf("%s: err %v, want kept %v", id, err, kept)
		}
	}
}
