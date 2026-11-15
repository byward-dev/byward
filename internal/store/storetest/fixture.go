package storetest

import (
	"crypto/sha256"
	"errors"
	"reflect"
	"slices"
	"testing"
	"time"

	"github.com/byward-dev/byward/internal/store"
)

// What every migration fixture (an adapter's testdata/schema/vN.sql, ADR-0024 §11) holds and must
// still hold after migrating. The instants are 1793966400000000 µs and 4070908800000000 µs.
var (
	FixtureCreated = time.Date(2026, 11, 6, 12, 0, 0, 0, time.UTC)
	FixtureExpires = time.Date(2099, 1, 1, 0, 0, 0, 0, time.UTC)
	FixtureGrant   = store.Grant{
		ID: "fixture-grant", ClientID: "fixture-client", Subject: "tid:fixture", Issuer: "https://idp.example/v2.0",
		Resource: "https://mcp.example.com/mcp", Scopes: []string{"mcp"}, IdPTokens: []byte("sea"),
		CreatedAt: FixtureCreated, ExpiresAt: FixtureExpires, Epoch: 1,
	}
)

var (
	fixtureCode = store.PendingCode{
		GrantID: "fixture-grant", ClientID: "fixture-client", RedirectURI: "http://127.0.0.1:33418/callback",
		CodeChallenge: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM", Scopes: []string{"mcp"}, ExpiresAt: FixtureExpires,
	}
	fixtureRefresh = store.RefreshToken{
		Hash: sha256.Sum256([]byte("fixture-refresh")), GrantID: "fixture-grant", ClientID: "fixture-client",
		CreatedAt: FixtureCreated, IdleExpiresAt: FixtureExpires,
	}
	fixtureRevocations = []store.Revocation{
		{GrantID: "fixture-revoked", Before: FixtureCreated, At: FixtureCreated},
		{Subject: "tid:fixture-revoked-subject", Before: FixtureCreated, At: FixtureCreated.Add(time.Second)},
	}
	fixtureRevokeAll = store.Revocation{All: true, Before: FixtureCreated, At: FixtureCreated.Add(2 * time.Second)}
	fixtureClient    = store.Client{ID: "fixture-dcr-client", Metadata: []byte(`{"client_name":"Fixture"}`), CreatedAt: FixtureCreated,
		UsedAt: FixtureCreated.Add(time.Second), ExpiresAt: FixtureExpires}
	fixtureConsent = store.Consent{Key: store.ConsentKey{Issuer: "https://idp.example/v2.0", Subject: "tid:fixture", ClientID: "fixture-client",
		Redirect: "http://127.0.0.1/cb", Resource: "https://mcp.example.com/mcp"}, Scopes: []string{"mcp"}, ApprovedAt: FixtureCreated, ExpiresAt: FixtureExpires}
)

// FixtureSince gives, for each part of the fixture that not every version holds, the first schema
// version whose fixture holds it. Each adapter has its own schema history, so its own versions. The
// grant, its code, its refresh token and the grant and subject revocations are in every fixture.
type FixtureSince struct {
	RevokeAll      int // a cut-off for every subject
	RotatedToken   int // a refresh token rotated to the grant's, still linked to its successor
	Client         int // a registered client
	Consent        int // a remembered consent
	SpentLogin     int // a spent login
	SpentAssertion int // a spent client assertion
	MarkedConsents int // a consent marked under the lifetime rule (#363), and one re-approved after it
}

// CheckFixture checks that s, migrated from the fixture of schema version v, holds that fixture's
// data. It consumes the code and rotates tokens, so it runs once per store.
func CheckFixture(t *testing.T, s store.Store, v int, since FixtureSince) {
	t.Helper()
	if g, err := s.Grant(ctx, FixtureGrant.ID); err != nil || !reflect.DeepEqual(g, FixtureGrant) {
		t.Fatalf("grant = %+v, %v\nwant %+v", g, err, FixtureGrant)
	}
	if r, err := s.RefreshToken(ctx, fixtureRefresh.Hash, FixtureCreated); err != nil || !reflect.DeepEqual(r, fixtureRefresh) {
		t.Fatalf("refresh token = %+v, %v\nwant %+v", r, err, fixtureRefresh)
	}
	wantRevs := fixtureRevocations
	if v >= since.RevokeAll {
		wantRevs = append(slices.Clone(fixtureRevocations), fixtureRevokeAll)
	}
	if revs, err := s.Revocations(ctx); err != nil || !reflect.DeepEqual(revs, wantRevs) {
		t.Fatalf("revocations = %+v, %v\nwant %+v", revs, err, wantRevs)
	}
	if c, err := s.ConsumeCode(ctx, FixtureGrant.ID, FixtureCreated); err != nil || !reflect.DeepEqual(c, fixtureCode) {
		t.Fatalf("code = %+v, %v\nwant %+v", c, err, fixtureCode)
	}
	if v >= since.RotatedToken {
		checkRotatedFixtureToken(t, s)
	}
	if v >= since.Client {
		if c, err := s.Client(ctx, fixtureClient.ID); err != nil || !reflect.DeepEqual(c, fixtureClient) {
			t.Fatalf("client = %+v, %v\nwant %+v", c, err, fixtureClient)
		}
	}
	if v >= since.Consent {
		if c, err := s.Consent(ctx, fixtureConsent.Key); err != nil || !reflect.DeepEqual(c, fixtureConsent) {
			t.Fatalf("consent = %+v, %v\nwant %+v", c, err, fixtureConsent)
		}
	}
	if v >= since.SpentLogin { // the spent login still refuses a second use
		if err := s.SpendLogin(ctx, sha256.Sum256([]byte("fixture-login")), FixtureCreated, FixtureExpires); !errors.Is(err, store.ErrConsumed) {
			t.Fatalf("spending the fixture login: %v, want ErrConsumed", err)
		}
	}
	if v >= since.SpentAssertion { // the spent client assertion still refuses a second use
		if err := s.SpendAssertion(ctx, sha256.Sum256([]byte("fixture-assertion")), FixtureCreated, FixtureExpires); !errors.Is(err, store.ErrConsumed) {
			t.Fatalf("spending the fixture assertion: %v, want ErrConsumed", err)
		}
	}
	if v >= since.MarkedConsents {
		checkMarkedFixtureConsents(t, s)
	}
}

// checkMarkedFixtureConsents: the fixture holds a consent marked under the lifetime rule (#363),
// and one an older binary re-approved after it was marked, which no longer counts as marked.
func checkMarkedFixtureConsents(t *testing.T, s store.Store) {
	t.Helper()
	for subject, want := range map[string]bool{"tid:fixture": true, "tid:fixture-reapproved": false} {
		k := store.ConsentKey{Issuer: "https://idp.example/v2.0", Subject: subject, ClientID: "fixture-client",
			Redirect: "https://app.example/cb", Resource: "https://mcp.example.com/mcp"}
		if got, err := s.Consent(ctx, k); err != nil || got.RecordsLifetime != want || !slices.Equal(got.Scopes, []string{"mcp", "offline_access"}) {
			t.Fatalf("%s's consent = %+v, %v; want RecordsLifetime %v", subject, got, err, want)
		}
	}
}

// checkRotatedFixtureToken: the fixture holds a token rotated 1 s after creation to
// fixture-refresh. Its rotation time and its link to the successor must survive migrations: a
// retry with it inside the grace window must rotate the successor, not count as reuse.
func checkRotatedFixtureToken(t *testing.T, s store.Store) {
	t.Helper()
	oldHash := sha256.Sum256([]byte("fixture-refresh-old"))
	want := store.RefreshToken{Hash: oldHash, GrantID: FixtureGrant.ID, ClientID: "fixture-client",
		CreatedAt: FixtureCreated, IdleExpiresAt: FixtureExpires, RotatedAt: FixtureCreated.Add(time.Second)}
	if got, err := s.RefreshToken(ctx, oldHash, FixtureCreated); err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("rotated fixture token = %+v, %v\nwant %+v", got, err, want)
	}
	retry := FixtureCreated.Add(2 * time.Second)
	next := store.RefreshToken{Hash: sha256.Sum256([]byte("fixture-refresh-next")), GrantID: FixtureGrant.ID, ClientID: "fixture-client",
		CreatedAt: retry, IdleExpiresAt: FixtureExpires}
	if err := s.RotateRefreshToken(ctx, store.RotateRequest{Old: oldHash, Next: next, Now: retry, Grace: 30 * time.Second}); err != nil {
		t.Fatalf("retry with the rotated fixture token: %v (its successor link was lost)", err)
	}
	if got, err := s.RefreshToken(ctx, fixtureRefresh.Hash, retry); err != nil || !got.RotatedAt.Equal(retry) {
		t.Fatalf("the successor %+v, %v: want it rotated at %v by the retry", got, err, retry)
	}
}
