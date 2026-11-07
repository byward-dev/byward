package memstore

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/byward-dev/byward/internal/store"
)

// Fail switches one method's failure on and off; Down fails every method; the embedded store
// bypasses both; GrantIDs records what was created.
func TestFailuresAreSwitchedPerMethod(t *testing.T) {
	ctx, boom := context.Background(), errors.New("boom")
	s := New()
	now := time.Now()
	g := store.Grant{ID: "g1", ClientID: "c", Subject: "s", CreatedAt: now, ExpiresAt: now.Add(time.Hour)}
	if _, err := s.CreateGrant(ctx, g); err != nil {
		t.Fatal(err)
	}
	s.Fail(boom, "Grant")
	if _, err := s.Grant(ctx, "g1"); !errors.Is(err, boom) {
		t.Fatalf("Grant with a failure set: %v, want boom", err)
	}
	if _, err := s.Store.Grant(ctx, "g1"); err != nil {
		t.Fatalf("the embedded store: %v, want no failure", err)
	}
	s.Fail(nil, "Grant")
	if _, err := s.Grant(ctx, "g1"); err != nil {
		t.Fatalf("Grant after clearing: %v", err)
	}
	s.Down(boom)
	if _, err := s.Consent(ctx, store.ConsentKey{}); !errors.Is(err, boom) {
		t.Fatalf("Consent while down: %v, want boom", err)
	}
	s.Down(nil)
	if ids := s.GrantIDs(); len(ids) != 1 || ids[0] != "g1" {
		t.Fatalf("GrantIDs %v, want [g1]", ids)
	}
}
