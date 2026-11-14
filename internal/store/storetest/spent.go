package storetest

import (
	"crypto/sha256"
	"testing"
	"time"

	"github.com/byward-dev/byward/internal/store"
)

// Spent names a record of spent hashes by the SQL adapters' table for it.
type Spent string

// The two records of spent hashes.
const (
	SpentLogins     Spent = "spent_logins"
	SpentAssertions Spent = "spent_assertions"
)

// CollectDropsExpiredSpent checks that Collect drops spent logins and spent client assertions once
// they expire, so neither record outgrows a lifetime's worth. An expired one already counts as
// absent, so Run cannot see it collected: open returns a new store with rows, the adapter's own
// count of a record's rows in that store, which shows it.
func CollectDropsExpiredSpent(t *testing.T, open func(t *testing.T) (store.Store, func(Spent) int)) {
	for _, tc := range []struct {
		kind  Spent
		spend spendFunc
	}{
		{SpentLogins, store.Store.SpendLogin},
		{SpentAssertions, store.Store.SpendAssertion},
	} {
		t.Run(string(tc.kind), func(t *testing.T) {
			s, rows := open(t)
			must(t, tc.spend(s, ctx, sha256.Sum256([]byte("x")), t0, t0.Add(time.Minute)))
			must(t, s.Collect(ctx, t0.Add(30*time.Second)))
			if n := rows(tc.kind); n != 1 {
				t.Fatalf("before expiry: %d rows, want 1", n)
			}
			must(t, s.Collect(ctx, t0.Add(time.Minute)))
			if n := rows(tc.kind); n != 0 {
				t.Fatalf("at expiry: %d rows, want 0", n)
			}
		})
	}
}
