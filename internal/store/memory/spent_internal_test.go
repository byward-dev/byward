package memory

import (
	"context"
	"crypto/sha256"
	"testing"
	"time"
)

// Collect drops spent logins and spent client assertions once they expire, so neither record
// outgrows a lifetime's worth.
func TestCollectDropsExpiredSpentRecords(t *testing.T) {
	for _, tc := range []struct {
		name  string
		spend func(*Store, [sha256.Size]byte, time.Time, time.Time) error
		rows  func(*Store) int
	}{
		{"logins", func(s *Store, h [sha256.Size]byte, now, exp time.Time) error {
			return s.SpendLogin(context.Background(), h, now, exp)
		}, func(s *Store) int { return len(s.logins) }},
		{"client assertions", func(s *Store, h [sha256.Size]byte, now, exp time.Time) error {
			return s.SpendAssertion(context.Background(), h, now, exp)
		}, func(s *Store) int { return len(s.asserts) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, now := New(), time.Now()
			if err := tc.spend(s, sha256.Sum256([]byte("x")), now, now.Add(time.Minute)); err != nil {
				t.Fatal(err)
			}
			if err := s.Collect(context.Background(), now.Add(30*time.Second)); err != nil || tc.rows(s) != 1 {
				t.Fatalf("before expiry: %d spent, %v; want 1", tc.rows(s), err)
			}
			if err := s.Collect(context.Background(), now.Add(time.Minute)); err != nil || tc.rows(s) != 0 {
				t.Fatalf("at expiry: %d spent, %v; want 0", tc.rows(s), err)
			}
		})
	}
}
