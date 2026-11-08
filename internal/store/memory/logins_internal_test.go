package memory

import (
	"context"
	"crypto/sha256"
	"testing"
	"time"
)

// Collect drops spent logins once they expire, so the record never outgrows LoginLifetime's worth.
func TestCollectDropsExpiredSpentLogins(t *testing.T) {
	s, now := New(), time.Now()
	if err := s.SpendLogin(context.Background(), sha256.Sum256([]byte("l")), now, now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if err := s.Collect(context.Background(), now.Add(30*time.Second)); err != nil || len(s.logins) != 1 {
		t.Fatalf("before expiry: %d spent logins (%v), want 1", len(s.logins), err)
	}
	if err := s.Collect(context.Background(), now.Add(time.Minute)); err != nil || len(s.logins) != 0 {
		t.Fatalf("at expiry: %d spent logins (%v), want 0", len(s.logins), err)
	}
}
