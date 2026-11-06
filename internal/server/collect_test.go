package server

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"testing"
	"testing/synctest"
	"time"

	"github.com/byward-dev/byward/internal/audit"
	"github.com/byward-dev/byward/internal/config"
	"github.com/byward-dev/byward/internal/store"
	"github.com/byward-dev/byward/internal/store/sqlite"
)

// The wired server removes expired store rows while it runs (ADR-0007 §1): a grant that expires
// between two collections is gone one interval later; a live grant stays. Fake time in the bubble.
func TestTheServerRemovesExpiredRowsWhileItRuns(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var st *sqlite.Store
		orig := wireStore
		t.Cleanup(func() { wireStore = orig })
		wireStore = func(cfg *config.Config, log *slog.Logger, rec *audit.Log) (*sqlite.Store, error) {
			s, err := orig(cfg, log, rec)
			st = s
			return s, err
		}
		cfg, _, err := config.Load(nil, append(authEnv(t), "BYWARD_PUBLIC_URL=https://mcp.example.com/mcp", "BYWARD_UPSTREAM_URL=http://u/mcp"), os.ReadFile)
		if err != nil {
			t.Fatal(err)
		}
		a, err := buildAuth(cfg, discard, Observability{})
		if err != nil {
			t.Fatal(err)
		}
		ctx := context.Background()
		now := time.Now()
		for id, expires := range map[string]time.Time{"expiring": now.Add(collectEvery / 2), "live": now.Add(time.Hour)} {
			g := store.Grant{ID: id, ClientID: "test-app", Subject: "tid:oid", Issuer: "https://idp.example/v2.0",
				Resource: cfg.PublicURL.String(), Scopes: []string{"mcp"}, CreatedAt: now, ExpiresAt: expires}
			if _, err := st.CreateGrant(ctx, g); err != nil {
				t.Fatal(err)
			}
		}

		bg, stop := context.WithCancel(ctx)
		done := make(chan struct{})
		go func() { defer close(done); a.background(bg) }()
		t.Cleanup(func() { // inside the bubble, so a failed check still ends the background work
			stop()
			<-done
			if err := a.closeStore(); err != nil {
				t.Error(err)
			}
		})
		synctest.Wait()
		if _, err := st.Grant(ctx, "expiring"); err != nil {
			t.Fatalf("a grant that has not expired yet was collected: %v", err)
		}
		time.Sleep(collectEvery)
		synctest.Wait()
		if _, err := st.Grant(ctx, "expiring"); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("expired grant one interval later: %v, want ErrNotFound", err)
		}
		if _, err := st.Grant(ctx, "live"); err != nil {
			t.Fatalf("live grant: %v", err)
		}
	})
}
