package server

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/byward-dev/byward/internal/audit"
	"github.com/byward-dev/byward/internal/config"
	"github.com/byward-dev/byward/internal/denylist"
	"github.com/byward-dev/byward/internal/store"
	"github.com/byward-dev/byward/internal/store/sqlite"
)

// The wired server removes expired store rows at startup and while it runs (ADR-0007 §1): a grant
// that expires between two collections is gone one interval later; a live grant stays. Fake time
// in the bubble.
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
		for id, expires := range map[string]time.Time{"expired": now.Add(-time.Minute), "expiring": now.Add(collectEvery / 2), "live": now.Add(time.Hour)} {
			g := store.Grant{ID: id, ClientID: "test-app", Subject: "tid:oid", Issuer: "https://idp.example/v2.0",
				Resource: cfg.PublicURL.String(), Scopes: []string{"mcp"}, CreatedAt: now.Add(-time.Hour), ExpiresAt: expires}
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
		if _, err := st.Grant(ctx, "expired"); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("expired grant at startup: %v, want ErrNotFound (collection runs at startup)", err)
		}
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

// flakyCollector fails its first Collect, then succeeds; release, when set, holds every Collect
// until it is closed, and entered reports each call.
type flakyCollector struct {
	calls   atomic.Int32
	entered chan struct{}
	release chan struct{}
}

func (c *flakyCollector) Collect(ctx context.Context, _ time.Time) error {
	n := c.calls.Add(1)
	if c.entered != nil {
		c.entered <- struct{}{}
	}
	if c.release != nil {
		<-c.release
	}
	if n == 1 {
		return errors.New("disk I/O error")
	}
	return nil
}

// A failed collection is logged and retried at the next interval; stopping is not an error.
func TestAFailedCollectionIsLoggedAndRetried(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var logs syncBuffer
		c := &flakyCollector{}
		ctx, stop := context.WithCancel(context.Background())
		done := make(chan struct{})
		go func() { defer close(done); collect(ctx, c, slog.New(slog.NewTextHandler(&logs, nil))) }()
		synctest.Wait()
		if c.calls.Load() != 1 || strings.Count(logs.String(), "removing expired store rows failed") != 1 {
			t.Fatalf("after the first collection: %d calls, logs %q", c.calls.Load(), logs.String())
		}
		time.Sleep(collectEvery)
		synctest.Wait()
		if n := c.calls.Load(); n != 2 {
			t.Fatalf("calls after one interval = %d, want 2 (a failure is retried)", n)
		}
		stop()
		<-done
		if n := strings.Count(logs.String(), "level=ERROR"); n != 1 {
			t.Fatalf("%d error lines, want only the failed collection: %q", n, logs.String())
		}
	})
}

type noRevocations struct{}

func (noRevocations) Revocations(context.Context) ([]store.Revocation, error) { return nil, nil }

// The background work returns only after a collection in progress has finished, so Run never
// closes the store under it.
func TestBackgroundWorkWaitsForACollectionInProgress(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		c := &flakyCollector{entered: make(chan struct{}), release: make(chan struct{})}
		ctx, stop := context.WithCancel(context.Background())
		done := make(chan struct{})
		go func() { defer close(done); runBackground(ctx, c, denylist.New(noRevocations{}, time.Now), discard) }()
		<-c.entered
		stop()
		synctest.Wait()
		select {
		case <-done:
			t.Fatal("the background work returned while a collection was still running")
		default:
		}
		close(c.release)
		<-done
	})
}
