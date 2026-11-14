//go:build integration

package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/byward-dev/byward/internal/broker"
	"github.com/byward-dev/byward/internal/config"
	"github.com/byward-dev/byward/internal/logging"
	"github.com/byward-dev/byward/internal/testutil/fakeupstream"
	"github.com/byward-dev/byward/internal/testutil/pgtest"
)

// Two replicas in one process share a PostgreSQL store over verify-full TLS (ADR-0007, #227 D5):
// each with its own background work and the same keys. What one does, the other honours within a
// deny-list sync; a client assertion is single use across them; and a restore of the database is
// found while they run, with one new epoch between them.
func TestIntegrationTwoReplicasShareThePostgreSQLStore(t *testing.T) {
	pgtest.Require(t)
	img := pgtest.Images[len(pgtest.Images)-1] // the adapter's own suite covers each version
	srv := pgtest.Start(t, img.Image)
	up := fakeupstream.New()
	t.Cleanup(up.Close)
	pgEnv := func(t *testing.T, db string) []string { return postgresEnv(t, srv.DSN(db), up.URL+"/mcp") }
	// pair starts two replicas on a new database and returns its name too.
	pair := func(t *testing.T) (cfg *config.Config, db string, a, b *replica) {
		t.Helper()
		db = srv.NewDatabase(t)
		cfg, _, err := config.Load(nil, pgEnv(t, db), os.ReadFile)
		if err != nil {
			t.Fatal(err)
		}
		a, b = startReplica(t, cfg), startReplica(t, cfg)
		// The startup log names the database and its TLS, never the DSN's password nor the SQLite paths
		// it does not use.
		for _, r := range []*replica{a, b} {
			if logs := r.logs.String(); !strings.Contains(logs, "tls=verify-full") || strings.Contains(logs, srv.Password) ||
				strings.Contains(logs, "BYWARD_STORE_DIR") || strings.Contains(logs, "BYWARD_STORE_COUNTER_FILE") {
				t.Fatalf("startup log without the database's TLS, or with the password or a SQLite path:\n%s", logs)
			}
		}
		return cfg, db, a, b
	}

	t.Run("a grant revoked on one replica is refused on the other", func(t *testing.T) {
		_, _, a, b := pair(t)
		rt := seedSignedInUser(t, a.wired, "g1", time.Now())
		code, body := postRefresh(t, b.s, rt) // signed in on A, refreshed on B
		access, _ := body["access_token"].(string)
		if code != http.StatusOK || access == "" {
			t.Fatalf("refresh on B: %d %v", code, body)
		}
		if code := mcpPing(a.s, access); code != http.StatusOK {
			t.Fatalf("A with the token B issued: %d, want 200", code)
		}
		if err := b.wired.Store.RevokeGrant(context.Background(), "g1", time.Now()); err != nil {
			t.Fatal(err)
		}
		eventually(t, "A refuses the revoked grant's token", func() bool { return mcpPing(a.s, access) == http.StatusUnauthorized })
	})

	t.Run("revoke-all through the operator command reaches every replica", func(t *testing.T) {
		cfg, _, a, b := pair(t)
		rt := seedSignedInUser(t, b.wired, "g2", time.Now())
		code, body := postRefresh(t, a.s, rt)
		access, _ := body["access_token"].(string)
		if code != http.StatusOK || mcpPing(b.s, access) != http.StatusOK {
			t.Fatalf("before revoke-all: refresh %d %v", code, body)
		}
		if err := RevokeAll(context.Background(), cfg, discard); err != nil {
			t.Fatal(err)
		}
		eventually(t, "B refuses every token", func() bool { return mcpPing(b.s, access) == http.StatusUnauthorized })
	})

	t.Run("store new-epoch refuses older refresh tokens on every replica, audited once", func(t *testing.T) {
		cfg, db, a, b := pair(t)
		rt := seedSignedInUser(t, a.wired, "g3", time.Now())
		var logs syncBuffer
		epoch, err := NewEpoch(context.Background(), cfg, logging.New(&logs, "json"))
		if err != nil || epoch != 2 {
			t.Fatalf("NewEpoch = %d, %v; want epoch 2", epoch, err)
		}
		if out := logs.String(); strings.Count(out, `"event":"store_restored"`) != 1 || !strings.Contains(out, `"reason":"operator new-epoch"`) ||
			!restoreLineNames(out, "dbname="+db) || strings.Contains(out, srv.Password) {
			t.Fatalf("want one store_restored record with the operator's reason, a warning naming the database, and no password:\n%s", out)
		}
		for _, r := range []*replica{a, b} {
			if code, body := postRefresh(t, r.s, rt); code != http.StatusBadRequest || body["error"] != "invalid_grant" {
				t.Fatalf("a refresh token from before new-epoch: %d %v, want 400 invalid_grant", code, body)
			}
		}
	})

	t.Run("a client assertion accepted by one replica is a replay on the other", func(t *testing.T) {
		replayIsRefusedAcrossReplicas(t, pgEnv(t, srv.NewDatabase(t)))
	})

	t.Run("a restore is found while the replicas run, with one new epoch", func(t *testing.T) {
		_, db, a, b := pair(t)
		ua := seedSignedInUser(t, a.wired, "ua", time.Now())
		ub := seedSignedInUser(t, b.wired, "ub", time.Now())
		dump := srv.Exec(t, nil, "pg_dump", "--format=custom", "--dbname="+db)
		// Writes after the dump on both replicas, so each one's mark is past the copy.
		for _, r := range []struct {
			on *replica
			rt string
		}{{a, ua}, {b, ub}} {
			if code, body := postRefresh(t, r.on.s, r.rt); code != http.StatusOK {
				t.Fatalf("refresh after the dump: %d %v", code, body)
			}
		}
		srv.Exec(t, dump, "pg_restore", "--clean", "--if-exists", "--dbname="+db)

		restored := func() int { return strings.Count(a.logs.String()+b.logs.String(), `"event":"store_restored"`) }
		// That one replica starts the epoch and the other adopts it is the adapter's own test
		// (ARestoreStartsOneEpochAcrossReplicas); here, the wired replicas find the restore and record it.
		eventually(t, "a replica records the restore", func() bool { return restored() > 0 })
		if n := restored(); n != 1 || !restoreLineNames(a.logs.String()+b.logs.String(), "dbname="+db) {
			t.Fatalf("store_restored records: %d, want 1 between the replicas with a warning naming the database\nA: %s\nB: %s", n, a.logs, b.logs)
		}
		// The dump holds ua and ub as current tokens: only the new epoch refuses them, on both replicas.
		for _, r := range []*replica{a, b} {
			for _, rt := range []string{ua, ub} {
				if code, body := postRefresh(t, r.s, rt); code != http.StatusBadRequest || body["error"] != "invalid_grant" {
					t.Fatalf("a refresh token from the copy: %d %v, want 400 invalid_grant", code, body)
				}
			}
		}
	})
}

// replica is one wired server with its background work running.
type replica struct {
	s     *Servers
	wired *broker.Config
	logs  *syncBuffer
}

// startReplica wires a server on cfg, as one replica starts, and runs its background work until the
// test ends; its store closes after that.
func startReplica(t *testing.T, cfg *config.Config) *replica {
	t.Helper()
	r := &replica{wired: new(broker.Config), logs: new(syncBuffer)}
	orig := newBroker // swapped for this New only: a second replica must not record into the first's
	newBroker = func(c broker.Config) (*broker.Broker, error) {
		c.IdP = refreshingIdP{c.IdP}
		*r.wired = c
		return orig(c)
	}
	s, err := New(cfg, logging.New(r.logs, "json"))
	newBroker = orig
	if err != nil {
		t.Fatal(err)
	}
	r.s = s
	ctx, stop := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); s.background(ctx) }()
	t.Cleanup(func() {
		stop()
		<-done
		if err := s.closeStore(); err != nil {
			t.Error(err)
		}
	})
	return r
}

// mcpPing sends an MCP ping with the access token to the replica and returns the status.
func mcpPing(s *Servers, access string) int {
	r := httptest.NewRequest(http.MethodPost, "https://mcp.example.com/mcp", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"ping"}`))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Accept", "application/json, text/event-stream")
	r.Header.Set("Authorization", "Bearer "+access)
	w := httptest.NewRecorder()
	s.Public.Handler.ServeHTTP(w, r)
	return w.Code
}

// eventually polls cond until it holds, or fails after three restore checks and deny-list syncs.
func eventually(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * restoreCheckEvery)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out: %s", what)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// restoreLineNames reports whether the restore warning in logs (`"reason":"store_restore"`) has want
// in it: the startup line names the database too, so the whole log would not tell.
func restoreLineNames(logs, want string) bool {
	for line := range strings.Lines(logs) {
		if strings.Contains(line, `"reason":"store_restore"`) && strings.Contains(line, want) {
			return true
		}
	}
	return false
}
