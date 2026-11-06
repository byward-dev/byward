package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"maps"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/byward-dev/byward/internal/audit"
	"github.com/byward-dev/byward/internal/broker"
	"github.com/byward-dev/byward/internal/config"
	"github.com/byward-dev/byward/internal/health"
	"github.com/byward-dev/byward/internal/resource"
	"github.com/byward-dev/byward/internal/store"
	"github.com/byward-dev/byward/internal/store/sqlite"
)

// storeEnv loads authEnv's configuration; cfg holds the store paths the server will use.
func storeEnv(t *testing.T) (env []string, cfg *config.Config) {
	t.Helper()
	env = append(authEnv(t), "BYWARD_PUBLIC_URL=https://mcp.example.com/mcp", "BYWARD_UPSTREAM_URL=http://u/mcp")
	cfg, _, err := config.Load(nil, env, os.ReadFile)
	if err != nil {
		t.Fatal(err)
	}
	return env, cfg
}

// withStore opens the store the server would use, runs fn on it and closes it again.
func withStore(t *testing.T, cfg *config.Config, fn func(*sqlite.Store)) {
	t.Helper()
	st, err := sqlite.Open(context.Background(), sqlite.Options{Dir: cfg.StoreDir, CounterFile: cfg.StoreCounterFile})
	if err != nil {
		t.Fatal(err)
	}
	fn(st)
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
}

// stop ends the background work of a and closes its store, in the order Run does.
func stop(t *testing.T, a *auth) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	a.background(ctx)
	if err := a.closeStore(); err != nil {
		t.Fatal(err)
	}
}

func grantFor(id string, at time.Time) store.Grant {
	return store.Grant{ID: id, ClientID: "test-app", Subject: "tid:oid-" + id, Issuer: "https://login.microsoftonline.com/x/v2.0",
		Resource: "https://mcp.example.com/mcp", CreatedAt: at, ExpiresAt: at.Add(time.Hour)}
}

// The server keeps its state in SQLite in BYWARD_STORE_DIR: a revocation written there
// before the server starts refuses that grant's tokens after the start.
func TestServerUsesTheSQLiteStoreInTheStateDirectory(t *testing.T) {
	env, cfg := storeEnv(t)
	now := time.Now()
	withStore(t, cfg, func(st *sqlite.Store) {
		for _, id := range []string{"revoked", "live"} {
			if _, err := st.CreateGrant(context.Background(), grantFor(id, now)); err != nil {
				t.Fatal(err)
			}
		}
		if err := st.RevokeGrant(context.Background(), "revoked", now); err != nil {
			t.Fatal(err)
		}
	})
	a, err := buildAuth(cfg, discard, Observability{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { stop(t, a) })
	if _, err := a.validator.Validate(context.Background(), sealAccess(t, cfg, env, "revoked")); err != resource.ErrInvalid {
		t.Fatalf("token of a grant revoked in the store before the start: %v, want refused", err)
	}
	if _, err := a.validator.Validate(context.Background(), sealAccess(t, cfg, env, "live")); err != nil {
		t.Fatalf("token of a live grant: %v", err)
	}
}

func TestRestoredStoreIsReportedAtStartup(t *testing.T) {
	_, cfg := storeEnv(t)
	db := filepath.Join(cfg.StoreDir, "byward.db")
	withStore(t, cfg, func(st *sqlite.Store) {
		if _, err := st.CreateGrant(context.Background(), grantFor("before-backup", time.Now())); err != nil {
			t.Fatal(err)
		}
	})
	backup, err := os.ReadFile(db) //nolint:gosec // G304: the test's own temporary database
	if err != nil {
		t.Fatal(err)
	}
	withStore(t, cfg, func(st *sqlite.Store) {
		if _, err := st.CreateGrant(context.Background(), grantFor("after-backup", time.Now())); err != nil {
			t.Fatal(err)
		}
	})
	for _, side := range []string{"-wal", "-shm"} {
		_ = os.Remove(db + side)
	}
	if err := os.WriteFile(db, backup, 0o600); err != nil { //nolint:gosec // G703: the test's own temporary database; restore by file copy, counter untouched
		t.Fatal(err)
	}

	var logs, auditLog bytes.Buffer
	a, err := buildAuth(cfg, slog.New(slog.NewJSONHandler(&logs, nil)),
		Observability{Audit: audit.New(slog.New(slog.NewJSONHandler(&auditLog, nil)), nil, time.Now)})
	if err != nil {
		t.Fatal(err)
	}
	stop(t, a)
	if out := logs.String(); !strings.Contains(out, `"reason":"store_restore"`) || !strings.Contains(out, `"epoch":2`) {
		t.Fatalf("startup log %s: want a store_restore warning with epoch 2", out)
	}
	// ADR-0021 §3: the restore is on the audit stream too, which operators ship off the host.
	type record struct {
		Event, Outcome, Reason string
		Epoch                  int64
	}
	var restored []record
	for _, line := range strings.Split(strings.TrimSpace(auditLog.String()), "\n") {
		var r record
		if json.Unmarshal([]byte(line), &r) == nil && r.Event == "store_restored" {
			restored = append(restored, r)
		}
	}
	want := record{Event: "store_restored", Outcome: "success", Reason: "restored from an older copy", Epoch: 2}
	if len(restored) != 1 || restored[0] != want {
		t.Fatalf("audit stream %s: want exactly %+v", auditLog.String(), want)
	}
}

func TestMissingCounterFileIsReportedAtStartup(t *testing.T) {
	_, cfg := storeEnv(t)
	withStore(t, cfg, func(st *sqlite.Store) {
		if _, err := st.CreateGrant(context.Background(), grantFor("g", time.Now())); err != nil {
			t.Fatal(err)
		}
	})
	if err := os.Remove(cfg.StoreCounterFile); err != nil {
		t.Fatal(err)
	}
	var logs bytes.Buffer
	a, err := buildAuth(cfg, slog.New(slog.NewJSONHandler(&logs, nil)), Observability{})
	if err != nil {
		t.Fatal(err)
	}
	stop(t, a)
	if out := logs.String(); !strings.Contains(out, `"reason":"store_counter_missing"`) {
		t.Fatalf("startup log %s: want a store_counter_missing warning", out)
	}
}

func TestUnusableStateDirectoryStopsStartupNamingTheSetting(t *testing.T) {
	env, _ := storeEnv(t)
	notADir := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(notADir, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, _, err := config.Load(nil, append(env, "BYWARD_STORE_DIR="+notADir), os.ReadFile)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := buildAuth(cfg, discard, Observability{}); err == nil || !strings.Contains(err.Error(), "BYWARD_STORE_DIR") {
		t.Fatalf("err = %v, want one naming BYWARD_STORE_DIR", err)
	}
}

func TestRefreshGraceSettingReachesTheBroker(t *testing.T) {
	env, _ := storeEnv(t)
	cfg, _, err := config.Load(nil, append(env, "BYWARD_REFRESH_GRACE=5s"), os.ReadFile)
	if err != nil {
		t.Fatal(err)
	}
	var got broker.Config
	orig := newBroker
	newBroker = func(c broker.Config) (*broker.Broker, error) { got = c; return orig(c) }
	t.Cleanup(func() { newBroker = orig })
	a, err := buildAuth(cfg, discard, Observability{})
	if err != nil {
		t.Fatal(err)
	}
	stop(t, a)
	if got.RefreshGrace != 5*time.Second {
		t.Fatalf("broker refresh grace = %v, want the configured 5s", got.RefreshGrace)
	}
}

// A startup that fails after the store opened closes it again. SQLite deletes the -wal file when its
// last connection closes (sqlite.org/wal.html), so a leftover -wal file means the store leaked.
func TestFailedStartupAfterTheStoreOpenedClosesIt(t *testing.T) {
	_, cfg := storeEnv(t)
	orig := newBroker
	newBroker = func(broker.Config) (*broker.Broker, error) { return nil, errors.New("broker refused") }
	t.Cleanup(func() { newBroker = orig })
	if _, err := buildAuth(cfg, discard, Observability{}); err == nil {
		t.Fatal("buildAuth succeeded with a failing broker")
	}
	if _, err := os.Stat(filepath.Join(cfg.StoreDir, "byward.db")); err != nil {
		t.Fatalf("the store was never opened, so this test proves nothing: %v", err)
	}
	if _, err := os.Stat(filepath.Join(cfg.StoreDir, "byward.db-wal")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("the store's -wal file is still there (%v): the store was left open", err)
	}
}

// Readiness covers the store (ADR-0007 §7, ADR-0021 §10): /readyz turns 503 when the database
// stops answering, here because it was closed.
func TestReadinessFailsWhenTheStoreIsUnavailable(t *testing.T) {
	_, cfg := storeEnv(t)
	a, err := buildAuth(cfg, discard, Observability{})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	a.background(ctx)
	mux := http.NewServeMux()
	health.New(discard, a.checks...).Register(mux)
	ready := func() (int, string) {
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/readyz", nil))
		return rec.Code, rec.Body.String()
	}
	if code, body := ready(); code != http.StatusOK {
		t.Fatalf("with the store open: %d %s", code, body)
	}
	if err := a.closeStore(); err != nil {
		t.Fatal(err)
	}
	if code, body := ready(); code != http.StatusServiceUnavailable || !strings.Contains(body, `"store"`) || strings.Contains(body, `"store":"ok"`) {
		t.Fatalf("with the store closed: %d %s, want 503 naming the store", code, body)
	}
}

// ADR-0007 §6: the absolute paths in use are logged at startup, defaults resolved.
func TestStartupLogsTheResolvedPaths(t *testing.T) {
	_, cfg := storeEnv(t)
	var logs bytes.Buffer
	a, err := buildAuth(cfg, slog.New(slog.NewJSONHandler(&logs, nil)), Observability{})
	if err != nil {
		t.Fatal(err)
	}
	stop(t, a)
	got := map[string]string{}
	for _, line := range strings.Split(strings.TrimSpace(logs.String()), "\n") {
		var rec struct{ Msg, Setting, Value string }
		if json.Unmarshal([]byte(line), &rec) == nil && rec.Msg == "path" {
			got[rec.Setting] = rec.Value
		}
	}
	want := map[string]string{"BYWARD_DATA_DIR": cfg.DataDir, "BYWARD_KEYS_DIR": cfg.KeysDir,
		"BYWARD_STATIC_CLIENTS_FILE": cfg.StaticClientsFile, "BYWARD_STORE_DIR": cfg.StoreDir,
		"BYWARD_STORE_COUNTER_FILE": cfg.StoreCounterFile}
	if !maps.Equal(got, want) {
		t.Fatalf("logged paths %v, want %v", got, want)
	}
}

// The server New builds closes its store when Run returns (the -wal file goes with the last
// connection, sqlite.org/wal.html), so a stopped proxy leaves a clean database behind.
func TestServerClosesTheStoreWhenRunReturns(t *testing.T) {
	env, _ := storeEnv(t)
	cfg, _, err := config.Load(nil, append(env, "BYWARD_LISTEN=127.0.0.1:0", "BYWARD_INTERNAL_LISTEN="), os.ReadFile)
	if err != nil {
		t.Fatal(err)
	}
	s, err := New(cfg, discard)
	if err != nil {
		t.Fatal(err)
	}
	wal := filepath.Join(cfg.StoreDir, "byward.db-wal")
	if _, err := os.Stat(wal); err != nil {
		t.Fatalf("the store is not open after New, so this test proves nothing: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := Run(ctx, s, discard); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(wal); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("the -wal file is still there after Run returned (%v): the store was left open", err)
	}
}
