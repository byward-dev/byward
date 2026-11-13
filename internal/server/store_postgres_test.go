package server

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"github.com/byward-dev/byward/internal/audit"
	"github.com/byward-dev/byward/internal/config"
	"github.com/byward-dev/byward/internal/store/postgres"
)

// scriptedChecks answers CheckRestore from a script, then with the last entry.
type scriptedChecks struct{ script []error }

// errRestoredMark in the script stands for a check that starts a new epoch.
var errRestoredMark = errors.New("restored")

func (s *scriptedChecks) CheckRestore(context.Context) (postgres.Restore, error) {
	next := s.script[0]
	if len(s.script) > 1 {
		s.script = s.script[1:]
	}
	switch next {
	case nil:
		return postgres.Restore{Epoch: 1}, nil
	case errRestoredMark:
		return postgres.Restore{Restored: true, Epoch: 2}, nil
	}
	return postgres.Restore{}, next
}

// A restore found while running is logged and audited once, by the replica that started the epoch;
// a failing check is logged once per run of failures, not every five seconds. Fake time in the
// bubble.
func TestARestoreFoundWhileRunningIsAuditedOnceAndFailuresAreNotRepeated(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var logs syncBuffer
		log := slog.New(slog.NewJSONHandler(&logs, nil))
		down := errors.New("store down")
		rc := &scriptedChecks{script: []error{down, down, down, nil, errRestoredMark, nil, down, nil}}
		ctx, stop := context.WithCancel(context.Background())
		done := make(chan struct{})
		go func() { defer close(done); watchRestore(ctx, rc, log, audit.New(log, nil, time.Now)) }()
		time.Sleep(10*restoreCheckEvery + time.Second)
		stop()
		<-done
		out := logs.String()
		if n := strings.Count(out, "checking the store for a restore failed"); n != 2 {
			t.Errorf("%d failure logs for two runs of failures, want 2\n%s", n, out)
		}
		if n := strings.Count(out, `"event":"store_restored"`); n != 1 || !strings.Contains(out, `"epoch":2`) ||
			!strings.Contains(out, "found while running") || strings.Count(out, `"reason":"store_restore"`) != 1 {
			t.Errorf("want one warning and one store_restored record for epoch 2\n%s", out)
		}
	})
}

// check --offline with the PostgreSQL store parses the DSN as startup would, without connecting:
// less than verify-full is refused outside development mode, and a good DSN brings the replica
// reminder instead of the SQLite path checks.
func TestCheckOfflineChecksThePostgreSQLDSNWithoutConnecting(t *testing.T) {
	for _, tc := range []struct {
		name, dsn string
		dev       bool
		inErr     string
	}{
		{"verify-full", "host=127.0.0.1 port=1 user=byward sslmode=verify-full", false, ""},
		{"require", "host=127.0.0.1 port=1 user=byward sslmode=require", false, "BYWARD_STORE_POSTGRES_DSN_FILE: postgres store: the DSN must use sslmode=verify-full"},
		{"plaintext in development mode", "host=127.0.0.1 port=1 user=byward sslmode=disable", true, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dsn := filepath.Join(t.TempDir(), "dsn")
			if err := os.WriteFile(dsn, []byte(tc.dsn), 0o600); err != nil {
				t.Fatal(err)
			}
			var env []string
			for _, kv := range authEnv(t) {
				if !strings.HasPrefix(kv, "BYWARD_STORE_DIR=") {
					env = append(env, kv)
				}
			}
			env = append(env, "BYWARD_STORE_POSTGRES_DSN_FILE="+dsn, "BYWARD_PUBLIC_URL=https://mcp.example.com/mcp", "BYWARD_UPSTREAM_URL=http://u/mcp")
			var args []string
			if tc.dev {
				args = []string{"--dev"}
			}
			cfg, _, err := config.Load(args, env, os.ReadFile)
			if err != nil {
				t.Fatal(err)
			}
			warnings, err := CheckOffline(cfg)
			if tc.inErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.inErr) {
					t.Fatalf("err = %v, want %q", err, tc.inErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			found := false
			for _, w := range warnings {
				found = found || w == replicaKeys
			}
			if !found {
				t.Fatalf("warnings %+v, want the replica keys reminder", warnings)
			}
		})
	}
}

// The proxy applies the verify-full rule before connecting: a plaintext DSN stops startup outside
// development mode, naming the setting; in development mode it gets as far as connecting.
func TestAPlaintextPostgreSQLStoreStopsStartupOutsideDevelopmentMode(t *testing.T) {
	for _, tc := range []struct {
		name  string
		args  []string
		inErr string
	}{
		{"outside development mode", nil, "sslmode=verify-full"},
		{"in development mode", []string{"--dev"}, "connect"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dsn := filepath.Join(t.TempDir(), "dsn")
			if err := os.WriteFile(dsn, []byte("host=127.0.0.1 port=1 user=byward sslmode=disable connect_timeout=2"), 0o600); err != nil {
				t.Fatal(err)
			}
			var env []string
			for _, kv := range authEnv(t) {
				if !strings.HasPrefix(kv, "BYWARD_STORE_DIR=") {
					env = append(env, kv)
				}
			}
			env = append(env, "BYWARD_STORE_POSTGRES_DSN_FILE="+dsn, "BYWARD_PUBLIC_URL=https://mcp.example.com/mcp", "BYWARD_UPSTREAM_URL=http://u/mcp")
			cfg, _, err := config.Load(tc.args, env, os.ReadFile)
			if err != nil {
				t.Fatal(err)
			}
			_, err = openStore(cfg, discard, nil)
			if err == nil || !strings.Contains(err.Error(), "BYWARD_STORE_POSTGRES_DSN_FILE") || !strings.Contains(err.Error(), tc.inErr) {
				t.Fatalf("err = %v, want one naming BYWARD_STORE_POSTGRES_DSN_FILE and %q", err, tc.inErr)
			}
		})
	}
}
