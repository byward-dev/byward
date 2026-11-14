package server

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"github.com/byward-dev/byward/internal/audit"
	"github.com/byward-dev/byward/internal/config"
)

// check is one scripted CheckRestore answer.
type check struct {
	restored bool
	epoch    int64
	err      error
}

// scriptedChecks answers CheckRestore from a script, then with its last entry.
type scriptedChecks struct{ script []check }

func (s *scriptedChecks) CheckRestore(context.Context) (bool, int64, error) {
	next := s.script[0]
	if len(s.script) > 1 {
		s.script = s.script[1:]
	}
	return next.restored, next.epoch, next.err
}

// A restore found while running is logged and audited once, by the replica that started the epoch,
// naming the store; an epoch adopted from another replica is not; a failing check is logged once per
// run of failures, not every five seconds. Fake time in the bubble.
func TestARestoreFoundWhileRunningIsAuditedOnceAndAFailingCheckIsLoggedOncePerRun(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var logs syncBuffer
		log := slog.New(slog.NewJSONHandler(&logs, nil))
		down := errors.New("store down")
		// Failures, epoch 1, epoch 2 started here, epoch 3 adopted from another replica, a failure.
		rc := &scriptedChecks{script: []check{{err: down}, {err: down}, {err: down}, {epoch: 1}, {restored: true, epoch: 2}, {epoch: 2},
			{epoch: 3}, {err: down}, {epoch: 3}}}
		ctx, stop := context.WithCancel(context.Background())
		done := make(chan struct{})
		go func() {
			defer close(done)
			watchRestore(ctx, rc, log, audit.New(log, nil, time.Now), "BYWARD_STORE_POSTGRES_DSN_FILE", "host=db.example")
		}()
		time.Sleep(10*restoreCheckEvery + time.Second)
		stop()
		<-done
		out := logs.String()
		if n := strings.Count(out, "checking the store for a restore failed"); n != 2 {
			t.Errorf("%d failure logs for two runs of failures, want 2\n%s", n, out)
		}
		if n := strings.Count(out, `"event":"store_restored"`); n != 1 || !strings.Contains(out, `"epoch":2`) || strings.Contains(out, `"epoch":3`) ||
			!strings.Contains(out, "found while running") || strings.Count(out, `"reason":"store_restore"`) != 1 ||
			!strings.Contains(out, `"value":"host=db.example"`) {
			t.Errorf("want one warning naming the store and one store_restored record, both for epoch 2 only\n%s", out)
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
		{"verify-full passes with the replica reminder", "host=127.0.0.1 port=1 user=byward sslmode=verify-full", false, ""},
		{"require is refused outside development mode", "host=127.0.0.1 port=1 user=byward sslmode=require", false, "BYWARD_STORE_POSTGRES_DSN_FILE: postgres store: the DSN must use sslmode=verify-full"},
		{"plaintext passes in development mode", "host=127.0.0.1 port=1 user=byward sslmode=disable", true, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			env := postgresEnv(t, tc.dsn, "http://u/mcp")
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
		{"in development mode", []string{"--dev"}, "failed to connect"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			env := postgresEnv(t, "host=127.0.0.1 port=1 user=byward sslmode=disable connect_timeout=2", "http://u/mcp")
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
