package server

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"maps"
	"slices"
	"strings"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/byward-dev/byward/internal/audit"
	"github.com/byward-dev/byward/internal/config"
)

// lockedBuffer is a bytes.Buffer safe for the proxy's background goroutine and the test.
type lockedBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *lockedBuffer) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

// grantRevokedRecords is every grant_revoked audit record in a JSON log, each as its fields
// without the time.
func grantRevokedRecords(t *testing.T, log string) []map[string]any {
	t.Helper()
	var out []map[string]any
	for _, line := range strings.Split(strings.TrimSpace(log), "\n") {
		if !strings.Contains(line, `"event":"grant_revoked"`) {
			continue
		}
		var rec map[string]any
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			t.Fatalf("not JSON: %s", line)
		}
		delete(rec, "time")
		out = append(out, rec)
	}
	return out
}

// #337: an operator revocation reaches the running proxy's audit stream, not only the command's
// output: once, at the proxy's next deny-list sync, as exactly the record the command wrote (the
// reason and the user key; no grant ID, no token).
func TestAnOperatorRevocationReachesTheRunningProxysAuditStream(t *testing.T) {
	for _, tc := range []struct {
		name   string
		revoke func(t *testing.T, cfg *config.Config, log *slog.Logger)
	}{
		{"revoke-user", func(t *testing.T, cfg *config.Config, log *slog.Logger) {
			if _, err := RevokeUser(context.Background(), cfg, log, aliceKey); err != nil {
				t.Fatal(err)
			}
		}},
		{"revoke-all", func(t *testing.T, cfg *config.Config, log *slog.Logger) {
			if err := RevokeAll(context.Background(), cfg, log); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				cfg, tokens := revokeEnv(t)
				proxyLog := &lockedBuffer{}
				logger := slog.New(slog.NewJSONHandler(proxyLog, nil))
				proxy, err := buildAuth(cfg, discard, Observability{Audit: audit.New(logger, nil, time.Now)})
				if err != nil {
					t.Fatal(err)
				}
				ctx, cancel := context.WithCancel(context.Background())
				done := make(chan struct{})
				go func() { defer close(done); proxy.background(ctx) }()
				defer func() { cancel(); <-done; _ = proxy.closeStore() }()

				time.Sleep(time.Second)
				var command bytes.Buffer
				tc.revoke(t, cfg, slog.New(slog.NewJSONHandler(&command, nil)))
				time.Sleep(10 * time.Second) // two deny-list syncs
				synctest.Wait()

				want := grantRevokedRecords(t, command.String())
				got := grantRevokedRecords(t, proxyLog.String())
				if len(want) != 1 || len(got) != 1 {
					t.Fatalf("the command wrote %d grant_revoked records and the proxy %d, want 1 each\ncommand: %s\nproxy: %s", len(want), len(got), command.String(), proxyLog.String())
				}
				for _, k := range []string{"msg", "level"} {
					delete(want[0], k)
					delete(got[0], k)
				}
				if !maps.Equal(want[0], got[0]) {
					t.Fatalf("the proxy recorded %v, want the command's record %v", got[0], want[0])
				}
				for k, v := range got[0] {
					if s, ok := v.(string); ok && slices.ContainsFunc(slices.Collect(maps.Values(tokens)), func(tok string) bool { return strings.Contains(s, tok) }) {
						t.Fatalf("the proxy's record carries a token in %s", k)
					}
				}
				if _, ok := got[0]["grant_id"]; ok {
					t.Fatal("the proxy's record carries a grant ID")
				}
			})
		})
	}
}
