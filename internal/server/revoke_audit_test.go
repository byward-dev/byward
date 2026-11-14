package server

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"maps"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"github.com/byward-dev/byward/internal/audit"
	"github.com/byward-dev/byward/internal/config"
)

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
				proxyLog := &syncBuffer{}
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
				time.Sleep(10 * time.Second) // two deny-list syncs, which run every 5 s
				synctest.Wait()

				want := grantRevokedRecords(t, command.String())
				got := grantRevokedRecords(t, proxyLog.String())
				if len(want) != 1 || len(got) != 1 {
					t.Fatalf("the command wrote %d grant_revoked records and the proxy %d, want 1 each\ncommand: %s\nproxy: %s", len(want), len(got), command.String(), proxyLog.String())
				}
				if !maps.Equal(want[0], got[0]) {
					t.Fatalf("the proxy recorded %v, want the command's record %v", got[0], want[0])
				}
				// Stated on their own: the record never carries a token or a grant ID (invariant 2), even
				// if the command's record ever did.
				for field, v := range got[0] {
					s, _ := v.(string)
					for id, tok := range tokens {
						if strings.Contains(s, tok) {
							t.Fatalf("the proxy's record carries %s's access token in %q", id, field)
						}
					}
				}
				if id, ok := got[0]["grant_id"]; ok {
					t.Fatalf("the proxy's record carries grant_id %v", id)
				}
			})
		})
	}
}
