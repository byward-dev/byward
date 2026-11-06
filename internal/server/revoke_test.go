package server

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/byward-dev/byward/internal/config"
	"github.com/byward-dev/byward/internal/resource"
	"github.com/byward-dev/byward/internal/store"
	"github.com/byward-dev/byward/internal/store/sqlite"
)

const (
	aliceKey = "00000000-0000-0000-0000-00000000000a:11111111-1111-1111-1111-11111111111a"
	bobKey   = "00000000-0000-0000-0000-00000000000a:11111111-1111-1111-1111-11111111111b"
)

// revokeEnv is a configured proxy whose store holds one grant for alice and one for bob, and a
// running replica (its store open) that has synced them.
func revokeEnv(t *testing.T) (env []string, cfg *config.Config, running *auth) {
	t.Helper()
	env, cfg = storeEnv(t)
	created := time.Now().Add(-time.Minute)
	withStore(t, cfg, func(st *sqlite.Store) {
		for id, subject := range map[string]string{"alice": aliceKey, "bob": bobKey} {
			g := grantFor(id, created)
			g.Subject = subject
			if _, err := st.CreateGrant(context.Background(), g); err != nil {
				t.Fatal(err)
			}
		}
	})
	running, err := buildAuth(cfg, discard, Observability{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { stop(t, running) })
	return env, cfg, running
}

// valid reports whether a fresh replica (the next deny-list sync) accepts the user's token.
func valid(t *testing.T, cfg *config.Config, env []string, grantID, subject string) bool {
	t.Helper()
	replica, err := buildAuth(cfg, discard, Observability{})
	if err != nil {
		t.Fatal(err)
	}
	defer stop(t, replica)
	_, err = replica.validator.Validate(context.Background(), sealAccessFor(t, cfg, env, grantID, subject))
	if err != nil && !errors.Is(err, resource.ErrInvalid) {
		t.Fatalf("validate: %v", err)
	}
	return err == nil
}

func grantGone(t *testing.T, cfg *config.Config, id string) bool {
	t.Helper()
	var err error
	withStore(t, cfg, func(st *sqlite.Store) { _, err = st.Grant(context.Background(), id) })
	return errors.Is(err, store.ErrNotFound)
}

// ADR-0006 §9: revoke-user ends one user's access, from a second connection to the store while a
// proxy runs. The key is accepted as the portal shows it (upper case) and audited canonically.
func TestRevokeUserEndsOnlyThatUsersAccessBesideARunningProxy(t *testing.T) {
	env, cfg, _ := revokeEnv(t)
	var logs bytes.Buffer
	user, err := RevokeUser(context.Background(), cfg, slog.New(slog.NewJSONHandler(&logs, nil)), strings.ToUpper(aliceKey))
	if err != nil || user != aliceKey {
		t.Fatalf("RevokeUser = %q, %v; want %q", user, err, aliceKey)
	}
	if valid(t, cfg, env, "alice", aliceKey) || !grantGone(t, cfg, "alice") {
		t.Fatal("alice's token is still accepted or her grant survived")
	}
	if !valid(t, cfg, env, "bob", bobKey) || grantGone(t, cfg, "bob") {
		t.Fatal("revoking alice ended bob's access")
	}
	if out := logs.String(); !strings.Contains(out, `"event":"grant_revoked"`) || !strings.Contains(out, `"reason":"operator revoke-user"`) ||
		!strings.Contains(out, `"user_key":"`+aliceKey+`"`) {
		t.Fatalf("audit %s: want grant_revoked, operator revoke-user, alice's key", out)
	}
}

func TestRevokeAllEndsEveryUsersAccessBesideARunningProxy(t *testing.T) {
	env, cfg, _ := revokeEnv(t)
	var logs bytes.Buffer
	if err := RevokeAll(context.Background(), cfg, slog.New(slog.NewJSONHandler(&logs, nil))); err != nil {
		t.Fatal(err)
	}
	for id, subject := range map[string]string{"alice": aliceKey, "bob": bobKey} {
		if valid(t, cfg, env, id, subject) || !grantGone(t, cfg, id) {
			t.Fatalf("%s's token is still accepted or the grant survived revoke-all", id)
		}
	}
	if out := logs.String(); !strings.Contains(out, `"event":"grant_revoked"`) || !strings.Contains(out, `"reason":"operator revoke-all"`) {
		t.Fatalf("audit %s: want grant_revoked with operator revoke-all", out)
	}
}

// A key that is not tid:oid (an email, a name, one GUID) would revoke nobody while looking done.
func TestRevokeUserRefusesWhatIsNotAUserKeyAndRevokesNobody(t *testing.T) {
	env, cfg, _ := revokeEnv(t)
	for _, key := range []string{"", "alice@contoso.com", "tid:oid", "11111111-1111-1111-1111-11111111111a", aliceKey + ":extra"} {
		if _, err := RevokeUser(context.Background(), cfg, discard, key); !errors.Is(err, ErrNotAUserKey) {
			t.Errorf("RevokeUser(%q) = %v, want ErrNotAUserKey", key, err)
		}
	}
	if !valid(t, cfg, env, "alice", aliceKey) {
		t.Fatal("a refused key revoked alice")
	}
	var revs []store.Revocation
	withStore(t, cfg, func(st *sqlite.Store) {
		var err error
		if revs, err = st.Revocations(context.Background()); err != nil {
			t.Fatal(err)
		}
	})
	if len(revs) != 0 {
		t.Fatalf("revocations = %+v, want none", revs)
	}
}

func TestRevocationNeedsAuthentication(t *testing.T) {
	cfg, _, err := config.Load(nil, []string{"BYWARD_INSECURE_NO_AUTH=true", "BYWARD_PUBLIC_URL=http://127.0.0.1:8080/mcp", "BYWARD_UPSTREAM_URL=http://u/mcp"}, os.ReadFile)
	if err != nil {
		t.Fatal(err)
	}
	if err := RevokeAll(context.Background(), cfg, discard); err == nil || !strings.Contains(err.Error(), "BYWARD_INSECURE_NO_AUTH") {
		t.Fatalf("RevokeAll without authentication = %v, want an error naming BYWARD_INSECURE_NO_AUTH", err)
	}
}
