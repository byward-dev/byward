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

// revokeEnv is a configured proxy whose store holds one grant for alice and one for bob, with an
// access token for each issued when the grants were (before any revocation), and a running
// replica holding the store open, so each revocation is a second writer.
func revokeEnv(t *testing.T) (cfg *config.Config, tokens map[string]string) {
	t.Helper()
	env, cfg := storeEnv(t)
	created := time.Now().Add(-time.Minute)
	tokens = map[string]string{}
	withStore(t, cfg, func(st *sqlite.Store) {
		for id, subject := range map[string]string{"alice": aliceKey, "bob": bobKey} {
			g := grantFor(id, created)
			g.Subject = subject
			if _, err := st.CreateGrant(context.Background(), g); err != nil {
				t.Fatal(err)
			}
			tokens[id] = sealAccessFor(t, cfg, env, id, subject, created)
		}
	})
	running, err := buildAuth(cfg, discard, Observability{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { stop(t, running) })
	return cfg, tokens
}

// valid reports whether a fresh replica (the next deny-list sync) accepts the access token.
func valid(t *testing.T, cfg *config.Config, tok string) bool {
	t.Helper()
	replica, err := buildAuth(cfg, discard, Observability{})
	if err != nil {
		t.Fatal(err)
	}
	defer stop(t, replica)
	_, err = replica.validator.Validate(context.Background(), tok)
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
	cfg, tok := revokeEnv(t)
	var logs bytes.Buffer
	user, err := RevokeUser(context.Background(), cfg, slog.New(slog.NewJSONHandler(&logs, nil)), strings.ToUpper(aliceKey))
	if err != nil || user != aliceKey {
		t.Fatalf("RevokeUser = %q, %v; want %q", user, err, aliceKey)
	}
	if valid(t, cfg, tok["alice"]) || !grantGone(t, cfg, "alice") {
		t.Fatal("alice's token is still accepted or her grant survived")
	}
	if !valid(t, cfg, tok["bob"]) || grantGone(t, cfg, "bob") {
		t.Fatal("revoking alice ended bob's access")
	}
	if out := logs.String(); !strings.Contains(out, `"event":"grant_revoked"`) || !strings.Contains(out, `"reason":"operator revoke-user"`) ||
		!strings.Contains(out, `"user_key":"`+aliceKey+`"`) {
		t.Fatalf("audit %s: want grant_revoked, operator revoke-user, alice's key", out)
	}
}

func TestRevokeAllEndsEveryUsersAccessBesideARunningProxy(t *testing.T) {
	cfg, tok := revokeEnv(t)
	var logs bytes.Buffer
	if err := RevokeAll(context.Background(), cfg, slog.New(slog.NewJSONHandler(&logs, nil))); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"alice", "bob"} {
		if valid(t, cfg, tok[id]) || !grantGone(t, cfg, id) {
			t.Fatalf("%s's token is still accepted or the grant survived revoke-all", id)
		}
	}
	if out := logs.String(); !strings.Contains(out, `"event":"grant_revoked"`) || !strings.Contains(out, `"reason":"operator revoke-all"`) {
		t.Fatalf("audit %s: want grant_revoked with operator revoke-all", out)
	}
}

// A key that is not tid:oid would revoke nobody while looking done (formats: entra.UserKey).
func TestRevokeUserRefusesWhatIsNotAUserKeyAndRevokesNobody(t *testing.T) {
	cfg, tok := revokeEnv(t)
	if _, err := RevokeUser(context.Background(), cfg, discard, "alice@contoso.com"); !errors.Is(err, ErrNotAUserKey) {
		t.Fatalf("RevokeUser(an email) = %v, want ErrNotAUserKey", err)
	}
	if !valid(t, cfg, tok["alice"]) {
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

// A revocation that fails is not audited: the grant_revoked record follows the stored revocation.
func TestAFailedRevocationIsNotAudited(t *testing.T) {
	cfg, _ := revokeEnv(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // the store still opens (on its own deadline); the revocation's write then fails
	var logs bytes.Buffer
	if err := RevokeAll(ctx, cfg, slog.New(slog.NewJSONHandler(&logs, nil))); err == nil {
		t.Fatal("RevokeAll with a cancelled context succeeded")
	}
	if strings.Contains(logs.String(), `"event":"grant_revoked"`) {
		t.Fatalf("a failed revocation was audited: %s", logs.String())
	}
	if !strings.Contains(logs.String(), `"msg":"store open"`) {
		t.Fatalf("the store never opened, so this test proves nothing: %s", logs.String())
	}
}
