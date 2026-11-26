package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"os"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"github.com/byward-dev/byward/internal/broker"
	"github.com/byward-dev/byward/internal/config"
	"github.com/byward-dev/byward/internal/logging"
	"github.com/byward-dev/byward/internal/resource"
	"github.com/byward-dev/byward/internal/store"
	"github.com/byward-dev/byward/internal/store/sqlite"
	"github.com/byward-dev/byward/internal/token"
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
	_, cfg = storeEnv(t)
	created := time.Now().Add(-time.Minute)
	tokens = map[string]string{}
	withStore(t, cfg, func(st *sqlite.Store) {
		for id, subject := range map[string]string{"alice": aliceKey, "bob": bobKey} {
			g := grantFor(id, created)
			g.Subject = subject
			if _, err := st.CreateGrant(context.Background(), g); err != nil {
				t.Fatal(err)
			}
			tokens[id] = sealAccessFor(t, cfg, id, subject, created)
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
	user, name, err := RevokeUser(context.Background(), cfg, slog.New(slog.NewJSONHandler(&logs, nil)), strings.ToUpper(aliceKey))
	// The store by its setting, never its path (security invariant 2, #575).
	if err != nil || user != aliceKey || name != "BYWARD_STORE_DIR" {
		t.Fatalf("RevokeUser = %q, %q, %v; want %q in BYWARD_STORE_DIR", user, name, err, aliceKey)
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

// revoke-all ends every user's access beside a running proxy and names the store by its setting,
// never its path.
func TestRevokeAllEndsEveryUsersAccessBesideARunningProxy(t *testing.T) {
	cfg, tok := revokeEnv(t)
	var logs bytes.Buffer
	if name, err := RevokeAll(context.Background(), cfg, slog.New(slog.NewJSONHandler(&logs, nil))); err != nil || name != "BYWARD_STORE_DIR" {
		t.Fatalf("RevokeAll = %q, %v; want BYWARD_STORE_DIR", name, err)
	}
	// An operator command prints no listing of the configuration, so no line of it shows the store's
	// path (security invariant 2, #575).
	if strings.Contains(logs.String(), cfg.StoreDir) || strings.Contains(logs.String(), cfg.StoreCounterFile) {
		t.Errorf("the command's log shows a store path:\n%s", logs.String())
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

// #469: an operator revocation is stored with the time it is made. Collect keeps it for
// store.RevocationRetention after that time, and for that long another replica's deny list, synced
// from the store, refuses the tokens it cut off. So at the last valid instant of a token issued at
// the revocation (its lifetime plus the validator's leeway), after a Collect at that instant, a
// freshly synced replica must still refuse it. A token the revocation does not cover still passes,
// so the refusal is the revocation's, not a stale deny list's.
func TestAnOperatorRevocationOutlivesTheTokensItCutOff(t *testing.T) {
	for _, tc := range []struct {
		name   string
		revoke func(t *testing.T, cfg *config.Config)
	}{
		{"revoke-user", func(t *testing.T, cfg *config.Config) {
			if _, _, err := RevokeUser(context.Background(), cfg, discard, aliceKey); err != nil {
				t.Fatal(err)
			}
		}},
		{"revoke-all", func(t *testing.T, cfg *config.Config) {
			if _, err := RevokeAll(context.Background(), cfg, discard); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				cfg, _ := revokeEnv(t)
				time.Sleep(45 * time.Second) // off the minute, so a time truncated to it is earlier
				revoked := sealAccessFor(t, cfg, "alice", aliceKey, time.Now())
				tc.revoke(t, cfg)
				time.Sleep(time.Second)
				uncovered := sealAccessFor(t, cfg, "bob", bobKey, time.Now()) // after even a revoke-all's cut-off

				if valid(t, cfg, revoked) {
					t.Fatal("a replica synced after the revocation accepts the revoked token")
				}
				if !valid(t, cfg, uncovered) {
					t.Fatal("a replica synced after the revocation refuses a token it does not cover")
				}
				time.Sleep(broker.AccessLifetime + token.Leeway - time.Second) // the revoked token's last valid instant
				withStore(t, cfg, func(st *sqlite.Store) {
					if err := st.Collect(context.Background(), time.Now()); err != nil {
						t.Fatal(err)
					}
				})
				if valid(t, cfg, revoked) {
					t.Fatal("a replica synced after Collect accepts the revoked token within its lifetime: the revocation was collected early")
				}
				if !valid(t, cfg, uncovered) {
					t.Fatal("a replica synced after Collect refuses a token the revocation does not cover")
				}
			})
		})
	}
}

// A key that is not tid:oid would revoke nobody while looking done (formats: entra.UserKey).
func TestRevokeUserRefusesWhatIsNotAUserKeyAndRevokesNobody(t *testing.T) {
	cfg, tok := revokeEnv(t)
	if _, _, err := RevokeUser(context.Background(), cfg, discard, "alice@contoso.example"); !errors.Is(err, ErrNotAUserKey) {
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

// L152: a revocation whose settings point at no store is refused with ErrNoStore, naming the setting,
// never the directory's path (security invariant 2, #575), and the way out, and creates nothing there.
func TestARevocationWithNoStoreIsRefusedNamingTheSetting(t *testing.T) {
	_, cfg := storeEnv(t)
	cfg.StoreDir += "-typo"
	_, err := RevokeAll(context.Background(), cfg, discard)
	if !errors.Is(err, ErrNoStore) || !strings.HasPrefix(err.Error(), "BYWARD_STORE_DIR: no byward store there") || strings.Contains(err.Error(), cfg.StoreDir) ||
		!strings.Contains(err.Error(), "run the command with the proxy's settings") {
		t.Fatalf("RevokeAll = %v; want ErrNoStore naming BYWARD_STORE_DIR, without its path, and the fix", err)
	}
	if _, err := os.Stat(cfg.StoreDir); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("the refused revocation created %s (%v)", cfg.StoreDir, err)
	}
}

func TestRevocationNeedsAuthentication(t *testing.T) {
	cfg := loadNoAuthConfig(t, "http://u/mcp")
	if _, err := RevokeAll(context.Background(), cfg, discard); err == nil || !strings.Contains(err.Error(), "BYWARD_INSECURE_NO_AUTH") {
		t.Fatalf("RevokeAll without authentication = %v, want an error naming BYWARD_INSECURE_NO_AUTH", err)
	}
}

// A revocation that fails is not audited: the grant_revoked record follows the stored revocation.
func TestAFailedRevocationIsNotAudited(t *testing.T) {
	cfg, _ := revokeEnv(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // the store still opens (on its own deadline); the revocation's write then fails
	var logs bytes.Buffer
	if _, err := RevokeAll(ctx, cfg, slog.New(slog.NewJSONHandler(&logs, nil))); err == nil {
		t.Fatal("RevokeAll with a cancelled context succeeded")
	}
	if strings.Contains(logs.String(), `"event":"grant_revoked"`) {
		t.Fatalf("a failed revocation was audited: %s", logs.String())
	}
	if !strings.Contains(logs.String(), `"msg":"store open"`) {
		t.Fatalf("the store never opened, so this test proves nothing: %s", logs.String())
	}
}

// With an oidc IdP the user key is the subject claim's value, matched exactly (sub is
// case-sensitive): revoke-user ends that user's grants, and a different case is another user.
func TestRevokeUserTakesAnOIDCSubjectAsItIs(t *testing.T) {
	cfg := loadOIDC(t, "keycloak", "https://sso.example.com/realms/acme", "c")
	created := time.Now().Add(-time.Minute)
	withStore(t, cfg, func(st *sqlite.Store) {
		for id, subject := range map[string]string{"alice": "f3a1-Alice", "other": "F3A1-alice"} {
			g := grantFor(id, created)
			g.Subject = subject
			if _, err := st.CreateGrant(context.Background(), g); err != nil {
				t.Fatal(err)
			}
		}
	})
	// What an operator pastes is trimmed: sign-in stores no subject with white space at either end.
	for _, pasted := range []string{"f3a1-Alice\n", " f3a1-Alice "} {
		if user, _, err := RevokeUser(context.Background(), cfg, discard, pasted); err != nil || user != "f3a1-Alice" {
			t.Fatalf("RevokeUser(%q) = %q, %v; want f3a1-Alice", pasted, user, err)
		}
	}
	if !grantGone(t, cfg, "alice") || grantGone(t, cfg, "other") {
		t.Fatal("revoke-user must end exactly the grants of that subject")
	}
	// The sub rule, not only the one every claim has: a sub is at most 255 ASCII characters.
	for _, key := range []string{"  ", "alice\nbob", "a\x00b", strings.Repeat("a", 256), "ålice"} {
		if _, _, err := RevokeUser(context.Background(), cfg, discard, key); !errors.Is(err, ErrNotAUserKey) {
			t.Errorf("RevokeUser(%q) = %v, want ErrNotAUserKey", key, err)
		}
	}
}

// A token given to revoke-user as an oidc sub is within the sub rule, so it is taken as a user key
// (#594): it revokes nobody, as no user signed in with it, and the audit record and every log line
// name it only as [REDACTED]. A real user's grant beside it stays.
func TestRevokeUserTakesATokenAsAnOIDCSubRevokesNobodyAndAuditsItRedacted(t *testing.T) {
	const token = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJMSzdDQU5BUlkifQ.LK7CANARY"
	cfg := loadOIDC(t, "keycloak", "https://sso.example.com/realms/acme", "c")
	withStore(t, cfg, func(st *sqlite.Store) {
		g := grantFor("held", time.Now().Add(-time.Minute))
		g.Subject = "f47ac10b-58cc-4372-a567-0e02b2c3d479"
		if _, err := st.CreateGrant(context.Background(), g); err != nil {
			t.Fatal(err)
		}
	})
	var logs bytes.Buffer
	if user, _, err := RevokeUser(context.Background(), cfg, logging.New(&logs, "json"), token); err != nil || user != token {
		t.Fatalf("RevokeUser(a token) = %q, %v; want it taken as a key", user, err)
	}
	if grantGone(t, cfg, "held") {
		t.Fatal("another user's grant was revoked")
	}
	if strings.Contains(logs.String(), "LK7CANARY") || !strings.Contains(logs.String(), `"user_key":"[REDACTED]"`) {
		t.Fatalf("the log shows the token, or does not audit it redacted: %s", logs.String())
	}
}

// revoke-user revokes a user key however it is written, under any subject claim, so every user
// sign-in stored stays revocable (#594). Through the real logger, the audit record names a
// credential-shaped key (logging.LooksSecret, which also matches a name such as "Ann Basic Lee", a sub
// such as eyJohn.Smith, or an email that happens to read like a token) as [REDACTED], and no other
// attribute carries a piece of it of 4 or more characters (other than one the issuer's host holds, such
// as example); any other key is named in full.
func TestRevokeUserRevokesAKeyUnderAnySubjectClaimAndAuditsACredentialShapedOneRedacted(t *testing.T) {
	for _, tc := range []struct {
		claim, key string
		redacted   bool
	}{
		{"sub", "eyJohn.Smith", true},
		{"sub", "Basic x9Zq", true},
		{"sub", "f47ac10b-58cc-4372-a567-0e02b2c3d479", false},
		{"name", "Ann Basic Lee", true},
		{"email", "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJMSzdDQU5BUlkifQ.LK7CANARY", true},
		{"email", "heyJoe.Smith.Jr@example.com", true},
		{"email", "jöhn@exämple.com", false},
		{"name", "José", false},
	} {
		t.Run(tc.claim+"/"+tc.key, func(t *testing.T) {
			cfg := loadOIDC(t, "keycloak", "https://sso.example.com/realms/acme", "c", "BYWARD_OIDC_SUBJECT_CLAIM="+tc.claim)
			withStore(t, cfg, func(st *sqlite.Store) {
				g := grantFor("held", time.Now().Add(-time.Minute))
				g.Subject = tc.key
				if _, err := st.CreateGrant(context.Background(), g); err != nil {
					t.Fatal(err)
				}
			})
			var logs bytes.Buffer
			user, _, err := RevokeUser(context.Background(), cfg, logging.New(&logs, "json"), tc.key)
			if err != nil || user != tc.key {
				t.Fatalf("RevokeUser = %q, %v; want the key revoked as given", user, err)
			}
			if !grantGone(t, cfg, "held") {
				t.Fatal("the user's grant is still there")
			}
			var record map[string]any
			for _, line := range strings.Split(strings.TrimSpace(logs.String()), "\n") {
				var r map[string]any
				if json.Unmarshal([]byte(line), &r) == nil && r["event"] == "grant_revoked" {
					record = r
				}
			}
			want := tc.key
			if tc.redacted {
				want = "[REDACTED]"
			}
			if record == nil || record["user_key"] != want {
				t.Fatalf("audit record %v; want user_key %q", record, want)
			}
			if !tc.redacted {
				return
			}
			for _, part := range strings.FieldsFunc(tc.key, func(r rune) bool { return r == ' ' || r == '.' || r == '@' }) {
				if len(part) >= 4 && !strings.Contains("https://sso.example.com/realms/acme", part) && strings.Contains(logs.String(), part) {
					t.Errorf("the log holds %q, part of the key: %s", part, logs.String())
				}
			}
		})
	}
}
