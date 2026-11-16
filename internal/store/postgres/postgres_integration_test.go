//go:build integration

package postgres

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/byward-dev/byward/internal/store"
	"github.com/byward-dev/byward/internal/store/storetest"
	"github.com/byward-dev/byward/internal/testutil/testcert"
)

var (
	ctx = context.Background()
	t0  = time.Date(2026, 11, 6, 12, 0, 0, 0, time.UTC)
)

// TestMain moves the local zone away from UTC before anything runs: pgx decodes timestamptz in
// time.Local, and the store must return UTC whatever the host's zone (CI runs in UTC).
func TestMain(m *testing.M) {
	time.Local = time.FixedZone("UTC+5:45", 5*60*60+45*60)
	os.Exit(m.Run())
}

// The adapter on each supported PostgreSQL version, over TLS with verify-full: the conformance
// suite, then what only PostgreSQL has (ADR-0007 §2, amended for #227).
func TestIntegrationPostgres(t *testing.T) {
	requirePostgres(t)
	for _, img := range postgresImages {
		t.Run(img.Name, func(t *testing.T) {
			srv := startPostgres(t, img.Image)
			t.Run("Conformance", func(t *testing.T) {
				storetest.Run(t, func(t *testing.T) store.Store {
					s, _ := srv.open(t)
					return s
				})
			})
			for _, tc := range []struct {
				name string
				fn   func(*testing.T, *server)
			}{
				{"RevocationRacingCreateGrantAcrossReplicasLeavesNoCoveredGrant", revocationRacingCreateGrantAcrossReplicasLeavesNoCoveredGrant},
				{"AConcurrentInsertOfTheSameIDIsErrExists", aConcurrentInsertOfTheSameIDIsErrExists},
				{"MigrationsRunOneAtATime", migrationsRunOneAtATime},
				{"NewerSchemaIsRefused", newerSchemaIsRefused},
				{"AnOperatorOpenFindsTheSchemaOrCreatesNothing", anOperatorOpenFindsTheSchemaOrCreatesNothing},
				{"FixturesMigrateToTheCurrentSchemaKeepingTheirData", fixturesMigrateToTheCurrentSchemaKeepingTheirData},
				{"FailedMigrationChangesNothing", failedMigrationChangesNothing},
				{"AnEpochBumpCountsAtOnceWithoutAReopen", anEpochBumpCountsAtOnceWithoutAReopen},
				{"OnlyCommittedWritesAdvanceTheWriteSequence", onlyCommittedWritesAdvanceTheWriteSequence},
				{"CollectDropsExpiredSpentRecords", collectDropsExpiredSpentRecords},
				{"CollectSkipsWhileAnotherReplicaCollects", collectSkipsWhileAnotherReplicaCollects},
				{"VerifyFullRefusesAnotherCAOrHostName", verifyFullRefusesAnotherCAOrHostName},
				{"PingAnswersWhileOpenAndFailsAfterClose", pingAnswersWhileOpenAndFailsAfterClose},
				{"EmptyIdPTokensReadBackAsNone", emptyIdPTokensReadBackAsNone},
				{"AnOlderBinarysReapprovalUnmarksTheConsent", anOlderBinarysReapprovalUnmarksTheConsent},
				{"ARestoreStartsOneEpochAcrossReplicas", aRestoreStartsOneEpochAcrossReplicas},
				{"AReplicasFirstCheckFindsARestore", aReplicasFirstCheckFindsARestore},
				{"AValueLostInACrashIsNoRestore", aValueLostInACrashIsNoRestore},
				{"ConcurrentWritesAreNoRestore", concurrentWritesAreNoRestore},
				{"NewEpochStartsAnEpochEachTimeThatRunningReplicasAdopt", newEpochStartsAnEpochEachTimeThatRunningReplicasAdopt},
				{"DescribeNamesTheDatabaseAndItsTLSNeverThePassword", describeNamesTheDatabaseAndItsTLSNeverThePassword},
				{"AReuseWhoseRevocationFailsReportsTheFailureAndKeepsTheGrant", aReuseWhoseRevocationFailsReportsTheFailureAndKeepsTheGrant},
			} {
				t.Run(tc.name, func(t *testing.T) { tc.fn(t, srv) })
			}
		})
	}
}

func grant(id, subject string) store.Grant {
	return store.Grant{ID: id, ClientID: "c", Subject: subject, Issuer: "https://idp.example/v2.0",
		Resource: "https://mcp.example.com/mcp", Scopes: []string{"mcp"}, CreatedAt: t0, ExpiresAt: t0.Add(24 * time.Hour)}
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

// Write skew, made to happen: replica A's CreateGrant has checked for a cut-off and waits to insert
// (an uncommitted grant with the same ID holds it) while replica B's cut-off commits. Under READ
// COMMITTED, A would then insert a grant the cut-off covers. SERIALIZABLE aborts A with 40001, and
// A's retry sees the cut-off and refuses (store.Grants.CreateGrant).
func revocationRacingCreateGrantAcrossReplicasLeavesNoCoveredGrant(t *testing.T, srv *server) {
	cutOff := t0.Add(time.Hour)
	for _, tc := range []struct {
		name   string
		revoke func(*Store) error
	}{
		{"RevokeSubject", func(s *Store) error { return s.RevokeSubject(ctx, "tid:alice", cutOff, cutOff) }},
		{"RevokeAll", func(s *Store) error { return s.RevokeAll(ctx, cutOff, cutOff) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a, db := srv.open(t)
			b := srv.openOn(t, db)
			holder, watch := srv.conn(t, db), srv.conn(t, db)
			tx, err := holder.Begin(ctx)
			must(t, err)
			defer func() { _ = tx.Rollback(ctx) }()
			_, err = tx.Exec(ctx, `INSERT INTO grants (id, client_id, subject, issuer, resource, scopes, created_at, expires_at, epoch)
				VALUES ('g', 'c', 'tid:other', '', '', '{}', $1, $2, 1)`, t0, t0.Add(time.Hour))
			must(t, err)

			done := make(chan error, 1)
			go func() {
				_, err := a.CreateGrant(ctx, grant("g", "tid:alice"))
				done <- err
			}()
			waitFor(t, watch, "A's insert to wait", `SELECT EXISTS (SELECT 1 FROM pg_stat_activity
				WHERE datname = current_database() AND wait_event_type = 'Lock' AND query LIKE 'INSERT INTO grants%')`)
			must(t, tc.revoke(b))
			must(t, tx.Rollback(ctx))

			if err := <-done; !errors.Is(err, store.ErrRevoked) {
				t.Fatalf("CreateGrant = %v, want ErrRevoked after its retry", err)
			}
			if _, err := b.Grant(ctx, "g"); !errors.Is(err, store.ErrNotFound) {
				t.Fatalf("a grant the cut-off covers was stored: %v", err)
			}
		})
	}
}

// A key inserted by a writer that is not SERIALIZABLE (an operator's SQL, say) while CreateGrant
// waits to insert the same one is a unique violation, not a serialization failure: SSI converts
// only conflicts with SERIALIZABLE transactions (postgresql.org/docs/current/transaction-iso.html).
// The retry's own check then reports ErrExists, as the contract says.
func aConcurrentInsertOfTheSameIDIsErrExists(t *testing.T, srv *server) {
	s, db := srv.open(t)
	holder, watch := srv.conn(t, db), srv.conn(t, db)
	tx, err := holder.Begin(ctx)
	must(t, err)
	defer func() { _ = tx.Rollback(ctx) }()
	_, err = tx.Exec(ctx, `INSERT INTO grants (id, client_id, subject, issuer, resource, scopes, created_at, expires_at, epoch)
		VALUES ('g', 'c', 'tid:other', '', '', '{}', $1, $2, 1)`, t0, t0.Add(time.Hour))
	must(t, err)

	done := make(chan error, 1)
	go func() {
		_, err := s.CreateGrant(ctx, grant("g", "tid:alice"))
		done <- err
	}()
	waitFor(t, watch, "the insert to wait", `SELECT EXISTS (SELECT 1 FROM pg_stat_activity
		WHERE datname = current_database() AND wait_event_type = 'Lock' AND query LIKE 'INSERT INTO grants%')`)
	must(t, tx.Commit(ctx))
	if err := <-done; !errors.Is(err, store.ErrExists) {
		t.Fatalf("CreateGrant = %v, want ErrExists after its retry", err)
	}
}

// Replicas that start together migrate one at a time: while another holds the migration lock, Open
// waits and changes nothing, then finds the schema migrated.
func migrationsRunOneAtATime(t *testing.T, srv *server) {
	db := srv.newDatabase(t)
	holder := srv.conn(t, db)
	_, err := holder.Exec(ctx, "SELECT pg_advisory_lock($1)", migrateLock)
	must(t, err)
	done := make(chan error, 1)
	openCtx := bounded(t)
	go func() {
		s, err := Open(openCtx, Options{DSN: srv.dsn(db)})
		if err == nil {
			_ = s.Close()
		}
		done <- err
	}()
	waitFor(t, holder, "Open to wait for the migration lock", `SELECT EXISTS (SELECT 1 FROM pg_locks
		WHERE locktype = 'advisory' AND NOT granted AND database = (SELECT oid FROM pg_database WHERE datname = current_database()))`)
	var migrated bool
	must(t, holder.QueryRow(ctx, "SELECT to_regclass('grants') IS NOT NULL").Scan(&migrated))
	if migrated {
		t.Fatal("Open migrated while another migrator held the lock")
	}
	_, err = holder.Exec(ctx, "SELECT pg_advisory_unlock($1)", migrateLock)
	must(t, err)
	must(t, <-done)
	if v := version(t, holder); v != schemaVersion() {
		t.Fatalf("schema v%d, want v%d", v, schemaVersion())
	}
}

func newerSchemaIsRefused(t *testing.T, srv *server) {
	s, db := srv.open(t)
	must(t, s.Close())
	_, err := srv.conn(t, db).Exec(ctx, "UPDATE schema_version SET version = $1", schemaVersion()+1)
	must(t, err)
	_, err = Open(bounded(t), Options{DSN: srv.dsn(db)})
	if err == nil || !strings.Contains(err.Error(), "newer than this binary") {
		t.Fatalf("err = %v, want the downgrade refusal", err)
	}
}

// L152: an operator command's open (MustExist) finds byward's schema at this binary's version, or
// fails having created and migrated nothing: a database without the schema, or one that does not
// exist, is store.ErrNoStore naming the database (never the DSN); another version is refused and
// stays as it was.
func anOperatorOpenFindsTheSchemaOrCreatesNothing(t *testing.T, srv *server) {
	// tables lists the database's tables, and schema_version's value when it has one.
	tables := func(t *testing.T, db string) string {
		c := srv.conn(t, db)
		rows, err := c.Query(ctx, "SELECT tablename FROM pg_tables WHERE schemaname = current_schema() ORDER BY tablename")
		must(t, err)
		names, err := pgx.CollectRows(rows, pgx.RowTo[string])
		must(t, err)
		out := strings.Join(names, ",")
		if slices.Contains(names, "schema_version") {
			var v int
			must(t, c.QueryRow(ctx, "SELECT version FROM schema_version").Scan(&v))
			out += fmt.Sprintf(" at v%d", v)
		}
		return out
	}
	storeAt := func(v int) func(*testing.T, string) {
		return func(t *testing.T, db string) {
			must(t, srv.openOn(t, db).Close())
			_, err := srv.conn(t, db).Exec(ctx, "UPDATE schema_version SET version = $1", v)
			must(t, err)
		}
	}
	for _, tc := range []struct {
		name    string
		prepare func(t *testing.T, db string)
		is      error  // the sentinel the refusal wraps; nil when Open succeeds
		want    string // in the error; "" when Open succeeds
	}{
		{"an empty database", func(*testing.T, string) {}, store.ErrNoStore, "holds no byward schema"},
		{"another program's tables", func(t *testing.T, db string) {
			_, err := srv.conn(t, db).Exec(ctx, "CREATE TABLE notes (body text)")
			must(t, err)
		}, store.ErrNoStore, "holds no byward schema"},
		{"schema_version at 0", func(t *testing.T, db string) {
			_, err := srv.conn(t, db).Exec(ctx, "CREATE TABLE schema_version (version integer NOT NULL); INSERT INTO schema_version VALUES (0)")
			must(t, err)
		}, store.ErrNoStore, "holds no byward schema"},
		{"an older schema", storeAt(schemaVersion() - 1), store.ErrOlderSchema, fmt.Sprintf("the store's v%d, this byward's v%d", schemaVersion()-1, schemaVersion())},
		{"a newer schema", storeAt(schemaVersion() + 1), store.ErrNewerSchema, fmt.Sprintf("the store's v%d, this byward's v%d", schemaVersion()+1, schemaVersion())},
		{"the store", storeAt(schemaVersion()), nil, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db := srv.newDatabase(t)
			tc.prepare(t, db)
			before := tables(t, db)
			st, err := Open(bounded(t), Options{DSN: srv.dsn(db), MustExist: true})
			if tc.want == "" {
				if err != nil {
					t.Fatalf("Open(MustExist) on the store: %v", err)
				}
				must(t, st.Close())
				return
			}
			if err == nil {
				must(t, st.Close())
				t.Fatal("Open(MustExist) succeeded")
			}
			for _, sentinel := range []error{store.ErrNoStore, store.ErrOlderSchema, store.ErrNewerSchema} {
				if errors.Is(err, sentinel) != (sentinel == tc.is) {
					t.Fatalf("Open(MustExist) = %v; errors.Is(%v) = %v, want %v", err, sentinel, errors.Is(err, sentinel), sentinel == tc.is)
				}
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Open(MustExist) = %v; want it to say %q", err, tc.want)
			}
			if tc.is == store.ErrNoStore && (!strings.Contains(err.Error(), "host="+srv.Host+" port="+srv.Port+" dbname="+db) || strings.Contains(err.Error(), srv.Password)) {
				t.Fatalf("Open(MustExist) = %v; want it to name the database, never the password", err)
			}
			if after := tables(t, db); after != before {
				t.Fatalf("the refused open changed the database: %q, then %q", before, after)
			}
		})
	}
	t.Run("a database that does not exist", func(t *testing.T) {
		_, err := Open(bounded(t), Options{DSN: srv.dsn("no_such_database"), MustExist: true})
		if !errors.Is(err, store.ErrNoStore) || !strings.Contains(err.Error(), "host="+srv.Host+" port="+srv.Port+" dbname=no_such_database") ||
			!strings.Contains(err.Error(), "does not exist") || strings.Contains(err.Error(), srv.Password) {
			t.Fatalf("Open(MustExist) = %v; want store.ErrNoStore naming the missing database, never the password", err)
		}
	})
	// A connection the server refuses is not a missing store: exit 1 with the real error, not 2.
	t.Run("a wrong password", func(t *testing.T) {
		u, err := url.Parse(srv.dsn(srv.newDatabase(t)))
		must(t, err)
		u.User = url.UserPassword(u.User.Username(), "not-the-password")
		_, err = Open(bounded(t), Options{DSN: u.String(), MustExist: true})
		if err == nil || errors.Is(err, store.ErrNoStore) || errors.Is(err, store.ErrOlderSchema) || errors.Is(err, store.ErrNewerSchema) ||
			!strings.Contains(err.Error(), "connect or read schema version") || !strings.Contains(err.Error(), "28P01") ||
			strings.Contains(err.Error(), "not-the-password") {
			t.Fatalf("Open(MustExist) with a wrong password = %v; want the server's refusal (28P01) as a connection error, no sentinel, without the password", err)
		}
	})
}

// The schema version that first holds each part of the migration fixture.
var fixtureSince = storetest.FixtureSince{RevokeAll: 1, RotatedToken: 1, Client: 1, Consent: 1, SpentLogin: 1, SpentAssertion: 2, MarkedConsents: 3}

// Migration fixtures (ADR-0024 §11): each released schema version, with data, migrated to the
// current schema and read back through the store, in UTC.
func fixturesMigrateToTheCurrentSchemaKeepingTheirData(t *testing.T, srv *server) {
	_, fresh := srv.open(t)
	want := schemaOf(t, srv.conn(t, fresh))
	for v := 1; v <= schemaVersion(); v++ {
		t.Run(fmt.Sprintf("v%d", v), func(t *testing.T) {
			db := srv.newDatabase(t)
			loadFixture(t, srv.conn(t, db), v)
			s := srv.openOn(t, db)

			if got := schemaOf(t, srv.conn(t, db)); !reflect.DeepEqual(got, want) {
				t.Fatalf("migrated schema differs from a fresh one:\n got %q\nwant %q", got, want)
			}
			storetest.CheckFixture(t, s, v, fixtureSince)
		})
	}
}

// A migration that fails leaves the database exactly as it was: its DDL and the version bump are
// one transaction, and the binary before it still opens the database.
func failedMigrationChangesNothing(t *testing.T, srv *server) {
	db := srv.newDatabase(t)
	c := srv.conn(t, db)
	loadFixture(t, c, schemaVersion())
	before := schemaOf(t, c)

	saved := migrations
	migrations = append(append([]string{}, saved...), "CREATE TABLE half_done (a integer); UPDATE grants SET subject = 'x'; SELECT * FROM no_such_table;")
	t.Cleanup(func() { migrations = saved })

	s, err := Open(bounded(t), Options{DSN: srv.dsn(db)})
	if err == nil {
		_ = s.Close()
		t.Fatal("Open succeeded although a migration fails")
	}
	if want := fmt.Sprintf("migrate to v%d", len(saved)+1); !strings.Contains(err.Error(), want) {
		t.Fatalf("Open failed before the injected migration ran: %v (want %q)", err, want)
	}
	if v := version(t, c); v != len(saved) {
		t.Fatalf("schema v%d after a failed migration, want v%d", v, len(saved))
	}
	if after := schemaOf(t, c); !reflect.DeepEqual(after, before) {
		t.Fatalf("schema changed by a failed migration:\n%q\n%q", before, after)
	}
	migrations = saved
	if g, err := srv.openOn(t, db).Grant(ctx, storetest.FixtureGrant.ID); err != nil || !reflect.DeepEqual(g, storetest.FixtureGrant) {
		t.Fatalf("data after a failed migration = %+v, %v; want %+v", g, err, storetest.FixtureGrant)
	}
}

// The epoch is read in SQL on every use (ADR-0007 §9): a bump by anyone counts at once, without a
// reopen, for refresh tokens of older grants and for new grants.
func anEpochBumpCountsAtOnceWithoutAReopen(t *testing.T, srv *server) {
	s, db := srv.open(t)
	if g, err := s.CreateGrant(ctx, grant("old", "tid:a")); err != nil || g.Epoch != 1 {
		t.Fatalf("CreateGrant = %+v, %v; want epoch 1", g, err)
	}
	old := store.RefreshToken{Hash: sha256.Sum256([]byte("old")), GrantID: "old", ClientID: "c", CreatedAt: t0, IdleExpiresAt: t0.Add(time.Hour)}
	must(t, s.PutRefreshToken(ctx, old))

	_, err := srv.conn(t, db).Exec(ctx, "UPDATE meta SET value = value + 1 WHERE key = 'epoch'")
	must(t, err)

	if _, err := s.RefreshToken(ctx, old.Hash, t0); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("a refresh token from the older epoch: %v, want ErrNotFound", err)
	}
	next := store.RefreshToken{Hash: sha256.Sum256([]byte("next")), GrantID: "old", ClientID: "c", CreatedAt: t0, IdleExpiresAt: t0.Add(time.Hour)}
	if err := s.RotateRefreshToken(ctx, store.RotateRequest{Old: old.Hash, Next: next, Now: t0}); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("rotating a refresh token from the older epoch: %v, want ErrNotFound", err)
	}
	if g, err := s.CreateGrant(ctx, grant("new", "tid:a")); err != nil || g.Epoch != 2 {
		t.Fatalf("CreateGrant after the bump = %+v, %v; want epoch 2", g, err)
	}
	if g, err := s.Grant(ctx, "new"); err != nil || g.Epoch != 2 {
		t.Fatalf("stored grant = %+v, %v; want epoch 2", g, err)
	}
}

// Restore detection reads the store_writes sequence (ADR-0007 §9): every committed write takes a
// value from it; a refused write commits nothing and takes none.
func onlyCommittedWritesAdvanceTheWriteSequence(t *testing.T, srv *server) {
	s, db := srv.open(t)
	c := srv.conn(t, db)
	writes := func() (n int64) {
		must(t, c.QueryRow(ctx, "SELECT CASE WHEN is_called THEN last_value ELSE 0 END FROM store_writes").Scan(&n))
		return n
	}
	start := writes()
	_, err := s.CreateGrant(ctx, grant("g", "tid:a"))
	must(t, err)
	must(t, s.Collect(ctx, t0))
	if got := writes(); got != start+2 {
		t.Fatalf("store_writes = %d after a grant and a collection, want %d", got, start+2)
	}
	if _, err := s.CreateGrant(ctx, grant("g", "tid:a")); !errors.Is(err, store.ErrExists) {
		t.Fatalf("second CreateGrant: %v, want ErrExists", err)
	}
	if got := writes(); got != start+2 {
		t.Fatalf("store_writes = %d after a refused write, want %d", got, start+2)
	}
}

func collectDropsExpiredSpentRecords(t *testing.T, srv *server) {
	storetest.CollectDropsExpiredSpent(t, func(t *testing.T) (store.Store, func(storetest.Spent) int) {
		s, db := srv.open(t)
		c := srv.conn(t, db)
		return s, func(kind storetest.Spent) int { return count(t, c, string(kind)) }
	})
}

// While another replica collects (it holds the collect lock), Collect returns at once having
// deleted nothing; once it is done, Collect deletes.
func collectSkipsWhileAnotherReplicaCollects(t *testing.T, srv *server) {
	s, db := srv.open(t)
	must(t, s.SpendLogin(ctx, sha256.Sum256([]byte("l")), t0, t0.Add(time.Minute)))
	holder, c := srv.conn(t, db), srv.conn(t, db)
	tx, err := holder.Begin(ctx)
	must(t, err)
	defer func() { _ = tx.Rollback(ctx) }()
	_, err = tx.Exec(ctx, "SELECT pg_advisory_xact_lock($1)", collectLock)
	must(t, err)

	quick, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	must(t, s.Collect(quick, t0.Add(time.Hour)))
	if n := count(t, c, "spent_logins"); n != 1 {
		t.Fatalf("Collect deleted %d rows while another replica held the lock", 1-n)
	}
	must(t, tx.Rollback(ctx))
	must(t, s.Collect(ctx, t0.Add(time.Hour)))
	if n := count(t, c, "spent_logins"); n != 0 {
		t.Fatalf("%d spent logins after Collect, want 0", n)
	}
}

// verify-full is checked end to end: a server certificate from another CA, or for another host
// name, fails the connection.
func verifyFullRefusesAnotherCAOrHostName(t *testing.T, srv *server) {
	db := srv.newDatabase(t)
	other := filepath.Join(t.TempDir(), "other-ca.pem")
	must(t, os.WriteFile(other, testcert.Root(t), 0o600))

	wrongCA := *srv.Server
	wrongCA.CAFile = other
	_, err := Open(bounded(t), Options{DSN: wrongCA.DSN(db)})
	if _, ok := errors.AsType[x509.UnknownAuthorityError](err); !ok {
		t.Fatalf("another CA: err = %v, want an unknown authority", err)
	}

	// The certificate names 127.0.0.1 only. As an IP, ::1 would match no SAN either.
	wrongHost := *srv.Server
	wrongHost.Host = "localhost"
	_, err = Open(bounded(t), Options{DSN: wrongHost.DSN(db)})
	if _, ok := errors.AsType[x509.HostnameError](err); !ok {
		t.Fatalf("another host name: err = %v, want a host name mismatch", err)
	}
}

// Ping backs the readiness probe (ADR-0021 §10): it answers while the store is open and fails once
// it is closed.
func pingAnswersWhileOpenAndFailsAfterClose(t *testing.T, srv *server) {
	s, _ := srv.open(t)
	must(t, s.Ping(ctx))
	must(t, s.Close())
	if err := s.Ping(ctx); err == nil || !strings.HasPrefix(err.Error(), "postgres store: ping") {
		t.Fatalf("Ping after Close = %v, want the ping error", err)
	}
}

// A replica still on the binary before v3 re-approves a consent with its own statement, which sets
// approved_at but not records_lifetime_at; its scopes followed the old rule, so the mark must not
// survive (#363).
func anOlderBinarysReapprovalUnmarksTheConsent(t *testing.T, srv *server) {
	s, db := srv.open(t)
	// Later or earlier than the mark: a replica's clock may lag, and only equality keeps it.
	for i, skew := range []time.Duration{time.Second, -time.Second} {
		k := store.ConsentKey{Issuer: "https://idp.example/v2.0", Subject: fmt.Sprintf("tid:alice-%d", i), ClientID: "c", Redirect: "https://app.example/cb", Resource: "https://mcp.example.com/mcp"}
		must(t, s.RememberConsent(ctx, store.Consent{Key: k, Scopes: []string{"mcp"}, ApprovedAt: t0, ExpiresAt: t0.Add(time.Hour), RecordsLifetime: true}))
		reapproved := t0.Add(skew)
		_, err := srv.conn(t, db).Exec(ctx, `INSERT INTO consents (issuer, subject, client_id, redirect, resource, scopes, approved_at, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		ON CONFLICT (issuer, subject, client_id, redirect, resource) DO UPDATE SET
			scopes = excluded.scopes, approved_at = excluded.approved_at, expires_at = excluded.expires_at`,
			k.Issuer, k.Subject, k.ClientID, k.Redirect, k.Resource, []string{"mcp", "offline_access"}, reapproved, t0.Add(time.Hour))
		must(t, err)
		if got, err := s.Consent(ctx, k); err != nil || got.RecordsLifetime || !got.ApprovedAt.Equal(reapproved) {
			t.Fatalf("consent after an older binary's re-approval %v off = %+v, %v; want it unmarked", skew, got, err)
		}
	}
}

// Empty IdP tokens are stored as none (store.Grant: "Nil when there are none"), as the SQLite
// adapter stores them, whether they come with the grant or with a rotation.
func emptyIdPTokensReadBackAsNone(t *testing.T, srv *server) {
	s, _ := srv.open(t)
	g := grant("g", "tid:a")
	g.IdPTokens = []byte{}
	_, err := s.CreateGrant(ctx, g)
	must(t, err)
	if got, err := s.Grant(ctx, "g"); err != nil || got.IdPTokens != nil {
		t.Fatalf("after CreateGrant: IdP tokens %#v, %v; want nil", got.IdPTokens, err)
	}
	old := store.RefreshToken{Hash: sha256.Sum256([]byte("old")), GrantID: "g", ClientID: "c", CreatedAt: t0, IdleExpiresAt: t0.Add(time.Hour)}
	must(t, s.PutRefreshToken(ctx, old))
	must(t, s.SetIdPTokens(ctx, "g", []byte("sealed")))
	next := store.RefreshToken{Hash: sha256.Sum256([]byte("next")), GrantID: "g", ClientID: "c", CreatedAt: t0, IdleExpiresAt: t0.Add(time.Hour)}
	must(t, s.RotateRefreshToken(ctx, store.RotateRequest{Old: old.Hash, Next: next, IdPTokens: []byte{}, Now: t0}))
	if got, err := s.Grant(ctx, "g"); err != nil || got.IdPTokens != nil {
		t.Fatalf("after a rotation with empty IdP tokens: %#v, %v; want nil", got.IdPTokens, err)
	}
}

// aConsent is one remembered consent of tid:b, for the tests that check a new epoch forgets it.
var aConsent = store.Consent{Key: store.ConsentKey{Issuer: "i", Subject: "tid:b", ClientID: "c", Redirect: "r", Resource: "u"},
	Scopes: []string{"mcp"}, ApprovedAt: t0, ExpiresAt: t0.Add(time.Hour)}

// copyOf takes a pg_dump of database db, and restoreCopy puts it back with pg_restore, as an
// operator's backup and restore would, while the stores stay open.
func copyOf(t *testing.T, srv *server, db string) []byte {
	t.Helper()
	return srv.Exec(t, nil, "pg_dump", "--format=custom", "--dbname="+db)
}

func restoreCopy(t *testing.T, srv *server, db string, dump []byte) {
	t.Helper()
	srv.Exec(t, dump, "pg_restore", "--clean", "--if-exists", "--dbname="+db)
}

// A restore from a copy older than what both replicas saw committed: the first to check starts a new
// epoch and forgets the remembered consents, the other adopts it, and neither reports the restore
// again. The epoch goes up by one.
func aRestoreStartsOneEpochAcrossReplicas(t *testing.T, srv *server) {
	a, db := srv.open(t)
	b := srv.openOn(t, db)
	must(t, b.RememberConsent(ctx, aConsent))
	dump := copyOf(t, srv, db)
	_, err := a.CreateGrant(ctx, grant("ga", "tid:a"))
	must(t, err)
	_, err = b.CreateGrant(ctx, grant("gb", "tid:b"))
	must(t, err)
	for name, s := range map[string]*Store{"A": a, "B": b} {
		if restored, epoch, err := s.CheckRestore(ctx); err != nil || restored || epoch != 1 {
			t.Fatalf("%s before the restore: restored=%v epoch=%d, %v; want epoch 1, no restore", name, restored, epoch, err)
		}
	}
	restoreCopy(t, srv, db, dump)

	firstRestored, firstEpoch, err := a.CheckRestore(ctx)
	must(t, err)
	secondRestored, secondEpoch, err := b.CheckRestore(ctx)
	must(t, err)
	if !firstRestored || firstEpoch != 2 || secondRestored || secondEpoch != 2 {
		t.Fatalf("A restored=%v epoch=%d, B restored=%v epoch=%d; want A to start epoch 2 and B to adopt it",
			firstRestored, firstEpoch, secondRestored, secondEpoch)
	}
	if _, err := b.Consent(ctx, aConsent.Key); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("the consent from the copy after the restore: %v, want it forgotten", err)
	}
	for name, s := range map[string]*Store{"A": a, "B": b} {
		if restored, epoch, err := s.CheckRestore(ctx); err != nil || restored || epoch != 2 {
			t.Fatalf("%s after the restore: restored=%v epoch=%d, %v; want epoch 2 and no second restore", name, restored, epoch, err)
		}
	}
	if g, err := a.CreateGrant(ctx, grant("after", "tid:a")); err != nil || g.Epoch != 2 {
		t.Fatalf("a grant after the restore: %+v, %v; want epoch 2", g, err)
	}
}

// A replica whose first check comes after the restore still starts the new epoch: it has seen the
// epoch since Open.
func aReplicasFirstCheckFindsARestore(t *testing.T, srv *server) {
	s, db := srv.open(t)
	dump := copyOf(t, srv, db)
	_, err := s.CreateGrant(ctx, grant("g", "tid:a"))
	must(t, err)
	restoreCopy(t, srv, db, dump)
	if restored, epoch, err := s.CheckRestore(ctx); err != nil || !restored || epoch != 2 {
		t.Fatalf("the first check after a restore: restored=%v epoch=%d, %v; want epoch 2 started", restored, epoch, err)
	}
}

// After a crash the sequence may lose values no transaction committed (postgresql.org/docs/current/
// functions-sequence.html): the mark holds only committed values, so that is no restore. No API
// loses a sequence value, so setval stands in for the crash.
func aValueLostInACrashIsNoRestore(t *testing.T, s0 *server) {
	s, db := s0.open(t)
	_, err := s.CreateGrant(ctx, grant("g", "tid:a"))
	must(t, err)
	c := s0.conn(t, db)
	var committed int64
	must(t, c.QueryRow(ctx, "SELECT last_value FROM store_writes").Scan(&committed))
	if _, _, err := s.CheckRestore(ctx); err != nil { // the replica sees the values taken so far
		t.Fatal(err)
	}
	tx, err := c.Begin(ctx)
	must(t, err)
	for range 3 {
		_, err = tx.Exec(ctx, "SELECT nextval('store_writes')")
		must(t, err)
	}
	must(t, tx.Rollback(ctx))
	if restored, _, err := s.CheckRestore(ctx); err != nil || restored {
		t.Fatalf("with uncommitted values taken: restored=%v, %v", restored, err)
	}
	_, err = c.Exec(ctx, "SELECT setval('store_writes', $1)", committed) // the crash loses them
	must(t, err)
	if restored, epoch, err := s.CheckRestore(ctx); err != nil || restored || epoch != 1 {
		t.Fatalf("after losing uncommitted values: restored=%v epoch=%d, %v; want no restore", restored, epoch, err)
	}
}

// Checks while the same replica writes never find a restore: the mark is read before the sequence.
func concurrentWritesAreNoRestore(t *testing.T, srv *server) {
	s, _ := srv.open(t)
	done := make(chan struct{})
	var wg sync.WaitGroup
	for w := range 4 {
		wg.Go(func() {
			for i := 0; ; i++ {
				select {
				case <-done:
					return
				default:
				}
				_ = s.SpendLogin(ctx, sha256.Sum256(fmt.Appendf(nil, "%d-%d", w, i)), t0, t0.Add(time.Minute))
			}
		})
	}
	defer func() { close(done); wg.Wait() }()
	for range 300 {
		if restored, _, err := s.CheckRestore(ctx); err != nil || restored {
			t.Fatalf("a check during writes: restored=%v, %v; want no restore", restored, err)
		}
	}
}

// new-epoch starts one epoch each time and forgets the remembered consents; a running replica
// adopts it at its next check without reporting a restore of its own.
func newEpochStartsAnEpochEachTimeThatRunningReplicasAdopt(t *testing.T, srv *server) {
	running, db := srv.open(t)
	_, err := running.CreateGrant(ctx, grant("g", "tid:a"))
	must(t, err)
	must(t, running.RememberConsent(ctx, aConsent))
	if _, _, err := running.CheckRestore(ctx); err != nil {
		t.Fatal(err)
	}
	operator := srv.openOn(t, db)
	for want := int64(2); want <= 3; want++ {
		if got, err := operator.NewEpoch(ctx); err != nil || got != want {
			t.Fatalf("NewEpoch = %d, %v; want %d", got, err, want)
		}
	}
	if _, err := running.Consent(ctx, aConsent.Key); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("a consent after new-epoch: %v, want it forgotten", err)
	}
	if restored, epoch, err := running.CheckRestore(ctx); err != nil || restored || epoch != 3 {
		t.Fatalf("the running replica: restored=%v epoch=%d, %v; want it to adopt epoch 3 without a restore", restored, epoch, err)
	}
	old := store.RefreshToken{Hash: sha256.Sum256([]byte("old")), GrantID: "g", ClientID: "c", CreatedAt: t0, IdleExpiresAt: t0.Add(time.Hour)}
	must(t, running.PutRefreshToken(ctx, old))
	if _, err := running.RefreshToken(ctx, old.Hash, t0); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("a refresh token of a grant from epoch 1: %v, want ErrNotFound", err)
	}
}

// Describe, for the startup log, names the host, the database and the TLS mode, never the password:
// verify-full normally, off for a plaintext connection development mode accepted.
func describeNamesTheDatabaseAndItsTLSNeverThePassword(t *testing.T, srv *server) {
	s, db := srv.open(t)
	dsn := strings.Replace(srv.DSN(db), "sslmode=verify-full", "sslmode=disable", 1)
	p, err := Open(bounded(t), Options{DSN: dsn, AllowPlaintext: true})
	must(t, err)
	t.Cleanup(func() { _ = p.Close() })
	for _, tc := range []struct {
		s   *Store
		tls string
	}{{s, "tls=verify-full"}, {p, "tls=off"}} {
		d := tc.s.Describe()
		if !strings.Contains(d, "host=127.0.0.1") || !strings.Contains(d, "dbname="+db) || !strings.Contains(d, tc.tls) ||
			strings.Contains(d, srv.Password) {
			t.Fatalf("Describe() = %q, want host, database and %s, and no password", d, tc.tls)
		}
	}
}

func count(t *testing.T, c *pgx.Conn, table string) (n int) {
	t.Helper()
	must(t, c.QueryRow(ctx, "SELECT count(*) FROM "+pgx.Identifier{table}.Sanitize()).Scan(&n))
	return n
}

func version(t *testing.T, c *pgx.Conn) (v int) {
	t.Helper()
	must(t, c.QueryRow(ctx, "SELECT version FROM schema_version").Scan(&v))
	return v
}

func loadFixture(t *testing.T, c *pgx.Conn, v int) {
	t.Helper()
	script, err := os.ReadFile(fixturePath(v))
	must(t, err)
	if _, err := c.Exec(ctx, string(script)); err != nil {
		t.Fatalf("load fixture v%d: %v", v, err)
	}
}

// schemaOf lists the schema's columns, constraints, indexes and sequences, one line each, sorted.
func schemaOf(t *testing.T, c *pgx.Conn) []string {
	t.Helper()
	rows, err := c.Query(ctx, `
		SELECT 'column ' || table_name || '.' || column_name || ' ' || data_type || ' ' || is_nullable || ' ' ||
			coalesce(column_default, '') || ' ' || is_identity
			FROM information_schema.columns WHERE table_schema = current_schema()
		UNION ALL SELECT 'constraint ' || conrelid::regclass || ' ' || conname || ': ' || pg_get_constraintdef(oid)
			FROM pg_constraint WHERE connamespace = current_schema()::regnamespace
		UNION ALL SELECT 'index ' || indexname || ': ' || indexdef FROM pg_indexes WHERE schemaname = current_schema()
		UNION ALL SELECT 'sequence ' || sequence_name FROM information_schema.sequences WHERE sequence_schema = current_schema()
		ORDER BY 1`)
	must(t, err)
	out, err := pgx.CollectRows(rows, pgx.RowTo[string])
	must(t, err)
	return out
}

// A reuse whose revocation cannot be written fails the call and rolls back: the grant and its user's
// consent to its client survive, and the caller never sees ErrReused for a revocation that did not
// happen.
func aReuseWhoseRevocationFailsReportsTheFailureAndKeepsTheGrant(t *testing.T, srv *server) {
	s, db := srv.open(t)
	if _, err := s.CreateGrant(ctx, grant("g", "tid:alice")); err != nil {
		t.Fatal(err)
	}
	tok := func(n byte) store.RefreshToken {
		return store.RefreshToken{Hash: sha256.Sum256([]byte{n}), GrantID: "g", ClientID: "c", CreatedAt: t0, IdleExpiresAt: t0.Add(time.Hour)}
	}
	consent := store.Consent{Key: store.ConsentKey{Issuer: "https://idp.example/v2.0", Subject: "tid:alice", ClientID: "c",
		Redirect: "http://127.0.0.1/callback", Resource: "https://mcp.example.com/mcp"},
		Scopes: []string{"mcp"}, ApprovedAt: t0, ExpiresAt: t0.Add(24 * time.Hour)}
	must(t, s.RememberConsent(ctx, consent))
	must(t, s.PutRefreshToken(ctx, tok(1)))
	must(t, s.RotateRefreshToken(ctx, store.RotateRequest{Old: tok(1).Hash, Next: tok(2), Now: t0.Add(time.Minute)}))
	if _, err := srv.conn(t, db).Exec(ctx, `CREATE FUNCTION refuse() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'revocation refused by the test'; END $$;
		CREATE TRIGGER refuse BEFORE INSERT ON revocations FOR EACH ROW EXECUTE FUNCTION refuse()`); err != nil {
		t.Fatal(err)
	}
	err := s.RotateRefreshToken(ctx, store.RotateRequest{Old: tok(1).Hash, Next: tok(3), Now: t0.Add(2 * time.Minute)})
	if err == nil || errors.Is(err, store.ErrReused) || !strings.Contains(err.Error(), "revocation refused by the test") {
		t.Fatalf("reuse with a failing revocation = %v, want the trigger's refusal", err)
	}
	if _, err := s.Grant(ctx, "g"); err != nil {
		t.Fatalf("grant after the failed reuse: %v, want it kept", err)
	}
	if _, err := s.Consent(ctx, consent.Key); err != nil {
		t.Fatalf("consent after the failed reuse: %v, want it kept", err)
	}
}
