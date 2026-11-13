//go:build integration

package postgres

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/byward-dev/byward/internal/store"
	"github.com/byward-dev/byward/internal/store/storetest"
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
		t.Run(img.name, func(t *testing.T) {
			srv := startPostgres(t, img.image)
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
				{"CreateGrantRetriesPastACutOffCommittedDuringIt", createGrantRetriesPastACutOffCommittedDuringIt},
				{"AConcurrentInsertOfTheSameIDIsErrExists", aConcurrentInsertOfTheSameIDIsErrExists},
				{"MigrationsRunOneAtATime", migrationsRunOneAtATime},
				{"NewerSchemaIsRefused", newerSchemaIsRefused},
				{"FixturesMigrateToTheCurrentSchemaKeepingTheirData", fixturesMigrateToTheCurrentSchemaKeepingTheirData},
				{"FailedMigrationChangesNothing", failedMigrationChangesNothing},
				{"TheEpochIsReadOnEveryUse", theEpochIsReadOnEveryUse},
				{"EveryWriteTakesAValueFromTheWriteSequence", everyWriteTakesAValueFromTheWriteSequence},
				{"CollectDropsExpiredSpentLogins", collectDropsExpiredSpentLogins},
				{"OneReplicaCollectsAtATime", oneReplicaCollectsAtATime},
				{"VerifyFullChecksTheCAAndTheHostName", verifyFullChecksTheCAAndTheHostName},
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
func createGrantRetriesPastACutOffCommittedDuringIt(t *testing.T, srv *server) {
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
	db := srv.database(t)
	holder := srv.conn(t, db)
	_, err := holder.Exec(ctx, "SELECT pg_advisory_lock($1)", migrateLock)
	must(t, err)
	done := make(chan error, 1)
	go func() {
		s, err := Open(bounded(t), Options{DSN: srv.dsn(db)})
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

// What every fixture holds (testdata/schema/vN.sql) and must still hold after migrating.
var (
	fixtureCreated = time.Date(2026, 11, 6, 12, 0, 0, 0, time.UTC)
	fixtureExpires = time.Date(2099, 1, 1, 0, 0, 0, 0, time.UTC)
	fixtureGrant   = store.Grant{
		ID: "fixture-grant", ClientID: "fixture-client", Subject: "tid:fixture", Issuer: "https://idp.example/v2.0",
		Resource: "https://mcp.example.com/mcp", Scopes: []string{"mcp"}, IdPTokens: []byte("sea"),
		CreatedAt: fixtureCreated, ExpiresAt: fixtureExpires, Epoch: 1,
	}
	fixtureCode = store.PendingCode{
		GrantID: "fixture-grant", ClientID: "fixture-client", RedirectURI: "http://127.0.0.1:33418/callback",
		CodeChallenge: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM", Scopes: []string{"mcp"}, ExpiresAt: fixtureExpires,
	}
	fixtureRefresh = store.RefreshToken{
		Hash: sha256.Sum256([]byte("fixture-refresh")), GrantID: "fixture-grant", ClientID: "fixture-client",
		CreatedAt: fixtureCreated, IdleExpiresAt: fixtureExpires,
	}
	fixtureRevocations = []store.Revocation{
		{GrantID: "fixture-revoked", Before: fixtureCreated, At: fixtureCreated},
		{Subject: "tid:fixture-revoked-subject", Before: fixtureCreated, At: fixtureCreated.Add(time.Second)},
		{All: true, Before: fixtureCreated, At: fixtureCreated.Add(2 * time.Second)},
	}
	fixtureClient = store.Client{ID: "fixture-dcr-client", Metadata: []byte(`{"client_name":"Fixture"}`), CreatedAt: fixtureCreated,
		UsedAt: fixtureCreated.Add(time.Second), ExpiresAt: fixtureExpires}
	fixtureConsent = store.Consent{Key: store.ConsentKey{Issuer: "https://idp.example/v2.0", Subject: "tid:fixture", ClientID: "fixture-client",
		Redirect: "http://127.0.0.1/cb", Resource: "https://mcp.example.com/mcp"}, Scopes: []string{"mcp"}, ApprovedAt: fixtureCreated, ExpiresAt: fixtureExpires}
)

// Migration fixtures (ADR-0024 §11): each released schema version, with data, migrated to the
// current schema and read back through the store, in UTC.
func fixturesMigrateToTheCurrentSchemaKeepingTheirData(t *testing.T, srv *server) {
	_, fresh := srv.open(t)
	want := schemaOf(t, srv.conn(t, fresh))
	for v := 1; v <= schemaVersion(); v++ {
		t.Run(fmt.Sprintf("v%d", v), func(t *testing.T) {
			db := srv.database(t)
			loadFixture(t, srv.conn(t, db), v)
			s := srv.openOn(t, db)

			if got := schemaOf(t, srv.conn(t, db)); !reflect.DeepEqual(got, want) {
				t.Fatalf("migrated schema differs from a fresh one:\n got %q\nwant %q", got, want)
			}
			if g, err := s.Grant(ctx, fixtureGrant.ID); err != nil || !reflect.DeepEqual(g, fixtureGrant) {
				t.Fatalf("grant = %+v, %v\nwant %+v", g, err, fixtureGrant)
			}
			if r, err := s.RefreshToken(ctx, fixtureRefresh.Hash, fixtureCreated); err != nil || !reflect.DeepEqual(r, fixtureRefresh) {
				t.Fatalf("refresh token = %+v, %v\nwant %+v", r, err, fixtureRefresh)
			}
			if revs, err := s.Revocations(ctx); err != nil || !reflect.DeepEqual(revs, fixtureRevocations) {
				t.Fatalf("revocations = %+v, %v\nwant %+v", revs, err, fixtureRevocations)
			}
			if c, err := s.Client(ctx, fixtureClient.ID); err != nil || !reflect.DeepEqual(c, fixtureClient) {
				t.Fatalf("client = %+v, %v\nwant %+v", c, err, fixtureClient)
			}
			if c, err := s.Consent(ctx, fixtureConsent.Key); err != nil || !reflect.DeepEqual(c, fixtureConsent) {
				t.Fatalf("consent = %+v, %v\nwant %+v", c, err, fixtureConsent)
			}
			if err := s.SpendLogin(ctx, sha256.Sum256([]byte("fixture-login")), fixtureCreated, fixtureExpires); !errors.Is(err, store.ErrConsumed) {
				t.Fatalf("spending the fixture login: %v, want ErrConsumed", err)
			}
			checkRotatedFixtureToken(t, s)
			if c, err := s.ConsumeCode(ctx, fixtureGrant.ID, fixtureCreated); err != nil || !reflect.DeepEqual(c, fixtureCode) {
				t.Fatalf("code = %+v, %v\nwant %+v", c, err, fixtureCode)
			}
		})
	}
}

// checkRotatedFixtureToken: the fixture holds a token rotated 1 s after creation to
// fixture-refresh. A retry with it inside the grace window must rotate the successor, not count as
// reuse.
func checkRotatedFixtureToken(t *testing.T, s *Store) {
	t.Helper()
	oldHash := sha256.Sum256([]byte("fixture-refresh-old"))
	want := store.RefreshToken{Hash: oldHash, GrantID: fixtureGrant.ID, ClientID: "fixture-client",
		CreatedAt: fixtureCreated, IdleExpiresAt: fixtureExpires, RotatedAt: fixtureCreated.Add(time.Second)}
	if got, err := s.RefreshToken(ctx, oldHash, fixtureCreated); err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("rotated fixture token = %+v, %v\nwant %+v", got, err, want)
	}
	retry := fixtureCreated.Add(2 * time.Second)
	next := store.RefreshToken{Hash: sha256.Sum256([]byte("fixture-refresh-next")), GrantID: fixtureGrant.ID, ClientID: "fixture-client",
		CreatedAt: retry, IdleExpiresAt: fixtureExpires}
	if err := s.RotateRefreshToken(ctx, store.RotateRequest{Old: oldHash, Next: next, Now: retry, Grace: 30 * time.Second}); err != nil {
		t.Fatalf("retry with the rotated fixture token: %v (its successor link was lost)", err)
	}
	if got, err := s.RefreshToken(ctx, fixtureRefresh.Hash, retry); err != nil || !got.RotatedAt.Equal(retry) {
		t.Fatalf("the successor %+v, %v: want it rotated at %v by the retry", got, err, retry)
	}
}

// A migration that fails leaves the database exactly as it was: its DDL and the version bump are
// one transaction, and the binary before it still opens the database.
func failedMigrationChangesNothing(t *testing.T, srv *server) {
	db := srv.database(t)
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
	if g, err := srv.openOn(t, db).Grant(ctx, fixtureGrant.ID); err != nil || !reflect.DeepEqual(g, fixtureGrant) {
		t.Fatalf("data after a failed migration = %+v, %v; want %+v", g, err, fixtureGrant)
	}
}

// The epoch is read in SQL on every use (ADR-0007 §9): a bump by anyone counts at once, without a
// reopen, for refresh tokens of older grants and for new grants.
func theEpochIsReadOnEveryUse(t *testing.T, srv *server) {
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
func everyWriteTakesAValueFromTheWriteSequence(t *testing.T, srv *server) {
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

// An expired spent login already counts as absent, so storetest cannot see it collected: the row
// count shows it.
func collectDropsExpiredSpentLogins(t *testing.T, srv *server) {
	s, db := srv.open(t)
	must(t, s.SpendLogin(ctx, sha256.Sum256([]byte("l")), t0, t0.Add(time.Minute)))
	c := srv.conn(t, db)
	must(t, s.Collect(ctx, t0.Add(30*time.Second)))
	if n := count(t, c, "spent_logins"); n != 1 {
		t.Fatalf("before expiry: %d spent logins, want 1", n)
	}
	must(t, s.Collect(ctx, t0.Add(time.Minute)))
	if n := count(t, c, "spent_logins"); n != 0 {
		t.Fatalf("at expiry: %d spent logins, want 0", n)
	}
}

// While another replica collects (it holds the collect lock), Collect returns at once having
// deleted nothing; once it is done, Collect deletes.
func oneReplicaCollectsAtATime(t *testing.T, srv *server) {
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
func verifyFullChecksTheCAAndTheHostName(t *testing.T, srv *server) {
	db := srv.database(t)
	other := filepath.Join(t.TempDir(), "other-ca.pem")
	must(t, os.WriteFile(other, newCA(t, "another CA").certPEM, 0o600))

	wrongCA := *srv
	wrongCA.caFile = other
	_, err := Open(bounded(t), Options{DSN: wrongCA.dsn(db)})
	if _, ok := errors.AsType[x509.UnknownAuthorityError](err); !ok {
		t.Fatalf("another CA: err = %v, want an unknown authority", err)
	}

	// The certificate names 127.0.0.1 only. As an IP, ::1 would match no SAN either.
	wrongHost := *srv
	wrongHost.host = "localhost"
	_, err = Open(bounded(t), Options{DSN: wrongHost.dsn(db)})
	if _, ok := errors.AsType[x509.HostnameError](err); !ok {
		t.Fatalf("another host name: err = %v, want a host name mismatch", err)
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
