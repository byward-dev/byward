package sqlite

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/corker/mcp-authproxy/internal/store"
)

var (
	ctx = context.Background()
	t0  = time.Date(2026, 11, 6, 12, 0, 0, 0, time.UTC)
)

// bounded is the context for Open: with a single connection, a statement issued outside the open
// transaction waits forever; the deadline turns that into a quick failure.
func bounded(t *testing.T) context.Context {
	c, cancel := context.WithTimeout(ctx, 10*time.Second)
	t.Cleanup(cancel)
	return c
}

func grant(id, subject string) store.Grant {
	return store.Grant{ID: id, ClientID: "c", Subject: subject, Issuer: "https://idp.example/v2.0",
		Resource: "https://mcp.example.com/mcp", Scopes: []string{"mcp"}, CreatedAt: t0, ExpiresAt: t0.Add(24 * time.Hour)}
}

func open(t *testing.T, dir, counter string) *Store {
	t.Helper()
	s, err := Open(bounded(t), Options{Dir: dir, CounterFile: counter})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

// The lock test the conformance suite cannot replace (#50): two stores on one database file, as two
// processes would be, race CreateGrant against RevokeSubject one pair at a time. IMMEDIATE
// transactions serialize each pair, so no covered grant survives.
func TestRevokeSubjectRacingCreateGrantAcrossProcessesLeavesNoCoveredGrant(t *testing.T) {
	dir, counter := t.TempDir(), filepath.Join(t.TempDir(), "writes")
	a, b := open(t, dir, counter), open(t, dir, counter)
	const rounds = 100
	before := t0.Add(time.Hour)
	for i := range rounds {
		subject := fmt.Sprintf("tid:u%d", i)
		start := make(chan struct{})
		var wg sync.WaitGroup
		wg.Go(func() {
			<-start
			if _, err := a.CreateGrant(ctx, grant(subject, subject)); err != nil && !errors.Is(err, store.ErrRevoked) {
				t.Errorf("CreateGrant %s: %v", subject, err)
			}
		})
		wg.Go(func() {
			<-start
			if err := b.RevokeSubject(ctx, subject, before, before); err != nil {
				t.Errorf("RevokeSubject %s: %v", subject, err)
			}
		})
		close(start)
		wg.Wait() // only the two calls of this round compete, well inside the busy timeout
		if _, err := a.Grant(ctx, subject); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("grant %s survived its subject's cut-off: %v", subject, err)
		}
	}
}

func TestDatabaseFilesAreOwnerOnly(t *testing.T) {
	files := []string{fileName, fileName + "-wal", fileName + "-shm"}
	cases := []struct {
		name  string
		setup func(t *testing.T, dir string)
	}{
		{"created by Open", func(*testing.T, string) {}},
		{"left behind with mode 0644", func(t *testing.T, dir string) {
			must(t, os.MkdirAll(dir, 0o700))
			for _, f := range files {
				must(t, os.WriteFile(filepath.Join(dir, f), nil, 0o644)) //nolint:gosec // G306: the loose mode under test
			}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), "state")
			tc.setup(t, dir)
			s := open(t, dir, filepath.Join(t.TempDir(), "writes"))
			if _, err := s.CreateGrant(ctx, grant("g1", "tid:a")); err != nil {
				t.Fatal(err)
			}
			fi, err := os.Stat(dir)
			if err != nil {
				t.Fatal(err)
			}
			if fi.Mode().Perm() != 0o700 {
				t.Fatalf("state directory mode %v, want 0700", fi.Mode().Perm())
			}
			for _, f := range files {
				fi, err := os.Stat(filepath.Join(dir, f))
				if err != nil {
					t.Fatalf("%s: %v", f, err)
				}
				if fi.Mode().Perm() != 0o600 {
					t.Errorf("%s has mode %v, want 0600", f, fi.Mode().Perm())
				}
			}
		})
	}
}

func TestOpenRefusesBadPaths(t *testing.T) {
	cases := []struct {
		name string
		opts func(dir, other string) Options // dir and other are distinct temporary directories
		want string
	}{
		{"relative state directory", func(_, o string) Options { return Options{Dir: "state", CounterFile: filepath.Join(o, "w")} }, "must be absolute"},
		{"relative counter file", func(d, _ string) Options { return Options{Dir: d, CounterFile: "writes"} }, "must be absolute"},
		{"? in the path", func(d, o string) Options {
			return Options{Dir: filepath.Join(d, "a?b"), CounterFile: filepath.Join(o, "w")}
		}, "must not contain"},
		{"counter file inside the state directory", func(d, _ string) Options { return Options{Dir: d, CounterFile: filepath.Join(d, "writes")} }, "outside the state directory"},
		{"counter file deeper inside", func(d, _ string) Options { return Options{Dir: d, CounterFile: filepath.Join(d, "sub", "writes")} }, "outside the state directory"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s, err := Open(bounded(t), tc.opts(t.TempDir(), t.TempDir()))
			if err == nil {
				must(t, s.Close())
				t.Fatal("accepted")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want %q", err, tc.want)
			}
		})
	}
}

// A '%' is an ordinary character: the database must be the file ensureFile prepared, not a
// percent-decoded other path (regression: the DSN was a file: URI).
func TestPercentInThePathOpensThatFile(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "x%2541")
	s := open(t, dir, filepath.Join(t.TempDir(), "writes"))
	if _, err := s.CreateGrant(ctx, grant("g1", "tid:a")); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(filepath.Join(dir, fileName))
	if err != nil || fi.Size() == 0 {
		t.Fatalf("database not in %s: %v, %v", dir, fi, err)
	}
	if _, err := os.Stat(filepath.Join(filepath.Dir(dir), "x%41")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("a percent-decoded path was used: %v", err)
	}
}

func TestEmptyDirMeansTheDefaultStateDirectory(t *testing.T) {
	if _, err := os.Stat(DefaultDir); err == nil || os.Geteuid() == 0 {
		t.Skip("would use the real " + DefaultDir)
	}
	_, err := Open(bounded(t), Options{CounterFile: filepath.Join(t.TempDir(), "w")})
	// MkdirAll names the first directory it cannot create, which may be a parent of DefaultDir.
	if err == nil || !strings.Contains(err.Error(), "state directory") || !strings.Contains(DefaultDir, strings.TrimSuffix(pathIn(err.Error()), ":")) {
		t.Fatalf("err = %v, want a state-directory error on (a parent of) %s", err, DefaultDir)
	}
}

func TestUnwritableStateDirectoryFailsOpen(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root writes anywhere")
	}
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o500); err != nil { //nolint:gosec // G302: a directory needs x; read-only on purpose
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) }) //nolint:gosec // G302: directory mode, restored for cleanup
	_, err := Open(bounded(t), Options{Dir: dir, CounterFile: filepath.Join(t.TempDir(), "w")})
	if err == nil || !strings.Contains(err.Error(), dir+" is not writable") {
		t.Fatalf("err = %v, want one naming the unwritable directory", err)
	}
}

func TestStateSurvivesReopen(t *testing.T) {
	dir, counter := t.TempDir(), filepath.Join(t.TempDir(), "writes")
	s := open(t, dir, counter)
	if _, err := s.CreateGrant(ctx, grant("g1", "tid:a")); err != nil {
		t.Fatal(err)
	}
	must(t, s.Close())
	again := open(t, dir, counter)
	if again.Startup().Restored || again.Startup().Epoch != 1 {
		t.Fatalf("reopen: restored=%v epoch=%d, want a normal start", again.Startup().Restored, again.Startup().Epoch)
	}
	if _, err := again.Grant(ctx, "g1"); err != nil {
		t.Fatalf("grant lost across reopen: %v", err)
	}
}

func TestNewerSchemaIsRefused(t *testing.T) {
	dir := t.TempDir()
	db := rawDB(t, dir)
	if _, err := db.Exec(fmt.Sprintf("PRAGMA user_version = %d", schemaVersion()+1)); err != nil {
		t.Fatal(err)
	}
	must(t, db.Close())
	_, err := Open(bounded(t), Options{Dir: dir, CounterFile: filepath.Join(t.TempDir(), "w")})
	if err == nil || !strings.Contains(err.Error(), "newer than this binary") {
		t.Fatalf("err = %v, want the downgrade refusal", err)
	}
}

// ADR-0007 §9: a database restored from an older copy is behind the counter mirror; Open bumps the
// epoch, refresh tokens from older epochs stop working, and grants made afterwards work.
func TestRestoredDatabaseStartsANewEpochOnce(t *testing.T) {
	dir, counter := t.TempDir(), filepath.Join(t.TempDir(), "writes")
	s := open(t, dir, counter)
	if _, err := s.CreateGrant(ctx, grant("old", "tid:a")); err != nil {
		t.Fatal(err)
	}
	old := store.RefreshToken{Hash: sha256.Sum256([]byte("old")), GrantID: "old", ClientID: "c", CreatedAt: t0, IdleExpiresAt: t0.Add(time.Hour)}
	if err := s.PutRefreshToken(ctx, old); err != nil {
		t.Fatal(err)
	}
	must(t, s.Close())
	backup := copyDB(t, dir) // the operator's backup

	s = open(t, dir, counter)
	if _, err := s.CreateGrant(ctx, grant("after-backup", "tid:a")); err != nil {
		t.Fatal(err)
	}
	must(t, s.Close())
	restoreDB(t, backup, dir) // restore by file copy, counter file untouched

	r := open(t, dir, counter)
	if !r.Startup().Restored || r.Startup().Epoch != 2 {
		t.Fatalf("restored=%v epoch=%d, want a detected restore and epoch 2", r.Startup().Restored, r.Startup().Epoch)
	}
	if _, err := r.RefreshToken(ctx, old.Hash, t0); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("refresh token from the old epoch: %v, want ErrNotFound", err)
	}
	g, err := r.CreateGrant(ctx, grant("new", "tid:a"))
	if err != nil || g.Epoch != 2 {
		t.Fatalf("new grant: %+v, %v; want epoch 2", g, err)
	}
	fresh := store.RefreshToken{Hash: sha256.Sum256([]byte("new")), GrantID: "new", ClientID: "c", CreatedAt: t0, IdleExpiresAt: t0.Add(time.Hour)}
	if err := r.PutRefreshToken(ctx, fresh); err != nil {
		t.Fatal(err)
	}
	if _, err := r.RefreshToken(ctx, fresh.Hash, t0); err != nil {
		t.Fatalf("refresh token of the new epoch: %v", err)
	}
	must(t, r.Close())

	// The restore is accepted once: the next start is normal.
	next := open(t, dir, counter)
	if next.Startup().Restored || next.Startup().Epoch != 2 {
		t.Fatalf("restart after the restore: restored=%v epoch=%d, want a normal start at epoch 2", next.Startup().Restored, next.Startup().Epoch)
	}
}

// The counter mirror against the database's own counter: only a mirror ahead of the database is a
// restore. One ahead is the crash window of a failed commit, which is treated as a restore on
// purpose (fail safe).
func TestOnlyACounterMirrorAheadOfTheDatabaseIsARestore(t *testing.T) {
	cases := []struct {
		name           string
		mirror         func(writes int64) string // "" removes the file
		restored, gone bool
	}{
		{"missing", func(int64) string { return "" }, false, true},
		{"behind", func(int64) string { return "0\n" }, false, false},
		{"equal", func(w int64) string { return strconv.FormatInt(w, 10) }, false, false},
		{"one ahead", func(w int64) string { return strconv.FormatInt(w+1, 10) }, true, false},
		{"far ahead", func(w int64) string { return strconv.FormatInt(w+1000, 10) }, true, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir, counter := t.TempDir(), filepath.Join(t.TempDir(), "writes")
			s := open(t, dir, counter)
			if _, err := s.CreateGrant(ctx, grant("g1", "tid:a")); err != nil {
				t.Fatal(err)
			}
			writes, _, err := readCounter(counter)
			if err != nil {
				t.Fatal(err)
			}
			must(t, s.Close())
			if m := tc.mirror(writes); m == "" {
				must(t, os.Remove(counter))
			} else {
				must(t, os.WriteFile(counter, []byte(m), 0o600))
			}
			again := open(t, dir, counter)
			if again.Startup().Restored != tc.restored || again.Startup().CounterMissing != tc.gone {
				t.Fatalf("restored=%v counterMissing=%v, want %v %v", again.Startup().Restored, again.Startup().CounterMissing, tc.restored, tc.gone)
			}
			wantEpoch := int64(1)
			if tc.restored {
				wantEpoch = 2
			}
			if again.Startup().Epoch != wantEpoch {
				t.Fatalf("epoch %d, want %d", again.Startup().Epoch, wantEpoch)
			}
			mirror, ok, err := readCounter(counter)
			var dbWrites int64
			must(t, again.db.QueryRow("SELECT value FROM meta WHERE key = 'writes'").Scan(&dbWrites))
			if err != nil || !ok || mirror != dbWrites {
				t.Fatalf("counter file = %d (%v, %v), want it rewritten to the database's %d", mirror, ok, err, dbWrites)
			}
		})
	}
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

// Regression (runtime sweep): an error from a write means nothing was stored. The mirror is written
// before the commit, so a counter path that cannot be written rolls the write back. Replacing the
// counter's directory with a file makes the write fail for root too.
func TestFirstOpenIsANormalStart(t *testing.T) {
	s := open(t, t.TempDir(), filepath.Join(t.TempDir(), "writes"))
	if got := s.Startup(); got != (Startup{Epoch: 1}) {
		t.Fatalf("first open: %+v, want a normal start at epoch 1", got)
	}
}

func TestFailedCounterWriteStoresNothing(t *testing.T) {
	cdir := t.TempDir()
	s := open(t, t.TempDir(), filepath.Join(cdir, "writes"))
	must(t, os.RemoveAll(cdir))
	must(t, os.WriteFile(cdir, nil, 0o600))
	if _, err := s.CreateGrant(ctx, grant("g1", "tid:a")); err == nil {
		t.Fatal("CreateGrant succeeded although the counter file cannot be written")
	}
	if _, err := s.Grant(ctx, "g1"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("the failed write was stored: %v", err)
	}
}

func TestCorruptCounterFileFailsOpen(t *testing.T) {
	for name, content := range map[string]string{"not a number": "not a number", "negative": "-1", "empty": ""} {
		t.Run(name, func(t *testing.T) {
			counter := filepath.Join(t.TempDir(), "writes")
			must(t, os.WriteFile(counter, []byte(content), 0o600))
			_, err := Open(bounded(t), Options{Dir: t.TempDir(), CounterFile: counter})
			if err == nil || !strings.Contains(err.Error(), "corrupt") {
				t.Fatalf("err = %v, want the corrupt-counter refusal", err)
			}
		})
	}
}

// Migration fixtures (ADR-0024 §11): one per released schema version, each migrated to the current
// schema and read back through the store.
func TestEverySchemaVersionHasAFixture(t *testing.T) {
	for v := 1; v <= schemaVersion(); v++ {
		if _, err := os.Stat(fixturePath(v)); err != nil {
			t.Errorf("schema v%d has no fixture %s: add one when releasing a schema version", v, fixturePath(v))
		}
	}
}

// What every fixture holds (testdata/schema/vN.sql) and must still hold after migrating.
var (
	fixtureCreated = time.UnixMicro(1793966400000000).UTC()
	fixtureExpires = time.UnixMicro(4070908800000000).UTC()
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
	}
)

func TestFixturesMigrateToTheCurrentSchemaKeepingTheirData(t *testing.T) {
	want := schemaOf(t, open(t, t.TempDir(), filepath.Join(t.TempDir(), "w")).db)
	for v := 1; v <= schemaVersion(); v++ {
		t.Run(fmt.Sprintf("v%d", v), func(t *testing.T) {
			dir := t.TempDir()
			loadFixture(t, dir, v)
			s := open(t, dir, filepath.Join(t.TempDir(), "writes"))

			if got := schemaOf(t, s.db); !reflect.DeepEqual(got, want) {
				t.Fatalf("migrated schema differs from a fresh one:\n got %q\nwant %q", got, want)
			}
			var litestream int
			must(t, s.db.QueryRow("SELECT count(*) FROM sqlite_master WHERE name = '_litestream_lock'").Scan(&litestream))
			if litestream != 1 {
				t.Fatal("Litestream's table was removed")
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
			if c, err := s.ConsumeCode(ctx, fixtureGrant.ID, fixtureCreated); err != nil || !reflect.DeepEqual(c, fixtureCode) {
				t.Fatalf("code = %+v, %v\nwant %+v", c, err, fixtureCode)
			}
		})
	}
}

// A migration that fails leaves the database exactly as it was: its DDL and the version bump are
// one transaction.
func TestFailedMigrationChangesNothing(t *testing.T) {
	dir := t.TempDir()
	loadFixture(t, dir, schemaVersion())
	before := schemaOf(t, rawDB(t, dir))

	saved := migrations
	migrations = append(append([]string{}, saved...), "CREATE TABLE half_done (a); UPDATE grants SET subject = 'x'; SELECT * FROM no_such_table;")
	t.Cleanup(func() { migrations = saved })

	s, err := Open(bounded(t), Options{Dir: dir, CounterFile: filepath.Join(t.TempDir(), "w")})
	if err == nil {
		_ = s.Close()
		t.Fatal("Open succeeded although a migration fails")
	}
	if want := fmt.Sprintf("migrate to v%d", len(saved)+1); !strings.Contains(err.Error(), want) {
		t.Fatalf("Open failed before the injected migration ran: %v (want %q)", err, want)
	}
	db := rawDB(t, dir)
	var v int
	must(t, db.QueryRow("PRAGMA user_version").Scan(&v))
	if v != len(saved) {
		t.Fatalf("user_version = %d after a failed migration, want %d", v, len(saved))
	}
	if after := schemaOf(t, db); !reflect.DeepEqual(after, before) {
		t.Fatalf("schema changed by a failed migration:\n%q\n%q", before, after)
	}
	must(t, db.Close())
	migrations = saved // the old binary again: it must still open the database and read its data
	old := open(t, dir, filepath.Join(t.TempDir(), "w2"))
	if g, err := old.Grant(ctx, fixtureGrant.ID); err != nil || !reflect.DeepEqual(g, fixtureGrant) {
		t.Fatalf("data after a failed migration = %+v, %v; want %+v", g, err, fixtureGrant)
	}
}

// schemaOf lists the schema objects (type, name, SQL), without Litestream's.
func schemaOf(t *testing.T, db *sql.DB) []string {
	t.Helper()
	rows, err := db.Query("SELECT type, name, coalesce(sql, '') FROM sqlite_master WHERE name NOT LIKE '_litestream%' ORDER BY type, name")
	must(t, err)
	defer func() { _ = rows.Close() }()
	var out []string
	for rows.Next() {
		var typ, name, text string
		must(t, rows.Scan(&typ, &name, &text))
		out = append(out, typ+" "+name+": "+strings.Join(strings.Fields(text), " "))
	}
	must(t, rows.Err())
	return out
}

func loadFixture(t *testing.T, dir string, v int) {
	t.Helper()
	script, err := os.ReadFile(fixturePath(v))
	must(t, err)
	db := rawDB(t, dir)
	if _, err := db.Exec(string(script)); err != nil {
		t.Fatalf("load fixture v%d: %v", v, err)
	}
	must(t, db.Close())
}

func fixturePath(v int) string { return filepath.Join("testdata", "schema", fmt.Sprintf("v%d.sql", v)) }

// rawDB opens the database file in dir without the store, for setting up fixtures.
func rawDB(t *testing.T, dir string) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", filepath.Join(dir, fileName))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

// copyDB copies the database file (the store is closed, so the WAL is checkpointed).
func copyDB(t *testing.T, dir string) string {
	t.Helper()
	backup := filepath.Join(t.TempDir(), fileName)
	copyFile(t, filepath.Join(dir, fileName), backup)
	return backup
}

func restoreDB(t *testing.T, backup, dir string) {
	t.Helper()
	for _, suffix := range []string{"-wal", "-shm"} {
		_ = os.Remove(filepath.Join(dir, fileName+suffix))
	}
	copyFile(t, backup, filepath.Join(dir, fileName))
}

func copyFile(t *testing.T, from, to string) {
	t.Helper()
	src, err := os.Open(from) //nolint:gosec // G304: test files
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = src.Close() }()
	dst, err := os.OpenFile(to, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600) //nolint:gosec // G304: test files
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.Copy(dst, src); err != nil {
		t.Fatal(err)
	}
	if err := dst.Close(); err != nil {
		t.Fatal(err)
	}
}

// pathIn returns the first absolute path in an error message.
func pathIn(msg string) string {
	for _, f := range strings.Fields(msg) {
		if strings.HasPrefix(f, "/") {
			return f
		}
	}
	return ""
}
