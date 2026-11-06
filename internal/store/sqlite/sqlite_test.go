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

func grant(id, subject string) store.Grant {
	return store.Grant{ID: id, ClientID: "c", Subject: subject, Issuer: "https://idp.example/v2.0",
		Resource: "https://mcp.example.com/mcp", Scopes: []string{"mcp"}, CreatedAt: t0, ExpiresAt: t0.Add(24 * time.Hour)}
}

func open(t *testing.T, dir, counter string) *Store {
	t.Helper()
	s, err := Open(ctx, Options{Dir: dir, CounterFile: counter})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

// The lock test the conformance suite cannot replace (#50): two stores on one database file, as two
// processes would be, race CreateGrant against RevokeSubject. IMMEDIATE transactions serialize them,
// so no covered grant survives and no call fails with SQLITE_BUSY.
func TestCreateGrantAndRevokeSubjectAreSerializedAcrossConnections(t *testing.T) {
	dir, counter := t.TempDir(), filepath.Join(t.TempDir(), "writes")
	a, b := open(t, dir, counter), open(t, dir, counter)
	const rounds = 100
	before := t0.Add(time.Hour)
	var wg sync.WaitGroup
	for i := range rounds {
		subject := fmt.Sprintf("tid:u%d", i)
		start := make(chan struct{})
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
	}
	wg.Wait()
	for i := range rounds {
		id := fmt.Sprintf("tid:u%d", i)
		if _, err := a.Grant(ctx, id); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("grant %s survived its subject's cut-off: %v", id, err)
		}
	}
}

func TestDatabaseFilesAreOwnerOnly(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state") // created by Open
	s := open(t, dir, filepath.Join(t.TempDir(), "writes"))
	if _, err := s.CreateGrant(ctx, grant("g1", "tid:a")); err != nil {
		t.Fatal(err)
	}
	if fi, err := os.Stat(dir); err != nil || fi.Mode().Perm() != 0o700 {
		t.Fatalf("state directory: %v %v, want 0700", fi.Mode().Perm(), err)
	}
	for _, name := range []string{FileName, FileName + "-wal", FileName + "-shm"} {
		fi, err := os.Stat(filepath.Join(dir, name))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if fi.Mode().Perm() != 0o600 {
			t.Errorf("%s has mode %v, want 0600", name, fi.Mode().Perm())
		}
	}
}

func TestExistingLooseDatabaseFileIsTightened(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, FileName), nil, 0o644); err != nil { //nolint:gosec // G306: the loose mode under test
		t.Fatal(err)
	}
	open(t, dir, filepath.Join(t.TempDir(), "writes"))
	if fi, _ := os.Stat(filepath.Join(dir, FileName)); fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v, want 0600", fi.Mode().Perm())
	}
}

func TestOpenRefusesBadPaths(t *testing.T) {
	cases := map[string]Options{
		"relative state directory": {Dir: "state", CounterFile: filepath.Join(t.TempDir(), "w")},
		"relative counter file":    {Dir: t.TempDir(), CounterFile: "writes"},
		"query character in path":  {Dir: filepath.Join(t.TempDir(), "a?b"), CounterFile: filepath.Join(t.TempDir(), "w")},
	}
	for name, opts := range cases {
		t.Run(name, func(t *testing.T) {
			if s, err := Open(ctx, opts); err == nil {
				_ = s.Close()
				t.Fatal("accepted")
			}
		})
	}
}

func TestUnwritableStateDirectoryFailsOpen(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root writes anywhere")
	}
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })
	_, err := Open(ctx, Options{Dir: dir, CounterFile: filepath.Join(t.TempDir(), "w")})
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
	_ = s.Close()
	again := open(t, dir, counter)
	if again.RestoreDetected() || again.Epoch() != 1 {
		t.Fatalf("reopen: restored=%v epoch=%d, want a normal start", again.RestoreDetected(), again.Epoch())
	}
	if _, err := again.Grant(ctx, "g1"); err != nil {
		t.Fatalf("grant lost across reopen: %v", err)
	}
}

func TestNewerSchemaIsRefused(t *testing.T) {
	dir := t.TempDir()
	db := rawDB(t, dir)
	if _, err := db.Exec(fmt.Sprintf("PRAGMA user_version = %d", SchemaVersion+1)); err != nil {
		t.Fatal(err)
	}
	_ = db.Close()
	_, err := Open(ctx, Options{Dir: dir, CounterFile: filepath.Join(t.TempDir(), "w")})
	if err == nil || !strings.Contains(err.Error(), "newer than this binary") {
		t.Fatalf("err = %v, want the downgrade refusal", err)
	}
}

// ADR-0007 §9: a database restored from an older copy is behind the counter mirror; Open bumps the
// epoch, refresh tokens from older epochs stop working, and grants made afterwards work.
func TestRestoredDatabaseBumpsTheEpochAndRefusesOldRefreshTokens(t *testing.T) {
	dir, counter := t.TempDir(), filepath.Join(t.TempDir(), "writes")
	s := open(t, dir, counter)
	if _, err := s.CreateGrant(ctx, grant("old", "tid:a")); err != nil {
		t.Fatal(err)
	}
	old := store.RefreshToken{Hash: sha256.Sum256([]byte("old")), GrantID: "old", ClientID: "c", CreatedAt: t0, IdleExpiresAt: t0.Add(time.Hour)}
	if err := s.PutRefreshToken(ctx, old); err != nil {
		t.Fatal(err)
	}
	_ = s.Close()
	backup := copyDB(t, dir) // the operator's backup

	s = open(t, dir, counter)
	if _, err := s.CreateGrant(ctx, grant("after-backup", "tid:a")); err != nil {
		t.Fatal(err)
	}
	_ = s.Close()
	restoreDB(t, backup, dir) // restore by file copy, counter file untouched

	r := open(t, dir, counter)
	if !r.RestoreDetected() || r.Epoch() != 2 {
		t.Fatalf("restored=%v epoch=%d, want a detected restore and epoch 2", r.RestoreDetected(), r.Epoch())
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
	_ = r.Close()

	// The restore is accepted once: the next start is normal.
	next := open(t, dir, counter)
	if next.RestoreDetected() || next.Epoch() != 2 {
		t.Fatalf("restart after the restore: restored=%v epoch=%d, want a normal start at epoch 2", next.RestoreDetected(), next.Epoch())
	}
}

func TestMissingCounterFileIsAFirstStart(t *testing.T) {
	dir, counter := t.TempDir(), filepath.Join(t.TempDir(), "writes")
	s := open(t, dir, counter)
	if _, err := s.CreateGrant(ctx, grant("g1", "tid:a")); err != nil {
		t.Fatal(err)
	}
	_ = s.Close()
	if err := os.Remove(counter); err != nil {
		t.Fatal(err)
	}
	again := open(t, dir, counter)
	if again.RestoreDetected() {
		t.Fatal("a missing counter file was taken for a restore")
	}
	if _, err := os.Stat(counter); err != nil {
		t.Fatalf("counter file not recreated: %v", err)
	}
}

func TestCorruptCounterFileFailsOpen(t *testing.T) {
	counter := filepath.Join(t.TempDir(), "writes")
	if err := os.WriteFile(counter, []byte("not a number"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := Open(ctx, Options{Dir: t.TempDir(), CounterFile: counter})
	if err == nil || !strings.Contains(err.Error(), "corrupt") {
		t.Fatalf("err = %v, want the corrupt-counter refusal", err)
	}
}

// Migration fixtures (ADR-0024 §11): one per released schema version, each migrated to the current
// schema and read back through the store.
func TestEverySchemaVersionHasAFixture(t *testing.T) {
	for v := 1; v <= SchemaVersion; v++ {
		if _, err := os.Stat(fixturePath(v)); err != nil {
			t.Errorf("schema v%d has no fixture %s: add one when releasing a schema version", v, fixturePath(v))
		}
	}
}

func TestFixturesMigrateToTheCurrentSchema(t *testing.T) {
	for v := 1; v <= SchemaVersion; v++ {
		t.Run(fmt.Sprintf("v%d", v), func(t *testing.T) {
			dir := t.TempDir()
			script, err := os.ReadFile(fixturePath(v))
			if err != nil {
				t.Fatal(err)
			}
			db := rawDB(t, dir)
			if _, err := db.Exec(string(script)); err != nil {
				t.Fatalf("load fixture: %v", err)
			}
			_ = db.Close()

			s := open(t, dir, filepath.Join(t.TempDir(), "writes"))
			var got int
			if err := s.db.QueryRow("PRAGMA user_version").Scan(&got); err != nil || got != SchemaVersion {
				t.Fatalf("schema after Open = v%d (%v), want v%d", got, err, SchemaVersion)
			}
			g, err := s.Grant(ctx, "fixture-grant")
			if err != nil || g.Subject != "tid:fixture" || g.ClientID != "fixture-client" || string(g.IdPTokens) != "sea" {
				t.Fatalf("fixture grant = %+v, %v", g, err)
			}
			if _, err := s.RefreshToken(ctx, sha256.Sum256([]byte("fixture-refresh")), t0); err != nil {
				t.Fatalf("fixture refresh token: %v", err)
			}
			if _, err := s.ConsumeCode(ctx, "fixture-grant", t0); err != nil {
				t.Fatalf("fixture code: %v", err)
			}
		})
	}
}

func fixturePath(v int) string { return filepath.Join("testdata", "schema", fmt.Sprintf("v%d.sql", v)) }

// rawDB opens the database file in dir without the store, for setting up fixtures.
func rawDB(t *testing.T, dir string) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", "file:"+filepath.Join(dir, FileName))
	if err != nil {
		t.Fatal(err)
	}
	return db
}

// copyDB copies the database file (the store is closed, so the WAL is checkpointed).
func copyDB(t *testing.T, dir string) string {
	t.Helper()
	backup := filepath.Join(t.TempDir(), FileName)
	copyFile(t, filepath.Join(dir, FileName), backup)
	return backup
}

func restoreDB(t *testing.T, backup, dir string) {
	t.Helper()
	for _, suffix := range []string{"-wal", "-shm"} {
		_ = os.Remove(filepath.Join(dir, FileName+suffix))
	}
	copyFile(t, backup, filepath.Join(dir, FileName))
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
