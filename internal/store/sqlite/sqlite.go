// Package sqlite is the default store adapter (ADR-0007 §2): embedded SQLite through
// modernc.org/sqlite (pure Go), WAL mode, a busy timeout, files with mode 0600, and every write
// in one IMMEDIATE transaction on a single connection, so conditional updates are atomic and
// CreateGrant and RevokeSubject are serialized.
//
// Restore detection (ADR-0007 §9): every write increments a counter in the database, mirrored to a
// file kept next to the keys, outside the backup. At Open, a database behind that file was restored
// from an older copy: the epoch is bumped and refresh tokens of grants from older epochs stop
// working, so users sign in again.
package sqlite

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	_ "modernc.org/sqlite" // registers the "sqlite" driver

	"github.com/byward-dev/byward/internal/store"
)

// DefaultDir is the state directory in the container image (ADR-0007 §6).
const DefaultDir = "/var/lib/byward"

// fileName is the database file inside the state directory; back up this file (with its -wal).
const fileName = "byward.db"

const busyTimeoutMS = 5000

// Options configure Open.
type Options struct {
	// Dir is the state directory, an absolute path (ADR-0007 §6); empty means DefaultDir. It is
	// created with mode 0700 when missing; an unwritable directory fails Open.
	Dir string
	// CounterFile is the absolute path of the write-counter mirror. Keep it outside the backup,
	// next to the keys; if it is backed up and restored together with the database, restores go
	// undetected.
	CounterFile string
}

// Store is the SQLite adapter.
type Store struct {
	db             *sql.DB
	counterFile    string
	restored       bool
	counterMissing bool
	epoch          int64 // set at Open, never changed afterwards
}

var _ store.Store = (*Store)(nil)

// validate is what Open requires of the paths before touching the file system.
func (opts Options) validate() (Options, error) {
	if opts.Dir == "" {
		opts.Dir = DefaultDir
	}
	if !filepath.IsAbs(opts.Dir) || !filepath.IsAbs(opts.CounterFile) {
		return opts, errors.New("sqlite store: the state directory and the counter file must be absolute paths")
	}
	if strings.Contains(opts.Dir, "?") {
		return opts, errors.New("sqlite store: the state directory must not contain '?'")
	}
	if rel, err := filepath.Rel(opts.Dir, opts.CounterFile); err == nil && !strings.HasPrefix(rel, "..") {
		return opts, errors.New("sqlite store: the counter file must be outside the state directory, or a backup of the directory hides restores")
	}
	return opts, nil
}

// CheckPaths catches, without creating or writing anything, the path mistakes that would stop
// Open (for `byward check --offline`): the rules above; the state directory is a directory, or a
// path MkdirAll can create; the database files in it are regular files when present; the counter
// file's directory exists (Open does not create it, unless it is created with the state
// directory); an existing counter file is readable and not corrupt. It is not an exact prediction
// of Open: writability needs a write, and paths with ".." through symlinks are not modelled.
func CheckPaths(opts Options) error {
	opts, err := opts.validate()
	if err != nil {
		return err
	}
	switch fi, err := os.Stat(opts.Dir); {
	case err == nil && !fi.IsDir():
		return fmt.Errorf("sqlite store: state directory %s is not a directory", opts.Dir)
	case err == nil:
		for _, name := range []string{fileName, fileName + "-wal", fileName + "-shm"} {
			f := filepath.Join(opts.Dir, name)
			// Open creates the database through a symlink whose target's directory exists (O_CREATE);
			// SQLite does not do that for its WAL and SHM files.
			if err := regularIfPresent(f, name == fileName); err != nil {
				return fmt.Errorf("sqlite store: database file %w", err)
			}
		}
	case errors.Is(err, os.ErrNotExist) || errors.Is(err, syscall.ENOTDIR):
		if err := creatable(opts.Dir); err != nil {
			return fmt.Errorf("sqlite store: state directory %s cannot be created: %w", opts.Dir, err)
		}
	default:
		return fmt.Errorf("sqlite store: state directory: %w", err)
	}
	dir := filepath.Dir(opts.CounterFile)
	fi, err := os.Stat(dir)
	switch {
	case errors.Is(err, os.ErrNotExist) && within(dir, opts.Dir):
		// Open's MkdirAll of the state directory creates it first; creatable checked that above.
	case errors.Is(err, os.ErrNotExist):
		return fmt.Errorf("sqlite store: the counter file's directory %s does not exist; create it, the store does not", dir)
	case err != nil:
		return fmt.Errorf("sqlite store: counter file directory: %w", err)
	case !fi.IsDir():
		return fmt.Errorf("sqlite store: the counter file's directory %s is not a directory", dir)
	}
	if fi, err := os.Stat(opts.CounterFile); err == nil && !fi.Mode().IsRegular() {
		return fmt.Errorf("sqlite store: counter file %s is not a regular file", opts.CounterFile)
	}
	_, _, err = readCounter(opts.CounterFile)
	return err
}

// regularIfPresent refuses an entry at path that is not a regular file, or a symlink to nothing;
// with creatable, a symlink to a missing file in an existing directory passes, as O_CREATE makes it.
func regularIfPresent(path string, creatable bool) error {
	fi, err := os.Lstat(path)
	switch {
	case errors.Is(err, os.ErrNotExist):
		return nil
	case err != nil:
		return err
	case fi.Mode()&os.ModeSymlink != 0:
		if fi, err = os.Stat(path); err != nil {
			if creatable && targetDirExists(path) {
				return nil
			}
			return fmt.Errorf("%s is a symlink to nothing", path)
		}
	}
	if !fi.Mode().IsRegular() {
		return fmt.Errorf("%s is not a regular file", path)
	}
	return nil
}

// maxLinks bounds the symlink chain targetDirExists follows, as the kernel's own limit does.
const maxLinks = 40

// targetDirExists reports whether the final target of a symlink chain is missing but its directory
// exists, so that O_CREATE can make it; a loop or a longer chain does not count.
func targetDirExists(link string) bool {
	for range maxLinks {
		target, err := os.Readlink(link)
		if err != nil {
			return false
		}
		if !filepath.IsAbs(target) {
			target = filepath.Join(filepath.Dir(link), target)
		}
		fi, err := os.Lstat(target)
		switch {
		case errors.Is(err, os.ErrNotExist):
			dir, err := os.Stat(filepath.Dir(target))
			return err == nil && dir.IsDir()
		case err != nil || fi.Mode()&os.ModeSymlink == 0:
			return false
		}
		link = target
	}
	return false
}

// creatable reports whether os.MkdirAll could create the missing path: walking up to the nearest
// entry that exists, that entry must be a directory (a symlink to one counts; a dangling symlink,
// which Stat reports as missing but MkdirAll cannot replace, does not).
func creatable(path string) error {
	for p := path; ; p = filepath.Dir(p) {
		fi, err := os.Lstat(p)
		switch {
		case errors.Is(err, os.ErrNotExist) || errors.Is(err, syscall.ENOTDIR): // a parent decides
			if parent := filepath.Dir(p); parent == p {
				return nil
			}
			continue
		case err != nil:
			return err
		case fi.Mode()&os.ModeSymlink != 0:
			if fi, err = os.Stat(p); err != nil {
				return fmt.Errorf("%s is a symlink to nothing", p)
			}
		}
		if !fi.IsDir() {
			return fmt.Errorf("%s is not a directory", p)
		}
		return nil
	}
}

// within reports whether path is dir or below it.
func within(dir, path string) bool {
	rel, err := filepath.Rel(dir, path)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

// Open opens (creating if needed) the database in opts.Dir, migrates it and checks for a restore.
func Open(ctx context.Context, opts Options) (*Store, error) {
	opts, err := opts.validate()
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(opts.Dir, 0o700); err != nil {
		return nil, fmt.Errorf("sqlite store: state directory: %w", err)
	}
	if err := probeWritable(opts.Dir); err != nil {
		return nil, err
	}
	path := filepath.Join(opts.Dir, fileName)
	if err := ensureFile(path); err != nil {
		return nil, err
	}
	// A plain path, not a "file:" URI: SQLite would percent-decode a URI and could open a file
	// other than the one ensureFile prepared.
	dsn := path + "?_txlock=immediate" +
		"&_pragma=busy_timeout(" + strconv.Itoa(busyTimeoutMS) + ")" +
		"&_pragma=journal_mode(WAL)&_pragma=synchronous(FULL)&_pragma=foreign_keys(ON)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("sqlite store: open %s: %w", path, err)
	}
	db.SetMaxOpenConns(1)
	s := &Store{db: db, counterFile: opts.CounterFile}
	if err := migrate(ctx, db); err != nil {
		_ = db.Close()
		return nil, err
	}
	if err := s.detectRestore(ctx); err != nil {
		_ = db.Close()
		return nil, err
	}
	return s, nil
}

// Ping checks that the database answers, for the readiness probe (ADR-0021 §10). It waits for the
// one connection, so a long write delays it; give it a deadline.
func (s *Store) Ping(ctx context.Context) error {
	var one int
	if err := s.db.QueryRowContext(ctx, "SELECT 1").Scan(&one); err != nil {
		return fmt.Errorf("sqlite store: ping: %w", err)
	}
	return nil
}

// Close closes the database.
func (s *Store) Close() error { return s.db.Close() }

// write runs fn in one IMMEDIATE transaction, increments the write counter and mirrors it to
// the counter file before the commit. If the mirror cannot be written, nothing is committed, so an
// error always means "not stored". If the commit or the directory sync then fails, the mirror is
// one write ahead and the
// next Open treats the database as restored: users sign in again (fail safe). The single
// connection and the IMMEDIATE lock order every write, so the mirror follows commit order.
func (s *Store) write(ctx context.Context, fn func(*sql.Tx) error) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("sqlite store: begin: %w", err)
	}
	if err := fn(tx); err != nil {
		_ = tx.Rollback()
		return err
	}
	var writes int64
	if err := tx.QueryRowContext(ctx, "UPDATE meta SET value = value + 1 WHERE key = 'writes' RETURNING value").Scan(&writes); err != nil {
		_ = tx.Rollback()
		return fmt.Errorf("sqlite store: write counter: %w", err)
	}
	if err := writeCounter(s.counterFile, writes); err != nil {
		_ = tx.Rollback()
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("sqlite store: commit: %w", err)
	}
	return nil
}

// CreateGrant implements store.Grants.
func (s *Store) CreateGrant(ctx context.Context, g store.Grant) (store.Grant, error) {
	if g.ID == "" || g.ClientID == "" || g.Subject == "" || !g.ExpiresAt.After(g.CreatedAt) {
		return store.Grant{}, store.ErrInvalid
	}
	scopes, err := json.Marshal(nonNil(g.Scopes))
	if err != nil {
		return store.Grant{}, err
	}
	err = s.write(ctx, func(tx *sql.Tx) error {
		var n int
		if err := tx.QueryRowContext(ctx, "SELECT count(*) FROM grants WHERE id = ?", g.ID).Scan(&n); err != nil {
			return err
		}
		if n > 0 {
			return store.ErrExists
		}
		if err := tx.QueryRowContext(ctx, "SELECT count(*) FROM revocations WHERE (subject = ? OR scope = 'all') AND before > ?",
			g.Subject, micros(g.CreatedAt)).Scan(&n); err != nil {
			return err
		}
		if n > 0 {
			return store.ErrRevoked
		}
		_, err := tx.ExecContext(ctx, `INSERT INTO grants
			(id, client_id, subject, issuer, resource, scopes, idp_tokens, created_at, expires_at, epoch)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			g.ID, g.ClientID, g.Subject, g.Issuer, g.Resource, string(scopes), blob(g.IdPTokens),
			micros(g.CreatedAt), micros(g.ExpiresAt), s.epoch)
		return err
	})
	if err != nil {
		return store.Grant{}, err
	}
	g.Epoch = s.epoch
	g.Scopes, g.IdPTokens = cloneStrings(g.Scopes), cloneBytes(g.IdPTokens)
	return g, nil
}

// Grant implements store.Grants.
func (s *Store) Grant(ctx context.Context, id string) (store.Grant, error) {
	var g store.Grant
	var scopes string
	var created, expires int64
	err := s.db.QueryRowContext(ctx, `SELECT id, client_id, subject, issuer, resource, scopes, idp_tokens,
		created_at, expires_at, epoch FROM grants WHERE id = ?`, id).
		Scan(&g.ID, &g.ClientID, &g.Subject, &g.Issuer, &g.Resource, &scopes, &g.IdPTokens, &created, &expires, &g.Epoch)
	if errors.Is(err, sql.ErrNoRows) {
		return store.Grant{}, store.ErrNotFound
	}
	if err != nil {
		return store.Grant{}, fmt.Errorf("sqlite store: grant: %w", err)
	}
	if err := json.Unmarshal([]byte(scopes), &g.Scopes); err != nil {
		return store.Grant{}, fmt.Errorf("sqlite store: grant scopes: %w", err)
	}
	if len(g.Scopes) == 0 {
		g.Scopes = nil // as stored by the caller: nil and empty are written alike
	}
	g.CreatedAt, g.ExpiresAt = fromMicros(created), fromMicros(expires)
	return g, nil
}

// RevokeGrant implements store.Grants.
func (s *Store) RevokeGrant(ctx context.Context, id string, at time.Time) error {
	return s.write(ctx, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, "DELETE FROM grants WHERE id = ?", id)
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n == 0 {
			return store.ErrNotFound
		}
		_, err = tx.ExecContext(ctx, "INSERT INTO revocations (grant_id, subject, before, at) VALUES (?, '', ?, ?)",
			id, micros(at), micros(at))
		return err
	})
}

// UpdateGrant implements store.Grants.
func (s *Store) UpdateGrant(ctx context.Context, id string, expiresAt time.Time) error {
	return s.write(ctx, func(tx *sql.Tx) error {
		var created int64
		err := tx.QueryRowContext(ctx, "SELECT created_at FROM grants WHERE id = ?", id).Scan(&created)
		if errors.Is(err, sql.ErrNoRows) {
			return store.ErrNotFound
		}
		if err != nil {
			return err
		}
		if micros(expiresAt) <= created {
			return store.ErrInvalid
		}
		_, err = tx.ExecContext(ctx, "UPDATE grants SET expires_at = ? WHERE id = ?", micros(expiresAt), id)
		return err
	})
}

// RevokeSubject implements store.Grants.
func (s *Store) RevokeSubject(ctx context.Context, subject string, before, at time.Time) error {
	if subject == "" {
		return store.ErrInvalid
	}
	return s.write(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, "DELETE FROM grants WHERE subject = ? AND created_at < ?", subject, micros(before)); err != nil {
			return err
		}
		_, err := tx.ExecContext(ctx, "INSERT INTO revocations (grant_id, subject, before, at) VALUES ('', ?, ?, ?)",
			subject, micros(before), micros(at))
		return err
	})
}

// RevokeAll implements store.Grants.
func (s *Store) RevokeAll(ctx context.Context, before, at time.Time) error {
	return s.write(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, "DELETE FROM grants WHERE created_at < ?", micros(before)); err != nil {
			return err
		}
		_, err := tx.ExecContext(ctx, "INSERT INTO revocations (grant_id, subject, scope, before, at) VALUES ('', '', 'all', ?, ?)",
			micros(before), micros(at))
		return err
	})
}

// PutCode implements store.Codes.
func (s *Store) PutCode(ctx context.Context, c store.PendingCode) error {
	scopes, err := json.Marshal(nonNil(c.Scopes))
	if err != nil {
		return err
	}
	return s.write(ctx, func(tx *sql.Tx) error {
		if err := mustHaveGrant(ctx, tx, c.GrantID); err != nil {
			return err
		}
		var n int
		if err := tx.QueryRowContext(ctx, "SELECT count(*) FROM codes WHERE grant_id = ?", c.GrantID).Scan(&n); err != nil {
			return err
		}
		if n > 0 {
			return store.ErrExists
		}
		_, err := tx.ExecContext(ctx, `INSERT INTO codes (grant_id, client_id, redirect_uri, code_challenge, scopes, expires_at)
			VALUES (?, ?, ?, ?, ?, ?)`, c.GrantID, c.ClientID, c.RedirectURI, c.CodeChallenge, string(scopes), micros(c.ExpiresAt))
		return err
	})
}

// ConsumeCode implements store.Codes.
func (s *Store) ConsumeCode(ctx context.Context, grantID string, now time.Time) (store.PendingCode, error) {
	var c store.PendingCode
	err := s.write(ctx, func(tx *sql.Tx) error {
		var scopes string
		var expires, consumed int64
		err := tx.QueryRowContext(ctx, `SELECT grant_id, client_id, redirect_uri, code_challenge, scopes, expires_at, consumed
			FROM codes WHERE grant_id = ?`, grantID).
			Scan(&c.GrantID, &c.ClientID, &c.RedirectURI, &c.CodeChallenge, &scopes, &expires, &consumed)
		if errors.Is(err, sql.ErrNoRows) || (err == nil && expires <= micros(now)) {
			return store.ErrNotFound
		}
		if err != nil {
			return err
		}
		if consumed != 0 {
			return store.ErrConsumed
		}
		if err := json.Unmarshal([]byte(scopes), &c.Scopes); err != nil {
			return fmt.Errorf("sqlite store: code scopes: %w", err)
		}
		if len(c.Scopes) == 0 {
			c.Scopes = nil
		}
		c.ExpiresAt = fromMicros(expires)
		_, err = tx.ExecContext(ctx, "UPDATE codes SET consumed = 1 WHERE grant_id = ? AND consumed = 0", grantID)
		return err
	})
	if err != nil {
		return store.PendingCode{}, err
	}
	return c, nil
}

// PutRefreshToken implements store.RefreshTokens.
func (s *Store) PutRefreshToken(ctx context.Context, t store.RefreshToken) error {
	return s.write(ctx, func(tx *sql.Tx) error {
		if err := mustHaveGrant(ctx, tx, t.GrantID); err != nil {
			return err
		}
		var n int
		if err := tx.QueryRowContext(ctx, "SELECT count(*) FROM refresh_tokens WHERE hash = ?", t.Hash[:]).Scan(&n); err != nil {
			return err
		}
		if n > 0 {
			return store.ErrExists
		}
		_, err := tx.ExecContext(ctx, `INSERT INTO refresh_tokens (hash, grant_id, client_id, created_at, idle_expires_at)
			VALUES (?, ?, ?, ?, ?)`, t.Hash[:], t.GrantID, t.ClientID, micros(t.CreatedAt), micros(t.IdleExpiresAt))
		return err
	})
}

// RefreshToken implements store.RefreshTokens. A token whose grant was created in an earlier
// epoch is ErrNotFound: the store was restored since (ADR-0007 §9).
func (s *Store) RefreshToken(ctx context.Context, hash [sha256.Size]byte, now time.Time) (store.RefreshToken, error) {
	var t store.RefreshToken
	var created, idle, epoch int64
	var rotated sql.NullInt64
	err := s.db.QueryRowContext(ctx, `SELECT r.grant_id, r.client_id, r.created_at, r.idle_expires_at, r.rotated_at, g.epoch
		FROM refresh_tokens r JOIN grants g ON g.id = r.grant_id WHERE r.hash = ?`, hash[:]).
		Scan(&t.GrantID, &t.ClientID, &created, &idle, &rotated, &epoch)
	if errors.Is(err, sql.ErrNoRows) || (err == nil && (idle <= micros(now) || epoch < s.epoch)) {
		return store.RefreshToken{}, store.ErrNotFound
	}
	if err != nil {
		return store.RefreshToken{}, fmt.Errorf("sqlite store: refresh token: %w", err)
	}
	t.Hash, t.CreatedAt, t.IdleExpiresAt = hash, fromMicros(created), fromMicros(idle)
	if rotated.Valid {
		t.RotatedAt = fromMicros(rotated.Int64)
	}
	return t, nil
}

// RotateRefreshToken implements store.RefreshTokens: one IMMEDIATE transaction. A reuse commits
// the revocation and still reports ErrReused.
func (s *Store) RotateRefreshToken(ctx context.Context, r store.RotateRequest) error {
	reused := false
	err := s.write(ctx, func(tx *sql.Tx) error {
		var grantID string
		var idle, epoch int64
		var rotated sql.NullInt64
		var successor []byte
		err := tx.QueryRowContext(ctx, `SELECT r.grant_id, r.idle_expires_at, r.rotated_at, r.successor, g.epoch
			FROM refresh_tokens r JOIN grants g ON g.id = r.grant_id WHERE r.hash = ?`, r.Old[:]).
			Scan(&grantID, &idle, &rotated, &successor, &epoch)
		if errors.Is(err, sql.ErrNoRows) || (err == nil && (idle <= micros(r.Now) || epoch < s.epoch)) {
			return store.ErrNotFound
		}
		if err != nil {
			return err
		}
		if r.Next.GrantID != grantID {
			return store.ErrInvalid
		}
		var n int
		if err := tx.QueryRowContext(ctx, "SELECT count(*) FROM refresh_tokens WHERE hash = ?", r.Next.Hash[:]).Scan(&n); err != nil {
			return err
		}
		if n > 0 {
			return store.ErrExists
		}
		rotating := r.Old[:]
		if rotated.Valid {
			// A retry is allowed only for the immediate predecessor of the current token, within
			// Grace of its own rotation.
			var curRotated sql.NullInt64
			err := tx.QueryRowContext(ctx, "SELECT rotated_at FROM refresh_tokens WHERE hash = ?", successor).Scan(&curRotated)
			if errors.Is(err, sql.ErrNoRows) || (err == nil && (curRotated.Valid || r.Now.Sub(fromMicros(rotated.Int64)) >= r.Grace)) {
				reused = true
				if _, err := tx.ExecContext(ctx, "DELETE FROM grants WHERE id = ?", grantID); err != nil {
					return err
				}
				_, err := tx.ExecContext(ctx, "INSERT INTO revocations (grant_id, subject, before, at) VALUES (?, '', ?, ?)",
					grantID, micros(r.Now), micros(r.Now))
				return err
			}
			if err != nil {
				return err
			}
			rotating = successor
			if _, err := tx.ExecContext(ctx, "UPDATE refresh_tokens SET successor = ? WHERE hash = ?", r.Next.Hash[:], r.Old[:]); err != nil {
				return err
			}
		}
		if _, err := tx.ExecContext(ctx, "UPDATE refresh_tokens SET rotated_at = ?, successor = ? WHERE hash = ?",
			micros(r.Now), r.Next.Hash[:], rotating); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO refresh_tokens (hash, grant_id, client_id, created_at, idle_expires_at)
			VALUES (?, ?, ?, ?, ?)`, r.Next.Hash[:], grantID, r.Next.ClientID, micros(r.Next.CreatedAt), micros(r.Next.IdleExpiresAt)); err != nil {
			return err
		}
		if r.IdPTokens != nil {
			if _, err := tx.ExecContext(ctx, "UPDATE grants SET idp_tokens = ? WHERE id = ?", r.IdPTokens, grantID); err != nil {
				return err
			}
		}
		return nil
	})
	if err == nil && reused {
		return store.ErrReused
	}
	return err
}

// Revocations implements store.Revocations.
func (s *Store) Revocations(ctx context.Context) ([]store.Revocation, error) {
	rows, err := s.db.QueryContext(ctx, "SELECT grant_id, subject, scope, before, at FROM revocations ORDER BY at, seq")
	if err != nil {
		return nil, fmt.Errorf("sqlite store: revocations: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []store.Revocation
	for rows.Next() {
		var r store.Revocation
		var scope string
		var before, at int64
		if err := rows.Scan(&r.GrantID, &r.Subject, &scope, &before, &at); err != nil {
			return nil, err
		}
		r.All = scope == "all"
		r.Before, r.At = fromMicros(before), fromMicros(at)
		out = append(out, r)
	}
	return out, rows.Err()
}

// Collect implements store.Collector.
func (s *Store) Collect(ctx context.Context, now time.Time) error {
	n := micros(now)
	return s.write(ctx, func(tx *sql.Tx) error {
		for _, q := range []struct {
			sql string
			arg int64
		}{
			{"DELETE FROM grants WHERE expires_at <= ?", n}, // cascades to codes and refresh tokens
			{"DELETE FROM codes WHERE expires_at <= ?", n},
			{"DELETE FROM refresh_tokens WHERE idle_expires_at <= ?", n},
			{"DELETE FROM revocations WHERE at <= ?", micros(now.Add(-store.RevocationRetention))},
			{"DELETE FROM clients WHERE expires_at <= ?", n},
			{"DELETE FROM clients WHERE used_at IS NULL AND created_at <= ?", micros(now.Add(-store.UnusedClientLifetime))},
		} {
			if _, err := tx.ExecContext(ctx, q.sql, q.arg); err != nil {
				return fmt.Errorf("sqlite store: collect: %w", err)
			}
		}
		return nil
	})
}

func mustHaveGrant(ctx context.Context, tx *sql.Tx, id string) error {
	var n int
	if err := tx.QueryRowContext(ctx, "SELECT count(*) FROM grants WHERE id = ?", id).Scan(&n); err != nil {
		return err
	}
	if n == 0 {
		return store.ErrNotFound
	}
	return nil
}

// Times are stored as UTC microseconds (store.go: adapters may keep microsecond precision);
// integers compare correctly whatever zone the caller used.
func micros(t time.Time) int64     { return t.UnixMicro() }
func fromMicros(v int64) time.Time { return time.UnixMicro(v).UTC() }
func nonNil(s []string) []string   { return append([]string{}, s...) }
func cloneStrings(s []string) []string {
	if s == nil {
		return nil
	}
	return append([]string{}, s...)
}
func cloneBytes(b []byte) []byte {
	if b == nil {
		return nil
	}
	return append([]byte{}, b...)
}

// blob keeps nil as SQL NULL rather than an empty blob.
func blob(b []byte) any {
	if b == nil {
		return nil
	}
	return b
}

// probeWritable fails early, naming the directory, when the proxy cannot write its state.
func probeWritable(dir string) error {
	f, err := os.CreateTemp(dir, ".write-probe-*")
	if err != nil {
		return fmt.Errorf("sqlite store: state directory %s is not writable: %w", dir, err)
	}
	name := f.Name()
	_ = f.Close()
	return os.Remove(name)
}

// ensureFile creates the database file with mode 0600, or tightens an existing one, together with
// leftover -wal and -shm files. SQLite creates new -wal and -shm files with the database file's
// mode.
func ensureFile(path string) error {
	for _, side := range []string{path + "-wal", path + "-shm"} {
		if err := os.Chmod(side, 0o600); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("sqlite store: %s: %w", side, err)
		}
	}
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600) //nolint:gosec // G304: the operator's state directory
	if err != nil {
		return fmt.Errorf("sqlite store: database file %s: %w", path, err)
	}
	if err := f.Chmod(0o600); err != nil {
		_ = f.Close()
		return fmt.Errorf("sqlite store: database file %s: %w", path, err)
	}
	return f.Close()
}

// CreateClient implements store.Clients.
func (s *Store) CreateClient(ctx context.Context, c store.Client, max int) error {
	if c.ID == "" || len(c.Metadata) == 0 || !c.UsedAt.IsZero() || !c.ExpiresAt.After(c.CreatedAt) {
		return store.ErrInvalid
	}
	return s.write(ctx, func(tx *sql.Tx) error {
		var n int
		if err := tx.QueryRowContext(ctx, "SELECT count(*) FROM clients WHERE id = ?", c.ID).Scan(&n); err != nil {
			return err
		}
		if n > 0 {
			return store.ErrExists
		}
		if max > 0 {
			if err := tx.QueryRowContext(ctx, "SELECT count(*) FROM clients WHERE expires_at > ?", micros(c.CreatedAt)).Scan(&n); err != nil {
				return err
			}
			if n >= max {
				return store.ErrFull
			}
		}
		_, err := tx.ExecContext(ctx, "INSERT INTO clients (id, metadata, created_at, expires_at) VALUES (?, ?, ?, ?)",
			c.ID, c.Metadata, micros(c.CreatedAt), micros(c.ExpiresAt))
		return err
	})
}

// Client implements store.Clients.
func (s *Store) Client(ctx context.Context, id string) (store.Client, error) {
	var c store.Client
	var created, expires int64
	var used sql.NullInt64
	err := s.db.QueryRowContext(ctx, "SELECT id, metadata, created_at, used_at, expires_at FROM clients WHERE id = ?", id).
		Scan(&c.ID, &c.Metadata, &created, &used, &expires)
	if errors.Is(err, sql.ErrNoRows) {
		return store.Client{}, store.ErrNotFound
	}
	if err != nil {
		return store.Client{}, fmt.Errorf("sqlite store: client: %w", err)
	}
	c.CreatedAt, c.ExpiresAt = fromMicros(created), fromMicros(expires)
	if used.Valid {
		c.UsedAt = fromMicros(used.Int64)
	}
	return c, nil
}

// UseClient implements store.Clients. A use that changes nothing (already used, and not extending
// by at least minExtension) does not write, so it costs no write-counter update.
func (s *Store) UseClient(ctx context.Context, id string, now, expires time.Time, minExtension time.Duration) error {
	c, err := s.Client(ctx, id)
	if err != nil {
		return err
	}
	extend := !expires.Before(c.ExpiresAt.Add(minExtension))
	if !c.UsedAt.IsZero() && !extend {
		return nil
	}
	return s.write(ctx, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, `UPDATE clients SET used_at = coalesce(used_at, ?),
			expires_at = CASE WHEN ? >= expires_at + ? THEN ? ELSE expires_at END WHERE id = ?`,
			micros(now), micros(expires), minExtension.Microseconds(), micros(expires), id)
		if err != nil {
			return err
		}
		if n, err := res.RowsAffected(); err != nil || n == 0 {
			return store.ErrNotFound
		}
		return nil
	})
}
