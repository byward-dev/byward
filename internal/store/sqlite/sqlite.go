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
	"time"

	_ "modernc.org/sqlite" // registers the "sqlite" driver

	"github.com/corker/mcp-authproxy/internal/store"
)

// DefaultDir is the state directory in the container image (ADR-0007 §6).
const DefaultDir = "/var/lib/mcp-authproxy"

// FileName is the database file inside the state directory.
const FileName = "mcp-authproxy.db"

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

// Open opens (creating if needed) the database in opts.Dir, migrates it and checks for a restore.
func Open(ctx context.Context, opts Options) (*Store, error) {
	if opts.Dir == "" {
		opts.Dir = DefaultDir
	}
	if !filepath.IsAbs(opts.Dir) || !filepath.IsAbs(opts.CounterFile) {
		return nil, errors.New("sqlite store: the state directory and the counter file must be absolute paths")
	}
	if strings.Contains(opts.Dir, "?") {
		return nil, errors.New("sqlite store: the state directory must not contain '?'")
	}
	if rel, err := filepath.Rel(opts.Dir, opts.CounterFile); err == nil && !strings.HasPrefix(rel, "..") {
		return nil, errors.New("sqlite store: the counter file must be outside the state directory, or a backup of the directory hides restores")
	}
	if err := os.MkdirAll(opts.Dir, 0o700); err != nil {
		return nil, fmt.Errorf("sqlite store: state directory: %w", err)
	}
	if err := probeWritable(opts.Dir); err != nil {
		return nil, err
	}
	path := filepath.Join(opts.Dir, FileName)
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
	if err := s.init(ctx); err != nil {
		_ = db.Close()
		return nil, err
	}
	return s, nil
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
		if err := tx.QueryRowContext(ctx, "SELECT count(*) FROM revocations WHERE subject = ? AND before > ?",
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
	err := s.db.QueryRowContext(ctx, `SELECT r.grant_id, r.client_id, r.created_at, r.idle_expires_at, g.epoch
		FROM refresh_tokens r JOIN grants g ON g.id = r.grant_id WHERE r.hash = ?`, hash[:]).
		Scan(&t.GrantID, &t.ClientID, &created, &idle, &epoch)
	if errors.Is(err, sql.ErrNoRows) || (err == nil && (idle <= micros(now) || epoch < s.epoch)) {
		return store.RefreshToken{}, store.ErrNotFound
	}
	if err != nil {
		return store.RefreshToken{}, fmt.Errorf("sqlite store: refresh token: %w", err)
	}
	t.Hash, t.CreatedAt, t.IdleExpiresAt = hash, fromMicros(created), fromMicros(idle)
	return t, nil
}

// Revocations implements store.Revocations.
func (s *Store) Revocations(ctx context.Context) ([]store.Revocation, error) {
	rows, err := s.db.QueryContext(ctx, "SELECT grant_id, subject, before, at FROM revocations ORDER BY at, seq")
	if err != nil {
		return nil, fmt.Errorf("sqlite store: revocations: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []store.Revocation
	for rows.Next() {
		var r store.Revocation
		var before, at int64
		if err := rows.Scan(&r.GrantID, &r.Subject, &before, &at); err != nil {
			return nil, err
		}
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
