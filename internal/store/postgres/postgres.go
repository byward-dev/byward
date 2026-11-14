// Package postgres is the store adapter for more than one replica (ADR-0007 §2, amended for #227):
// PostgreSQL 15 or later through pgx. Every write is one SERIALIZABLE transaction, retried on a
// serialization failure, a deadlock or a unique violation, so the checks and the writes of each
// method are atomic across replicas without per-key locks. Collect runs READ COMMITTED behind a
// try-lock, so one replica collects at a time.
//
// Every write transaction also takes a value from the store_writes sequence, which restore
// detection reads (ADR-0007 §9). The epoch is read in SQL on every use, never cached, so a bump by
// any replica counts at once on all of them.
package postgres

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/byward-dev/byward/internal/store"
)

// Options configure Open.
type Options struct {
	// DSN is the connection string, a URL or key=value pairs as pgx parses them (pool settings such
	// as pool_max_conns included). It holds the password: it is never logged nor quoted in errors.
	DSN string
	// AllowPlaintext accepts a DSN without verify-full TLS, for development mode only; the caller
	// logs it as a relaxation.
	AllowPlaintext bool
}

// Store is the PostgreSQL adapter.
type Store struct {
	pool *pgxpool.Pool
	mark mark // this replica's view of store_writes and the epoch, for restore detection
}

var _ store.Store = (*Store)(nil)

// Open parses the DSN, refuses anything but verify-full TLS (unless AllowPlaintext), connects and
// migrates the schema.
func Open(ctx context.Context, opts Options) (*Store, error) {
	cfg, err := parseDSN(opts.DSN, opts.AllowPlaintext)
	if err != nil {
		return nil, err
	}
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("postgres store: %w", err)
	}
	if err := migrate(ctx, pool); err != nil {
		pool.Close()
		return nil, err
	}
	s := &Store{pool: pool}
	// The epoch at Open is the first one this replica has seen: a restore found by its first check
	// starts a new epoch, unless another replica already has.
	if err := pool.QueryRow(ctx, epochSQL).Scan(&s.mark.epoch); err != nil {
		pool.Close()
		return nil, fmt.Errorf("postgres store: epoch: %w", err)
	}
	return s, nil
}

// Ping checks that the database answers, for the readiness probe (ADR-0021 §10).
func (s *Store) Ping(ctx context.Context) error {
	if err := s.pool.Ping(ctx); err != nil {
		return fmt.Errorf("postgres store: ping: %w", err)
	}
	return nil
}

// Describe names the database for the startup log: host, port, database and TLS, never the DSN.
func (s *Store) Describe() string {
	c := s.pool.Config().ConnConfig
	return fmt.Sprintf("host=%s port=%d dbname=%s tls=%s", c.Host, c.Port, c.Database, tlsMode(&c.Config))
}

// tlsMode is how the first host's connection is protected: verify-full, unverified (encrypted, the
// server not checked; development mode only) or off.
func tlsMode(c *pgconn.Config) string {
	switch {
	case c.TLSConfig == nil:
		return "off"
	case c.TLSConfig.InsecureSkipVerify:
		return "unverified"
	}
	return "verify-full"
}

// Close closes the pool, waiting for connections in use to be returned.
func (s *Store) Close() error {
	s.pool.Close()
	return nil
}

// epochSQL is the store's current epoch, read in each statement that needs it (ADR-0007 §9).
const epochSQL = "(SELECT value FROM meta WHERE key = 'epoch')"

// CreateGrant implements store.Grants. SERIALIZABLE makes the cut-off check and the insert one
// step against a concurrent RevokeSubject or RevokeAll on any replica (store.Grants.CreateGrant).
func (s *Store) CreateGrant(ctx context.Context, g store.Grant) (store.Grant, error) {
	if g.ID == "" || g.ClientID == "" || g.Subject == "" || !g.ExpiresAt.After(g.CreatedAt) {
		return store.Grant{}, store.ErrInvalid
	}
	var epoch int64
	err := s.write(ctx, func(tx pgx.Tx) error {
		if err := mustNotExist(ctx, tx, "SELECT EXISTS (SELECT 1 FROM grants WHERE id = $1)", g.ID); err != nil {
			return err
		}
		var revoked bool
		if err := tx.QueryRow(ctx, "SELECT EXISTS (SELECT 1 FROM revocations WHERE (subject = $1 OR scope = 'all') AND before > $2)",
			g.Subject, ts(g.CreatedAt)).Scan(&revoked); err != nil {
			return err
		}
		if revoked {
			return store.ErrRevoked
		}
		return tx.QueryRow(ctx, `INSERT INTO grants
			(id, client_id, subject, issuer, resource, scopes, idp_tokens, created_at, expires_at, epoch)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, `+epochSQL+`) RETURNING epoch`,
			g.ID, g.ClientID, g.Subject, g.Issuer, g.Resource, nonNil(g.Scopes), nilIfEmpty(g.IdPTokens),
			ts(g.CreatedAt), ts(g.ExpiresAt)).Scan(&epoch)
	})
	if err != nil {
		return store.Grant{}, err
	}
	g.Epoch = epoch
	g.Scopes, g.IdPTokens = cloneStrings(g.Scopes), cloneBytes(g.IdPTokens)
	return g, nil
}

// Grant implements store.Grants.
func (s *Store) Grant(ctx context.Context, id string) (store.Grant, error) {
	var g store.Grant
	err := s.pool.QueryRow(ctx, `SELECT id, client_id, subject, issuer, resource, scopes, idp_tokens,
		created_at, expires_at, epoch FROM grants WHERE id = $1`, id).
		Scan(&g.ID, &g.ClientID, &g.Subject, &g.Issuer, &g.Resource, &g.Scopes, &g.IdPTokens, &g.CreatedAt, &g.ExpiresAt, &g.Epoch)
	if errors.Is(err, pgx.ErrNoRows) {
		return store.Grant{}, store.ErrNotFound
	}
	if err != nil {
		return store.Grant{}, fmt.Errorf("postgres store: grant: %w", err)
	}
	g.Scopes = nilIfEmpty(g.Scopes)
	g.CreatedAt, g.ExpiresAt = g.CreatedAt.UTC(), g.ExpiresAt.UTC()
	return g, nil
}

// RevokeGrant implements store.Grants.
func (s *Store) RevokeGrant(ctx context.Context, id string, at time.Time) error {
	return s.write(ctx, func(tx pgx.Tx) error {
		if err := forgetGrant(ctx, tx, id); err != nil {
			return err
		}
		tag, err := tx.Exec(ctx, "DELETE FROM grants WHERE id = $1", id)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return store.ErrNotFound
		}
		_, err = tx.Exec(ctx, "INSERT INTO revocations (grant_id, subject, before, at) VALUES ($1, '', $2, $2)", id, ts(at))
		return err
	})
}

// UpdateGrant implements store.Grants.
func (s *Store) UpdateGrant(ctx context.Context, id string, expiresAt time.Time) error {
	return s.write(ctx, func(tx pgx.Tx) error {
		var created time.Time
		err := tx.QueryRow(ctx, "SELECT created_at FROM grants WHERE id = $1", id).Scan(&created)
		if errors.Is(err, pgx.ErrNoRows) {
			return store.ErrNotFound
		}
		if err != nil {
			return err
		}
		if !ts(expiresAt).After(created) {
			return store.ErrInvalid
		}
		_, err = tx.Exec(ctx, "UPDATE grants SET expires_at = $1 WHERE id = $2", ts(expiresAt), id)
		return err
	})
}

// SetIdPTokens implements store.Grants.
func (s *Store) SetIdPTokens(ctx context.Context, id string, sealed []byte) error {
	if len(sealed) == 0 {
		return store.ErrInvalid
	}
	return s.write(ctx, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, "UPDATE grants SET idp_tokens = $1 WHERE id = $2", sealed, id)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return store.ErrNotFound
		}
		return nil
	})
}

// RevokeSubject implements store.Grants.
func (s *Store) RevokeSubject(ctx context.Context, subject string, before, at time.Time) error {
	if subject == "" {
		return store.ErrInvalid
	}
	return s.write(ctx, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, "DELETE FROM grants WHERE subject = $1 AND created_at < $2", subject, ts(before)); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, "DELETE FROM consents WHERE subject = $1 AND approved_at < $2", subject, ts(before)); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, "INSERT INTO revocations (grant_id, subject, before, at) VALUES ('', $1, $2, $3)",
			subject, ts(before), ts(at))
		return err
	})
}

// RevokeAll implements store.Grants.
func (s *Store) RevokeAll(ctx context.Context, before, at time.Time) error {
	return s.write(ctx, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, "DELETE FROM grants WHERE created_at < $1", ts(before)); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, "DELETE FROM consents WHERE approved_at < $1", ts(before)); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, "INSERT INTO revocations (grant_id, subject, scope, before, at) VALUES ('', '', 'all', $1, $2)",
			ts(before), ts(at))
		return err
	})
}

// PutCode implements store.Codes.
func (s *Store) PutCode(ctx context.Context, c store.PendingCode) error {
	return s.write(ctx, func(tx pgx.Tx) error {
		if err := mustHaveGrant(ctx, tx, c.GrantID); err != nil {
			return err
		}
		if err := mustNotExist(ctx, tx, "SELECT EXISTS (SELECT 1 FROM codes WHERE grant_id = $1)", c.GrantID); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `INSERT INTO codes (grant_id, client_id, redirect_uri, code_challenge, scopes, expires_at)
			VALUES ($1, $2, $3, $4, $5, $6)`, c.GrantID, c.ClientID, c.RedirectURI, c.CodeChallenge, nonNil(c.Scopes), ts(c.ExpiresAt))
		return err
	})
}

// ConsumeCode implements store.Codes.
func (s *Store) ConsumeCode(ctx context.Context, grantID string, now time.Time) (store.PendingCode, error) {
	var c store.PendingCode
	err := s.write(ctx, func(tx pgx.Tx) error {
		var consumed bool
		err := tx.QueryRow(ctx, `SELECT grant_id, client_id, redirect_uri, code_challenge, scopes, expires_at, consumed
			FROM codes WHERE grant_id = $1`, grantID).
			Scan(&c.GrantID, &c.ClientID, &c.RedirectURI, &c.CodeChallenge, &c.Scopes, &c.ExpiresAt, &consumed)
		if errors.Is(err, pgx.ErrNoRows) || (err == nil && !c.ExpiresAt.After(ts(now))) {
			return store.ErrNotFound
		}
		if err != nil {
			return err
		}
		if consumed {
			return store.ErrConsumed
		}
		_, err = tx.Exec(ctx, "UPDATE codes SET consumed = true WHERE grant_id = $1 AND NOT consumed", grantID)
		return err
	})
	if err != nil {
		return store.PendingCode{}, err
	}
	c.Scopes, c.ExpiresAt = nilIfEmpty(c.Scopes), c.ExpiresAt.UTC()
	return c, nil
}

// PutRefreshToken implements store.RefreshTokens.
func (s *Store) PutRefreshToken(ctx context.Context, t store.RefreshToken) error {
	return s.write(ctx, func(tx pgx.Tx) error {
		if err := mustHaveGrant(ctx, tx, t.GrantID); err != nil {
			return err
		}
		if err := mustNotExist(ctx, tx, "SELECT EXISTS (SELECT 1 FROM refresh_tokens WHERE hash = $1)", t.Hash[:]); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `INSERT INTO refresh_tokens (hash, grant_id, client_id, created_at, idle_expires_at)
			VALUES ($1, $2, $3, $4, $5)`, t.Hash[:], t.GrantID, t.ClientID, ts(t.CreatedAt), ts(t.IdleExpiresAt))
		return err
	})
}

// RefreshToken implements store.RefreshTokens. A token whose grant was created in an earlier epoch
// is ErrNotFound: the store was restored since (ADR-0007 §9).
func (s *Store) RefreshToken(ctx context.Context, hash [sha256.Size]byte, now time.Time) (store.RefreshToken, error) {
	var t store.RefreshToken
	var rotated *time.Time
	var stale bool
	err := s.pool.QueryRow(ctx, `SELECT r.grant_id, r.client_id, r.created_at, r.idle_expires_at, r.rotated_at,
		g.epoch < `+epochSQL+` FROM refresh_tokens r JOIN grants g ON g.id = r.grant_id WHERE r.hash = $1`, hash[:]).
		Scan(&t.GrantID, &t.ClientID, &t.CreatedAt, &t.IdleExpiresAt, &rotated, &stale)
	if errors.Is(err, pgx.ErrNoRows) || (err == nil && (!t.IdleExpiresAt.After(ts(now)) || stale)) {
		return store.RefreshToken{}, store.ErrNotFound
	}
	if err != nil {
		return store.RefreshToken{}, fmt.Errorf("postgres store: refresh token: %w", err)
	}
	t.Hash, t.CreatedAt, t.IdleExpiresAt = hash, t.CreatedAt.UTC(), t.IdleExpiresAt.UTC()
	if rotated != nil {
		t.RotatedAt = rotated.UTC()
	}
	return t, nil
}

// RotateRefreshToken implements store.RefreshTokens: one SERIALIZABLE transaction. A reuse commits
// the revocation and still reports ErrReused.
func (s *Store) RotateRefreshToken(ctx context.Context, r store.RotateRequest) error {
	reused := false
	err := s.write(ctx, func(tx pgx.Tx) error {
		reused = false // set again by each attempt
		var grantID string
		var idle time.Time
		var rotated *time.Time
		var successor []byte
		var stale bool
		err := tx.QueryRow(ctx, `SELECT r.grant_id, r.idle_expires_at, r.rotated_at, r.successor, g.epoch < `+epochSQL+`
			FROM refresh_tokens r JOIN grants g ON g.id = r.grant_id WHERE r.hash = $1`, r.Old[:]).
			Scan(&grantID, &idle, &rotated, &successor, &stale)
		if errors.Is(err, pgx.ErrNoRows) || (err == nil && (!idle.After(ts(r.Now)) || stale)) {
			return store.ErrNotFound
		}
		if err != nil {
			return err
		}
		if r.Next.GrantID != grantID {
			return store.ErrInvalid
		}
		if err := mustNotExist(ctx, tx, "SELECT EXISTS (SELECT 1 FROM refresh_tokens WHERE hash = $1)", r.Next.Hash[:]); err != nil {
			return err
		}
		rotating := r.Old[:]
		if rotated != nil {
			// A retry is allowed only for the immediate predecessor of the current token, within
			// Grace of its own rotation.
			var curRotated *time.Time
			err := tx.QueryRow(ctx, "SELECT rotated_at FROM refresh_tokens WHERE hash = $1", successor).Scan(&curRotated)
			if errors.Is(err, pgx.ErrNoRows) || (err == nil && (curRotated != nil || ts(r.Now).Sub(*rotated) >= r.Grace)) {
				reused = true
				if err := forgetGrant(ctx, tx, grantID); err != nil {
					return err
				}
				if _, err := tx.Exec(ctx, "DELETE FROM grants WHERE id = $1", grantID); err != nil {
					return err
				}
				_, err := tx.Exec(ctx, "INSERT INTO revocations (grant_id, subject, before, at) VALUES ($1, '', $2, $2)",
					grantID, ts(r.Now))
				return err
			}
			if err != nil {
				return err
			}
			rotating = successor
			if _, err := tx.Exec(ctx, "UPDATE refresh_tokens SET successor = $1 WHERE hash = $2", r.Next.Hash[:], r.Old[:]); err != nil {
				return err
			}
		}
		if _, err := tx.Exec(ctx, "UPDATE refresh_tokens SET rotated_at = $1, successor = $2 WHERE hash = $3",
			ts(r.Now), r.Next.Hash[:], rotating); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO refresh_tokens (hash, grant_id, client_id, created_at, idle_expires_at)
			VALUES ($1, $2, $3, $4, $5)`, r.Next.Hash[:], grantID, r.Next.ClientID, ts(r.Next.CreatedAt), ts(r.Next.IdleExpiresAt)); err != nil {
			return err
		}
		if r.IdPTokens != nil {
			if _, err := tx.Exec(ctx, "UPDATE grants SET idp_tokens = $1 WHERE id = $2", nilIfEmpty(r.IdPTokens), grantID); err != nil {
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
	rows, err := s.pool.Query(ctx, "SELECT grant_id, subject, scope, before, at FROM revocations ORDER BY at, seq")
	if err != nil {
		return nil, fmt.Errorf("postgres store: revocations: %w", err)
	}
	defer rows.Close()
	var out []store.Revocation
	for rows.Next() {
		var r store.Revocation
		var scope string
		if err := rows.Scan(&r.GrantID, &r.Subject, &scope, &r.Before, &r.At); err != nil {
			return nil, fmt.Errorf("postgres store: revocations: %w", err)
		}
		r.All = scope == "all"
		r.Before, r.At = r.Before.UTC(), r.At.UTC()
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("postgres store: revocations: %w", err)
	}
	return out, nil
}

// collectLock is the advisory lock key Collect tries: one replica collects per tick, the others
// skip. The bytes spell "byw:coll".
const collectLock int64 = 0x6279773a636f6c6c

// Collect implements store.Collector. It runs READ COMMITTED: it deletes only expired rows, which no
// SERIALIZABLE write depends on, so it needs no serialization and never aborts one. When another
// replica holds the try-lock, it returns nil having deleted nothing.
func (s *Store) Collect(ctx context.Context, now time.Time) error {
	n := ts(now)
	return s.inTx(ctx, pgx.ReadCommitted, func(tx pgx.Tx) error {
		var mine bool
		if err := tx.QueryRow(ctx, "SELECT pg_try_advisory_xact_lock($1)", collectLock).Scan(&mine); err != nil {
			return fmt.Errorf("collect: %w", err)
		}
		if !mine {
			return nil
		}
		for _, q := range []struct {
			sql string
			arg time.Time
		}{
			{"DELETE FROM grants WHERE expires_at <= $1", n}, // cascades to codes and refresh tokens
			{"DELETE FROM codes WHERE expires_at <= $1", n},
			{"DELETE FROM refresh_tokens WHERE idle_expires_at <= $1", n},
			{"DELETE FROM revocations WHERE at <= $1", ts(now.Add(-store.RevocationRetention))},
			{"DELETE FROM consents WHERE expires_at <= $1", n},
			{"DELETE FROM spent_logins WHERE expires_at <= $1", n},
			{"DELETE FROM spent_assertions WHERE expires_at <= $1", n},
			{"DELETE FROM clients WHERE expires_at <= $1", n},
			{"DELETE FROM clients WHERE used_at IS NULL AND created_at <= $1", ts(now.Add(-store.UnusedClientLifetime))},
		} {
			if _, err := tx.Exec(ctx, q.sql, q.arg); err != nil {
				return fmt.Errorf("collect: %w", err)
			}
		}
		return nil
	})
}

// SpendLogin implements store.Logins.
func (s *Store) SpendLogin(ctx context.Context, hash [sha256.Size]byte, now, expiresAt time.Time) error {
	if !expiresAt.After(now) {
		return store.ErrInvalid
	}
	return s.write(ctx, func(tx pgx.Tx) error {
		// One conditional statement (ADR-0007 §2): it inserts, or replaces only an expired record;
		// no row affected means a live one exists.
		tag, err := tx.Exec(ctx, `INSERT INTO spent_logins (hash, expires_at) VALUES ($1, $2)
			ON CONFLICT (hash) DO UPDATE SET expires_at = excluded.expires_at WHERE spent_logins.expires_at <= $3`,
			hash[:], ts(expiresAt), ts(now))
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return store.ErrConsumed
		}
		return nil
	})
}

// SpendAssertion implements store.ClientAssertions, as SpendLogin does for logins.
func (s *Store) SpendAssertion(ctx context.Context, hash [sha256.Size]byte, now, expiresAt time.Time) error {
	if !expiresAt.After(now) {
		return store.ErrInvalid
	}
	return s.write(ctx, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `INSERT INTO spent_assertions (hash, expires_at) VALUES ($1, $2)
			ON CONFLICT (hash) DO UPDATE SET expires_at = excluded.expires_at WHERE spent_assertions.expires_at <= $3`,
			hash[:], ts(expiresAt), ts(now))
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return store.ErrConsumed
		}
		return nil
	})
}

// RememberConsent implements store.Consents.
func (s *Store) RememberConsent(ctx context.Context, c store.Consent) error {
	k := c.Key
	if k.Issuer == "" || k.Subject == "" || k.ClientID == "" || k.Redirect == "" || k.Resource == "" || len(c.Scopes) == 0 || !c.ExpiresAt.After(c.ApprovedAt) {
		return store.ErrInvalid
	}
	return s.write(ctx, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO consents (issuer, subject, client_id, redirect, resource, scopes, approved_at, expires_at)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
			ON CONFLICT (issuer, subject, client_id, redirect, resource) DO UPDATE SET
				scopes = excluded.scopes, approved_at = excluded.approved_at, expires_at = excluded.expires_at`,
			k.Issuer, k.Subject, k.ClientID, k.Redirect, k.Resource, c.Scopes, ts(c.ApprovedAt), ts(c.ExpiresAt))
		return err
	})
}

// Consent implements store.Consents.
func (s *Store) Consent(ctx context.Context, k store.ConsentKey) (store.Consent, error) {
	c := store.Consent{Key: k}
	err := s.pool.QueryRow(ctx, `SELECT scopes, approved_at, expires_at FROM consents
		WHERE issuer = $1 AND subject = $2 AND client_id = $3 AND redirect = $4 AND resource = $5`,
		k.Issuer, k.Subject, k.ClientID, k.Redirect, k.Resource).Scan(&c.Scopes, &c.ApprovedAt, &c.ExpiresAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return store.Consent{}, store.ErrNotFound
	}
	if err != nil {
		return store.Consent{}, fmt.Errorf("postgres store: consent: %w", err)
	}
	c.ApprovedAt, c.ExpiresAt = c.ApprovedAt.UTC(), c.ExpiresAt.UTC()
	return c, nil
}

// CreateClient implements store.Clients. SERIALIZABLE makes the count and the insert one step, so
// concurrent registrations on any replica never exceed max.
func (s *Store) CreateClient(ctx context.Context, c store.Client, max int) error {
	if c.ID == "" || len(c.Metadata) == 0 || !c.UsedAt.IsZero() || !c.ExpiresAt.After(c.CreatedAt) {
		return store.ErrInvalid
	}
	return s.write(ctx, func(tx pgx.Tx) error {
		if err := mustNotExist(ctx, tx, "SELECT EXISTS (SELECT 1 FROM clients WHERE id = $1)", c.ID); err != nil {
			return err
		}
		if max > 0 {
			var n int
			if err := tx.QueryRow(ctx, "SELECT count(*) FROM clients WHERE expires_at > $1", ts(c.CreatedAt)).Scan(&n); err != nil {
				return err
			}
			if n >= max {
				return store.ErrFull
			}
		}
		_, err := tx.Exec(ctx, "INSERT INTO clients (id, metadata, created_at, expires_at) VALUES ($1, $2, $3, $4)",
			c.ID, c.Metadata, ts(c.CreatedAt), ts(c.ExpiresAt))
		return err
	})
}

// Client implements store.Clients.
func (s *Store) Client(ctx context.Context, id string) (store.Client, error) {
	var c store.Client
	var used *time.Time
	err := s.pool.QueryRow(ctx, "SELECT id, metadata, created_at, used_at, expires_at FROM clients WHERE id = $1", id).
		Scan(&c.ID, &c.Metadata, &c.CreatedAt, &used, &c.ExpiresAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return store.Client{}, store.ErrNotFound
	}
	if err != nil {
		return store.Client{}, fmt.Errorf("postgres store: client: %w", err)
	}
	c.CreatedAt, c.ExpiresAt = c.CreatedAt.UTC(), c.ExpiresAt.UTC()
	if used != nil {
		c.UsedAt = used.UTC()
	}
	return c, nil
}

// UseClient implements store.Clients. A use that changes nothing (already used, and not extending
// by at least minExtension) does not write.
func (s *Store) UseClient(ctx context.Context, id string, now, expires time.Time, minExtension time.Duration) error {
	c, err := s.Client(ctx, id)
	if err != nil {
		return err
	}
	if !c.UsedAt.IsZero() && expires.Before(c.ExpiresAt.Add(minExtension)) {
		return nil
	}
	return s.write(ctx, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `UPDATE clients SET used_at = coalesce(used_at, $1),
			expires_at = CASE WHEN $2 >= expires_at + $3::bigint * interval '1 microsecond' THEN $2 ELSE expires_at END
			WHERE id = $4`, ts(now), ts(expires), minExtension.Microseconds(), id)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return store.ErrNotFound
		}
		return nil
	})
}

// forgetGrant deletes the consents of a grant's user and client, before the grant itself goes.
func forgetGrant(ctx context.Context, tx pgx.Tx, grantID string) error {
	_, err := tx.Exec(ctx, `DELETE FROM consents WHERE (issuer, subject, client_id) IN
		(SELECT issuer, subject, client_id FROM grants WHERE id = $1)`, grantID)
	return err
}

func mustHaveGrant(ctx context.Context, tx pgx.Tx, id string) error {
	var ok bool
	if err := tx.QueryRow(ctx, "SELECT EXISTS (SELECT 1 FROM grants WHERE id = $1)", id).Scan(&ok); err != nil {
		return err
	}
	if !ok {
		return store.ErrNotFound
	}
	return nil
}

// mustNotExist runs an EXISTS query and returns ErrExists when it is true.
func mustNotExist(ctx context.Context, tx pgx.Tx, query string, arg any) error {
	var exists bool
	if err := tx.QueryRow(ctx, query, arg).Scan(&exists); err != nil {
		return err
	}
	if exists {
		return store.ErrExists
	}
	return nil
}

// ts is a time as PostgreSQL keeps it: microseconds (store.go allows it), in UTC. pgx truncates
// on its own; doing it here too makes comparisons in Go agree with the stored value.
func ts(t time.Time) time.Time { return t.Truncate(time.Microsecond).UTC() }

func nonNil(s []string) []string { return append([]string{}, s...) }

// nilIfEmpty: nil and empty are stored alike (an empty bytea is NULL, as SQLite's adapter stores
// it), so scopes and IdP tokens read back as nil when there are none.
func nilIfEmpty[S ~[]E, E any](s S) S {
	if len(s) == 0 {
		return nil
	}
	return s
}

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
