package postgres

import (
	"context"
	"errors"
	"fmt"

	"github.com/byward-dev/byward/internal/store"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// migrations are forward-only (ADR-0007): migrations[i] takes the schema from version i to i+1, in
// one transaction with the version bump (PostgreSQL DDL is transactional). Within a minor release
// they only add (expand, never contract), so replicas still on the older binary keep working during
// a rolling upgrade. Never edit a released migration: append a new one, and add its fixture under
// testdata/schema.
var migrations = []string{
	// v1. meta.epoch is the store epoch (ADR-0007 §9), bumped when a restore is detected; the
	// store_writes sequence advances with every write transaction, and pg_dump saves its value.
	// Times are timestamptz (microseconds); scopes are text arrays.
	`CREATE TABLE meta (key text PRIMARY KEY, value bigint NOT NULL);
	INSERT INTO meta (key, value) VALUES ('epoch', 1);
	CREATE SEQUENCE store_writes;

	CREATE TABLE grants (
		id         text PRIMARY KEY,
		client_id  text NOT NULL,
		subject    text NOT NULL,
		issuer     text NOT NULL,
		resource   text NOT NULL,
		scopes     text[] NOT NULL,
		idp_tokens bytea,
		created_at timestamptz NOT NULL,
		expires_at timestamptz NOT NULL,
		epoch      bigint NOT NULL
	);
	CREATE INDEX grants_subject ON grants (subject, created_at);
	CREATE INDEX grants_created ON grants (created_at);
	CREATE INDEX grants_expires ON grants (expires_at);

	CREATE TABLE codes (
		grant_id       text PRIMARY KEY REFERENCES grants (id) ON DELETE CASCADE,
		client_id      text NOT NULL,
		redirect_uri   text NOT NULL,
		code_challenge text NOT NULL,
		scopes         text[] NOT NULL,
		expires_at     timestamptz NOT NULL,
		consumed       boolean NOT NULL DEFAULT false
	);
	CREATE INDEX codes_expires ON codes (expires_at);

	-- rotated_at is NULL while the token is current; successor is the hash of the token issued in
	-- its place, moved to the newest one when a retry within the grace window issues another.
	CREATE TABLE refresh_tokens (
		hash            bytea PRIMARY KEY,
		grant_id        text NOT NULL REFERENCES grants (id) ON DELETE CASCADE,
		client_id       text NOT NULL,
		created_at      timestamptz NOT NULL,
		idle_expires_at timestamptz NOT NULL,
		rotated_at      timestamptz,
		successor       bytea
	);
	CREATE INDEX refresh_tokens_grant ON refresh_tokens (grant_id);
	CREATE INDEX refresh_tokens_idle ON refresh_tokens (idle_expires_at);

	-- A cut-off for every subject is marked by scope, never by an empty subject, so a row naming
	-- nothing cannot revoke everyone.
	CREATE TABLE revocations (
		seq      bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
		grant_id text NOT NULL,
		subject  text NOT NULL,
		scope    text NOT NULL DEFAULT '' CHECK (scope IN ('', 'all')),
		before   timestamptz NOT NULL,
		at       timestamptz NOT NULL
	);
	CREATE INDEX revocations_subject ON revocations (subject, before);
	CREATE INDEX revocations_at ON revocations (at);

	-- used_at is NULL until the client first redeems a code.
	CREATE TABLE clients (
		id         text PRIMARY KEY,
		metadata   bytea NOT NULL,
		created_at timestamptz NOT NULL,
		used_at    timestamptz,
		expires_at timestamptz NOT NULL
	);
	CREATE INDEX clients_expires ON clients (expires_at);

	CREATE TABLE consents (
		issuer      text NOT NULL,
		subject     text NOT NULL,
		client_id   text NOT NULL,
		redirect    text NOT NULL,
		resource    text NOT NULL,
		scopes      text[] NOT NULL,
		approved_at timestamptz NOT NULL,
		expires_at  timestamptz NOT NULL,
		PRIMARY KEY (issuer, subject, client_id, redirect, resource)
	);
	CREATE INDEX consents_subject ON consents (subject, approved_at);
	CREATE INDEX consents_approved ON consents (approved_at);
	CREATE INDEX consents_expires ON consents (expires_at);

	-- hash is SHA-256 of the login's IdP state (#150).
	CREATE TABLE spent_logins (
		hash       bytea PRIMARY KEY,
		expires_at timestamptz NOT NULL
	);
	CREATE INDEX spent_logins_expires ON spent_logins (expires_at);`,

	// v2: spent client assertions (#227). hash is SHA-256 of an assertion's replay key, never the jti.
	`CREATE TABLE spent_assertions (
		hash       bytea PRIMARY KEY,
		expires_at timestamptz NOT NULL
	);
	CREATE INDEX spent_assertions_expires ON spent_assertions (expires_at);`,

	// v3: consents written under the lifetime rule (#363). records_lifetime_at is the approved_at
	// of the write that marked the consent; the mark counts only while it still equals approved_at,
	// so a replica on an older binary that re-approves the consent (and so sets approved_at but not
	// this column) leaves it unmarked. NULL on every row from before this version.
	`ALTER TABLE consents ADD COLUMN records_lifetime_at timestamptz;`,
}

// schemaVersion is the schema this binary writes.
func schemaVersion() int { return len(migrations) }

// migrateLock is the advisory lock key migrations run under, so replicas starting together migrate
// one at a time. The bytes spell "byw:migr".
const migrateLock int64 = 0x6279773a6d696772

// current is migrate for an operator command, which never migrates and creates nothing: the
// schema must be this binary's. A database that does not exist, or one without schema_version or
// at version 0, is store.ErrNoStore; another version is store.ErrOlderSchema or
// store.ErrNewerSchema.
func current(ctx context.Context, pool *pgxpool.Pool) error {
	var exists bool
	if err := pool.QueryRow(ctx, "SELECT to_regclass('schema_version') IS NOT NULL").Scan(&exists); err != nil {
		if pgErr, ok := errors.AsType[*pgconn.PgError](err); ok && pgErr.Code == "3D000" { // invalid_catalog_name
			return fmt.Errorf("%w: the database (%s) does not exist", store.ErrNoStore, describe(pool.Config().ConnConfig))
		}
		return fmt.Errorf("postgres store: connect or read schema version: %w", err) // the first query connects
	}
	var v int
	if exists { // a statement naming a missing table fails at parse time, so ask first
		if err := pool.QueryRow(ctx, "SELECT coalesce(max(version), 0) FROM schema_version").Scan(&v); err != nil {
			return fmt.Errorf("postgres store: read schema version: %w", err)
		}
	}
	switch {
	case v == 0:
		return fmt.Errorf("%w: the database (%s) holds no byward schema", store.ErrNoStore, describe(pool.Config().ConnConfig))
	case v > schemaVersion():
		return fmt.Errorf("%w: v%d, this byward's v%d", store.ErrNewerSchema, v, schemaVersion())
	case v < schemaVersion():
		return fmt.Errorf("%w: v%d, this byward's v%d", store.ErrOlderSchema, v, schemaVersion())
	}
	return nil
}

// migrate brings the database to schemaVersion under migrateLock, which it holds on one connection
// for the whole run. A newer schema is refused: downgrading needs a backup (ADR-0007 Consequences).
func migrate(ctx context.Context, pool *pgxpool.Pool) error {
	conn, err := pool.Acquire(ctx)
	if err != nil {
		return fmt.Errorf("postgres store: connect: %w", err)
	}
	defer conn.Release()
	if _, err := conn.Exec(ctx, "SELECT pg_advisory_lock($1)", migrateLock); err != nil {
		return fmt.Errorf("postgres store: migration lock: %w", err)
	}
	// A session lock outlives a failed statement; release it on every path. If the connection is
	// gone, the server has released it already.
	defer func() { _, _ = conn.Exec(context.WithoutCancel(ctx), "SELECT pg_advisory_unlock($1)", migrateLock) }()

	if _, err := conn.Exec(ctx, "CREATE TABLE IF NOT EXISTS schema_version (version integer NOT NULL)"); err != nil {
		return fmt.Errorf("postgres store: schema version: %w", err)
	}
	var v int
	switch err := conn.QueryRow(ctx, "SELECT version FROM schema_version").Scan(&v); {
	case errors.Is(err, pgx.ErrNoRows):
		if _, err := conn.Exec(ctx, "INSERT INTO schema_version (version) VALUES (0)"); err != nil {
			return fmt.Errorf("postgres store: schema version: %w", err)
		}
	case err != nil:
		return fmt.Errorf("postgres store: read schema version: %w", err)
	}
	if v > schemaVersion() {
		return fmt.Errorf("postgres store: database schema v%d is newer than this binary's v%d; downgrading needs the backup taken before the upgrade", v, schemaVersion())
	}
	for ; v < schemaVersion(); v++ {
		if err := pgx.BeginFunc(ctx, conn, func(tx pgx.Tx) error {
			if _, err := tx.Exec(ctx, migrations[v]); err != nil {
				return err
			}
			_, err := tx.Exec(ctx, "UPDATE schema_version SET version = $1", v+1)
			return err
		}); err != nil {
			return fmt.Errorf("postgres store: migrate to v%d: %w", v+1, err)
		}
	}
	return nil
}
