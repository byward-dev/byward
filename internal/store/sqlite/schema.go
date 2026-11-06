package sqlite

import (
	"context"
	"database/sql"
	"fmt"
)

// migrations are forward-only (ADR-0007): migrations[i] takes the schema from version i to i+1.
// PRAGMA user_version holds the version; it is part of each migration's transaction. Never edit a
// released migration: append a new one, and add its fixture under testdata/schema.
var migrations = []string{
	// v1
	`CREATE TABLE meta (key TEXT PRIMARY KEY, value INTEGER NOT NULL) STRICT;
	INSERT INTO meta (key, value) VALUES ('epoch', 1), ('writes', 0);

	CREATE TABLE grants (
		id         TEXT PRIMARY KEY,
		client_id  TEXT NOT NULL,
		subject    TEXT NOT NULL,
		issuer     TEXT NOT NULL,
		resource   TEXT NOT NULL,
		scopes     TEXT NOT NULL,
		idp_tokens BLOB,
		created_at INTEGER NOT NULL,
		expires_at INTEGER NOT NULL,
		epoch      INTEGER NOT NULL
	) STRICT;
	CREATE INDEX grants_subject ON grants (subject, created_at);
	CREATE INDEX grants_expires ON grants (expires_at);

	CREATE TABLE codes (
		grant_id       TEXT PRIMARY KEY REFERENCES grants (id) ON DELETE CASCADE,
		client_id      TEXT NOT NULL,
		redirect_uri   TEXT NOT NULL,
		code_challenge TEXT NOT NULL,
		scopes         TEXT NOT NULL,
		expires_at     INTEGER NOT NULL,
		consumed       INTEGER NOT NULL DEFAULT 0
	) STRICT;

	CREATE TABLE refresh_tokens (
		hash            BLOB PRIMARY KEY,
		grant_id        TEXT NOT NULL REFERENCES grants (id) ON DELETE CASCADE,
		client_id       TEXT NOT NULL,
		created_at      INTEGER NOT NULL,
		idle_expires_at INTEGER NOT NULL
	) STRICT;
	CREATE INDEX refresh_tokens_grant ON refresh_tokens (grant_id);

	CREATE TABLE revocations (
		seq      INTEGER PRIMARY KEY,
		grant_id TEXT NOT NULL,
		subject  TEXT NOT NULL,
		before   INTEGER NOT NULL,
		at       INTEGER NOT NULL
	) STRICT;
	CREATE INDEX revocations_subject ON revocations (subject, before);`,

	// v2: refresh-token rotation (ADR-0006 §4). rotated_at is NULL while the token is current;
	// successor is the hash of the token issued in its place, moved to the newest one when a retry
	// within the grace window issues another.
	`ALTER TABLE refresh_tokens ADD COLUMN rotated_at INTEGER;
	ALTER TABLE refresh_tokens ADD COLUMN successor BLOB;`,

	// v3: revoke-all (ADR-0006 §9). A cut-off for every subject is marked explicitly, never by an
	// empty subject, so a row naming nothing cannot revoke everyone.
	`ALTER TABLE revocations ADD COLUMN scope TEXT NOT NULL DEFAULT '' CHECK (scope IN ('', 'all'));`,
}

// schemaVersion is the schema this binary writes.
func schemaVersion() int { return len(migrations) }

// migrate brings db to SchemaVersion. A newer schema is refused: downgrading needs a backup
// (ADR-0007 Consequences).
func migrate(ctx context.Context, db *sql.DB) error {
	var v int
	if err := db.QueryRowContext(ctx, "PRAGMA user_version").Scan(&v); err != nil {
		return fmt.Errorf("sqlite store: read schema version: %w", err)
	}
	if v > schemaVersion() {
		return fmt.Errorf("sqlite store: database schema v%d is newer than this binary's v%d; downgrading needs the backup taken before the upgrade", v, schemaVersion())
	}
	for ; v < schemaVersion(); v++ {
		tx, err := db.BeginTx(ctx, nil)
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, migrations[v]); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("sqlite store: migrate to v%d: %w", v+1, err)
		}
		if _, err := tx.ExecContext(ctx, fmt.Sprintf("PRAGMA user_version = %d", v+1)); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("sqlite store: migrate to v%d: %w", v+1, err)
		}
		if err := tx.Commit(); err != nil {
			return fmt.Errorf("sqlite store: migrate to v%d: %w", v+1, err)
		}
	}
	return nil
}
