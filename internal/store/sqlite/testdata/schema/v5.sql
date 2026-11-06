-- Fixture for schema v5 (v4 plus remembered consent), frozen when v5 is released. Never edit it: a
-- new schema version gets a new file (vN.sql) built by that version's code. It holds everything
-- v4.sql holds, plus a remembered consent of tid:fixture for fixture-client, so the migration test
-- can read it back through the store (sqlite_test.go).

CREATE TABLE meta (key TEXT PRIMARY KEY, value INTEGER NOT NULL) STRICT;
INSERT INTO meta (key, value) VALUES ('epoch', 1), ('writes', 3);

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
CREATE INDEX revocations_subject ON revocations (subject, before);

-- 2026-11-06T12:00:00Z = 1793966400000000 µs; expiry far in the future (2099-01-01 = 4070908800000000 µs).
INSERT INTO grants VALUES ('fixture-grant', 'fixture-client', 'tid:fixture', 'https://idp.example/v2.0',
	'https://mcp.example.com/mcp', '["mcp"]', X'736561', 1793966400000000, 4070908800000000, 1);
INSERT INTO codes VALUES ('fixture-grant', 'fixture-client', 'http://127.0.0.1:33418/callback',
	'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM', '["mcp"]', 4070908800000000, 0);
INSERT INTO refresh_tokens VALUES (X'918b7df4f2e8d18c096db4cdced88cf630a86839288472a5442714be311abb80',
	'fixture-grant', 'fixture-client', 1793966400000000, 4070908800000000);

INSERT INTO revocations (grant_id, subject, before, at) VALUES ('fixture-revoked', '', 1793966400000000, 1793966400000000);
INSERT INTO revocations (grant_id, subject, before, at) VALUES ('', 'tid:fixture-revoked-subject', 1793966400000000, 1793966401000000);

-- Litestream adds this table to databases it replicates (ADR-0007 Consequences).
CREATE TABLE _litestream_lock (id INTEGER);

-- v2: refresh-token rotation. fixture-refresh is current (rotated_at NULL); fixture-refresh-old was
-- rotated to it.
ALTER TABLE refresh_tokens ADD COLUMN rotated_at INTEGER;
ALTER TABLE refresh_tokens ADD COLUMN successor BLOB;

-- A refresh token rotated 1 s after creation; its successor is the current fixture-refresh token.
INSERT INTO refresh_tokens (hash, grant_id, client_id, created_at, idle_expires_at, rotated_at, successor)
	VALUES (X'f7a621603a17f47a345c2a6e29ac9be70dc860f4904fa9370caf4800a2c7ff3c', 'fixture-grant', 'fixture-client',
	1793966400000000, 4070908800000000, 1793966401000000,
	X'918b7df4f2e8d18c096db4cdced88cf630a86839288472a5442714be311abb80');

-- v3: revoke-all. A cut-off for every subject, recorded 2 s after creation.
ALTER TABLE revocations ADD COLUMN scope TEXT NOT NULL DEFAULT '' CHECK (scope IN ('', 'all'));
INSERT INTO revocations (grant_id, subject, scope, before, at) VALUES ('', '', 'all', 1793966400000000, 1793966402000000);

-- v4: dynamic client registrations. fixture-dcr-client was registered at the fixture time and used
-- 1 s later; its metadata is opaque to the store.
CREATE TABLE clients (
	id         TEXT PRIMARY KEY,
	metadata   BLOB NOT NULL,
	created_at INTEGER NOT NULL,
	used_at    INTEGER,
	expires_at INTEGER NOT NULL
) STRICT;
CREATE INDEX clients_expires ON clients (expires_at);
INSERT INTO clients (id, metadata, created_at, used_at, expires_at)
	VALUES ('fixture-dcr-client', CAST('{"client_name":"Fixture"}' AS BLOB), 1793966400000000, 1793966401000000, 4070908800000000);

-- v5: remembered consent. tid:fixture approved fixture-client at the fixture time.
CREATE TABLE consents (
	issuer      TEXT NOT NULL,
	subject     TEXT NOT NULL,
	client_id   TEXT NOT NULL,
	redirect    TEXT NOT NULL,
	resource    TEXT NOT NULL,
	scopes      TEXT NOT NULL,
	approved_at INTEGER NOT NULL,
	expires_at  INTEGER NOT NULL,
	PRIMARY KEY (issuer, subject, client_id, redirect, resource)
) STRICT;
CREATE INDEX consents_subject ON consents (subject, approved_at);
CREATE INDEX consents_expires ON consents (expires_at);
INSERT INTO consents (issuer, subject, client_id, redirect, resource, scopes, approved_at, expires_at)
	VALUES ('https://idp.example/v2.0', 'tid:fixture', 'fixture-client', 'http://127.0.0.1/cb', 'https://mcp.example.com/mcp', '["mcp"]',
		1793966400000000, 4070908800000000);

PRAGMA user_version = 5;
