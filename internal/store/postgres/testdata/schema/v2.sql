-- Schema v2 (v1 plus spent client assertions) as released, with data the migration test reads back
-- through the store (postgres_integration_test.go).
-- Times: 2026-11-06 12:00 UTC is fixtureCreated, 2099-01-01 is fixtureExpires.
CREATE TABLE meta (key text PRIMARY KEY, value bigint NOT NULL);
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
CREATE INDEX spent_logins_expires ON spent_logins (expires_at);

CREATE TABLE schema_version (version integer NOT NULL);
CREATE TABLE spent_assertions (
	hash       bytea PRIMARY KEY,
	expires_at timestamptz NOT NULL
);
CREATE INDEX spent_assertions_expires ON spent_assertions (expires_at);

INSERT INTO schema_version (version) VALUES (2);
SELECT setval('store_writes', 9);

INSERT INTO grants (id, client_id, subject, issuer, resource, scopes, idp_tokens, created_at, expires_at, epoch) VALUES
	('fixture-grant', 'fixture-client', 'tid:fixture', 'https://idp.example/v2.0', 'https://mcp.example.com/mcp', '{mcp}',
	 'sea'::bytea, '2026-11-06 12:00:00+00', '2099-01-01 00:00:00+00', 1);
INSERT INTO codes (grant_id, client_id, redirect_uri, code_challenge, scopes, expires_at) VALUES
	('fixture-grant', 'fixture-client', 'http://127.0.0.1:33418/callback', 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM', '{mcp}',
	 '2099-01-01 00:00:00+00');
-- fixture-refresh-old was rotated 1 s after creation to fixture-refresh, the current token.
INSERT INTO refresh_tokens (hash, grant_id, client_id, created_at, idle_expires_at, rotated_at, successor) VALUES
	(sha256('fixture-refresh-old'::bytea), 'fixture-grant', 'fixture-client', '2026-11-06 12:00:00+00', '2099-01-01 00:00:00+00',
	 '2026-11-06 12:00:01+00', sha256('fixture-refresh'::bytea)),
	(sha256('fixture-refresh'::bytea), 'fixture-grant', 'fixture-client', '2026-11-06 12:00:00+00', '2099-01-01 00:00:00+00',
	 NULL, NULL);
INSERT INTO revocations (grant_id, subject, scope, before, at) VALUES
	('fixture-revoked', '', '', '2026-11-06 12:00:00+00', '2026-11-06 12:00:00+00'),
	('', 'tid:fixture-revoked-subject', '', '2026-11-06 12:00:00+00', '2026-11-06 12:00:01+00'),
	('', '', 'all', '2026-11-06 12:00:00+00', '2026-11-06 12:00:02+00');
INSERT INTO clients (id, metadata, created_at, used_at, expires_at) VALUES
	('fixture-dcr-client', '{"client_name":"Fixture"}'::bytea, '2026-11-06 12:00:00+00', '2026-11-06 12:00:01+00', '2099-01-01 00:00:00+00');
INSERT INTO consents (issuer, subject, client_id, redirect, resource, scopes, approved_at, expires_at) VALUES
	('https://idp.example/v2.0', 'tid:fixture', 'fixture-client', 'http://127.0.0.1/cb', 'https://mcp.example.com/mcp', '{mcp}',
	 '2026-11-06 12:00:00+00', '2099-01-01 00:00:00+00');
INSERT INTO spent_logins (hash, expires_at) VALUES (sha256('fixture-login'::bytea), '2099-01-01 00:00:00+00');
INSERT INTO spent_assertions (hash, expires_at) VALUES (sha256('fixture-assertion'::bytea), '2099-01-01 00:00:00+00');
