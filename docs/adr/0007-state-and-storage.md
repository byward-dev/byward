# ADR-0007: State and storage — one store interface, embedded SQLite by default

- Status: Accepted
- Date: 2026-11-05
- Issue: #6 (F5)

## Context

ADR-0006 needs stored state: single-use authorization codes, grants (refresh-token hashes,
rotation family, encrypted IdP tokens), revocations, and DCR client records that outlive refresh
tokens. A fully stateless design cannot do single-use codes, rotation or revocation; babs calls its
own stateless mode "dev-only" because "codes/refresh [are] replayable within TTL" and requires
Redis in production. Competitors store state in bbolt (sigbit — "multiple processes cannot open
the same database"), memory by default (Pomerium, ToolHive), Redis (babs, ToolHive), or a
pluggable store with signing keys inside it (dex). sigbit defaults its data directory to `./data`
relative to the working directory and keeps its private key there.

Options no competitor ships were surveyed too (2026-11-05): Litestream v0.5.18 gives SQLite
continuous backup (single writer); LiteFS (last release 2025-04, FUSE + Consul), rqlite (a separate
server; no explicit transactions), dqlite and go-libsql (CGO), embedded Raft (quorum and recovery
burden) and Kubernetes CRDs (write-rate and size limits) do not fit. Remote KMS calls per token
cost latency, throttling and money; unwrapping a data key once at startup does not.

A restore brings back refresh tokens rotated after the restore point and erases reuse-detection
history; rotating the sealing key (ADR-0006) does not touch stored refresh tokens.

## Decision

1. **One narrow store interface** split by concern (codes, grants, revocations, clients), with a
   shared conformance test suite every adapter must pass; garbage collection of expired rows and
   in-code migrations are part of the interface (dex patterns).
2. **v0.1 adapter: embedded SQLite** via `modernc.org/sqlite` (pure Go, no CGO): WAL mode, busy
   timeout, file mode `0600`; code consumption and rotation are conditional updates in one
   transaction. **PostgreSQL adapter (`pgx/v5`) in v0.2** for more than one replica; we claim
   PostgreSQL only and keep SQL portable (single-statement conditional updates, retry on
   serialization failures). Postgres connections require TLS unless explicitly disabled.
3. **Stateless where possible:** logins in progress are a sealed blob plus a `__Host-` cookie;
   access tokens are sealed (ADR-0006); the legacy `Mcp-Session-Id` binding is a sealed wrapper
   (amends ADR-0004).
4. **Several replicas only for HTTP upstreams.** stdio upstream processes live on one replica
   (ADR-0003); a multi-replica store with a stdio upstream is rejected at startup.
5. **Keys never live in the store.** They come from a file or env with a key ID and a list of
   previous keys; generating and persisting keys is allowed only in an explicit single-node
   development mode, into a separate `0600` key file. A KMS key-unwrapping seam (Azure Key Vault
   first) is v0.2+.
6. **No paths relative to the working directory.** The data directory defaults to the OS state
   directory (`/var/lib/byward` in the container image); its absolute path is logged at
   startup and an unwritable directory fails startup.
7. **Store outages:** readiness depends on the store, liveness does not. Refresh and revoke return
   503; access tokens keep working until the revocation list is 30 s stale, then fail closed
   (ADR-0006).
8. **Backup and restore:** documented Litestream sidecar for the SQLite default (backup and
   disaster recovery, not high availability), with a restore test in CI; `pg_dump` for Postgres.
9. **Store epoch with automatic restore detection.** Each grant records the epoch it was created
   in. The store keeps a write counter mirrored to a small file next to the keys (outside the
   backup); at startup a store behind that file is treated as restored: the epoch is bumped, refresh
   tokens from older epochs are refused (users sign in again), and the event is logged.

## Consequences

- One replica, no external dependency by default; HA needs v0.2's PostgreSQL adapter and is
  limited to HTTP upstreams.
- A store outage longer than 30 s stops the proxy — deliberate (fail safe).
- The schema becomes public interface: migrations are forward-only; downgrading needs a backup.
- Litestream's `_litestream_lock` table appears in the database and must be tolerated.

## Considered options

- Fully stateless — rejected: fails single-use codes, rotation and revocation.
- bbolt — rejected: single process, no SQL parity with PostgreSQL.
- Memory by default with Redis/Valkey optional — rejected: loses state on restart and adds an
  external dependency; a KV adapter only if asked for (Valkey, BSD-3).
- LiteFS, rqlite, dqlite, libSQL/Turso, embedded Raft, Kubernetes CRDs — rejected (see Context).
- Keys stored in the database (dex) — rejected: a leaked backup would leak the keys.
- Manual epoch bump only — rejected: an operator restoring by file copy forgets it.
