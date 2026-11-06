# How to keep the proxy's state

The broker keeps grants, authorization codes, refresh tokens and revocations in an embedded SQLite
database ([ADR-0007](../adr/0007-state-and-storage.md)). Sealing keys are never stored there; they come
from the keys directory ([sealing-keys.md](sealing-keys.md)).

Expired rows are deleted at startup and every 5 minutes while the proxy runs: codes, refresh tokens
and grants past their expiry (a grant takes its codes and refresh tokens with it), and revocations
older than one hour, the longest access-token lifetime. The database stays the size of the live state.

## Settings

| Setting | Default | Meaning |
|---|---|---|
| `BYWARD_DATA_DIR` | `/var/lib/byward` | Data directory, an absolute path. The settings below, the keys directory (`keys`) and the static clients file (`clients.json`) default to paths in it. |
| `BYWARD_STORE_DIR` | `state` in the data directory | State directory, an absolute path. Created with mode 0700; the database file `byward.db` (and its `-wal`/`-shm` files) is 0600. An unwritable directory stops startup. |
| `BYWARD_STORE_COUNTER_FILE` | `store-writes` next to the keys directory | Restore-detection counter, an absolute path **outside** the state directory. |
| `BYWARD_REFRESH_GRACE` | `30s` | How long a just-rotated refresh token is still accepted (0s–60s), for a client retrying a response it lost. |

The full list is in [the settings reference](../reference/settings.md).

## Restore detection

Every write to the store also updates the counter file. At startup, a database that is behind its
counter file was restored from an older copy. The proxy then:

- starts a new store epoch;
- refuses refresh tokens issued before the restore, so those users sign in again (their access
  tokens keep working until they expire, at most one hour);
- logs a warning with `"reason":"store_restore"` and the new epoch.

Revocations recorded after the backup are lost with the restore: an access token revoked since then
is accepted again until it expires (at most one hour). If that matters, revoke those users again
after a restore.

This only works if the counter file is **not** in the backup: keep it outside the state directory and
outside whatever backs the state directory up. The proxy refuses to start if the counter file is
inside the state directory.

If the counter file is missing while the database has data, the proxy starts and logs
`"reason":"store_counter_missing"`: a restore could not be detected at that start. This happens after
the file was lost or moved, for example on a fresh pod with the counter on an `emptyDir`.

## Layouts

**Defaults (VM, Docker host, the container image):** everything lives in the data directory, and only
`state/` is backed up:

```text
/var/lib/byward/keys/2026-11-06    sealing keys (you create them, see sealing-keys.md)
/var/lib/byward/clients.json       static clients (you create it)
/var/lib/byward/store-writes       counter file, next to the keys directory
/var/lib/byward/state/             state directory: back this up, and only this
```

The proxy must be able to write the data directory (for the counter file) and the state directory;
startup fails otherwise. It logs the absolute path of each at startup.

**Kubernetes:** keys usually come from a read-only secret volume, whose parent directory is not
writable, so set `BYWARD_STORE_COUNTER_FILE` explicitly to a small writable volume that is not
part of the state backup. A per-pod `emptyDir` works but loses the counter on every pod restart, which
turns detection off for that start.

## Backups

Back up the state directory while the proxy is stopped, or with a tool that copies a consistent
SQLite snapshot. A documented Litestream setup with a restore drill is planned (ADR-0007 §8). Restoring
an older copy is safe: the proxy detects it at the next start as described above. Migrations are
forward-only, so an older proxy cannot open a database a newer one has upgraded; keep the backup taken
before an upgrade.
