# How to run several replicas on PostgreSQL

The default store is an embedded SQLite database ([state.md](state.md)): one replica. To run more
than one replica of the proxy behind a load balancer, give them a shared PostgreSQL store
([ADR-0007](../adr/0007-state-and-storage.md), amended for #227).

Requirements:

- **PostgreSQL 15 or later.** It is tested on 15 and on the newest major (`mise run test:postgres`).
- **An HTTP upstream.** A stdio upstream's processes live on one replica (ADR-0007 §4), so the proxy
  refuses to start with a stdio upstream and the PostgreSQL store.
- **The same keys on every replica.** Keys never live in the store. Each replica needs the same
  sealing keys (`BYWARD_KEYS_DIR`, [sealing-keys.md](sealing-keys.md)) and assertion keys
  (`BYWARD_ASSERTION_KEYS_DIR`); otherwise a token one replica sealed is refused by the next.
  `byward check --offline` and `byward doctor` remind you of this.

## 1. Create the database and a role

```sql
CREATE ROLE byward LOGIN PASSWORD '<a generated password>';
CREATE DATABASE byward OWNER byward;
```

The proxy creates and migrates its tables at startup. It needs no other privileges: owning the
database is enough.

## 2. Give the proxy the connection string

Write the connection string to a file that only the proxy's user can read, and point
`BYWARD_STORE_POSTGRES_DSN_FILE` at it. Setting it selects PostgreSQL. Do not also set the SQLite
store's `BYWARD_STORE_DIR` or `BYWARD_STORE_COUNTER_FILE`: the proxy refuses them beside it.

```sh
# /run/secrets/byward-postgres, mode 0600
postgres://byward:<password>@db.internal.example:5432/byward?sslmode=verify-full&sslrootcert=/etc/byward/db-ca.pem
```

```sh
BYWARD_STORE_POSTGRES_DSN_FILE=/run/secrets/byward-postgres
```

- **TLS must be `sslmode=verify-full`.** The proxy checks the host name and the certificate chain
  for every host in the string. It refuses plaintext, a Unix socket, `prefer` (the default), `allow`,
  `require` and `verify-ca` at startup. `sslrootcert` names the CA that signed the server's
  certificate; without it, the system's roots apply (`sslrootcert=system` also works). Only
  `--dev` accepts less, and logs it as a relaxation.
- **The `PG*` environment variables, a service file and `~/.pgpass` are read too.** The TLS rule is
  checked on the result, so none of them can weaken it.
- **Pool settings go in the string:** `pool_max_conns` (default: 4, or the number of CPUs if that
  is larger), `pool_max_conn_lifetime` and so on.
- **The string is never logged.** The startup log names the host, port, database and TLS mode, and
  an error about the string never repeats it.

`byward check --offline` parses the string and applies the TLS rule without connecting.

## 3. Start the replicas

Start as many replicas as you need, all with the same settings and keys. On their first start
they migrate the schema one at a time, under a lock.

What is shared and what is not:

| Shared through the store | Per replica |
|---|---|
| Grants, codes, refresh tokens, revocations, client registrations, remembered consent | The per-address rate limits: three replicas allow three times the budget ([rate limits](../reference/rate-limits.md)) |
| Spent logins and spent client assertions: each is single use across replicas | The On-Behalf-Of token cache and the CIMD document cache |
| The store epoch | The deny list, rebuilt from the store every 5 s |

A revocation on one replica, or with `byward revoke-user` / `byward revoke-all`, reaches every
replica at its next deny-list sync, within seconds.

## Backup and restore

Back up with `pg_dump`, or with your database service's backups and point-in-time recovery.

A restored database is older than what the replicas have seen. Refresh tokens rotated after the
backup and revocations made after it are lost with the restore. The proxy deals with this through
the store epoch, as for SQLite ([state.md](state.md#restore-detection)): refresh tokens from before
the new epoch are refused, so those users sign in again, and every remembered consent is forgotten.

**While the replicas run, they find a restore themselves.** Every write takes a value from a
sequence that `pg_dump` saves, and each replica remembers the highest value it saw committed. A
sequence below that means the database came back from an older copy. Within about 5 s, one replica
starts a new epoch and logs it (`"reason":"store_restore"`, and the `store_restored` audit event);
the others adopt it.

**After a restore, run `byward store new-epoch --yes`** with the proxy's settings. It starts a new
epoch whatever the replicas found, and it is the only way to cover these cases:

- the replicas were stopped during the restore, or have restarted since: a replica remembers only
  what it saw since its own start;
- writes made while `pg_dump` ran: it saves the sequence outside its data snapshot, so the copy can
  hold a higher value than its data;
- a point-in-time recovery to a moment the replicas never saw.

A failover to an asynchronous standby that lost committed transactions looks like a restore, and is
handled as one: those users sign in again.

## Upgrades

Migrations run at startup, forward only, one replica at a time under a lock. Within a minor version
they only add, so replicas still on the older version keep working during a rolling upgrade. A
database migrated by a newer version is refused by an older one: downgrading needs the backup taken
before the upgrade.
