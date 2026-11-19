# DBHub behind byward

> Verified on 2026-11-19 with DBHub 2.0.0 (released 2026-11-18), PostgreSQL 17.12 and byward built
> from `main`, as described in [How this was verified](#how-this-was-verified). The IdP side was
> byward's fake OIDC IdP from its test suite, not a real IdP. Not run: a real IdP, the other
> databases DBHub supports, byward in a container.

[DBHub](https://github.com/bytebase/dbhub) (MIT) lets an MCP client query PostgreSQL, MySQL, SQL
Server, MariaDB, Oracle, SQLite and others. Over HTTP it binds `0.0.0.0` with authentication
off by default, and its docs tell you to put it behind a reverse proxy or set a bearer token
(`--auth-token`). That token "answers 'does this request have the secret,' not 'who is this
user'" (DBHub, *Command-Line Options*).

byward adds the user: every user signs in through your IdP first, and DBHub accepts only requests
that carry byward's [upstream credential](../upstream-credential.md), the bearer token.

> **Every user shares one database role.** DBHub connects with the DSN you configure, for every
> signed-in user: each of them can read whatever that role can read. Connect with a read-only
> role that can see exactly the tables your users may see. DBHub's read-only mode is "a
> guardrail, not a permission boundary" (DBHub, *Read-Only Mode*); the role is the real limit.

## 1. Create a read-only database role

```sql
CREATE ROLE mcp_reader LOGIN PASSWORD '<password>';
GRANT CONNECT ON DATABASE shop TO mcp_reader;
GRANT USAGE ON SCHEMA public TO mcp_reader;
GRANT SELECT ON orders TO mcp_reader;
```

## 2. Choose the token

```sh
(umask 077; openssl rand -hex 24 > dbhub-token)
(umask 077; printf 'Bearer %s\n' "$(cat dbhub-token)" > upstream-credential)
```

DBHub reads the token itself; byward sends the whole header value, `Bearer <token>`, from its
credential file ([upstream credential](../upstream-credential.md#1-put-the-credential-in-a-file)).

## 3. Run DBHub

Its sources and tools go in a TOML file. The password stays out of it, through `${VAR}`
interpolation:

```toml
# dbhub.toml
[[sources]]
id = "shop"
dsn = "postgres://mcp_reader:${DB_PASSWORD}@postgres:5432/shop?sslmode=disable"

[[tools]]
name = "execute_sql"
source = "shop"
readonly = true

[[tools]]
name = "search_objects"
source = "shop"
```

```sh
# dbhub.env, mode 0600
DB_PASSWORD=<password>
DBHUB_AUTH_TOKEN=<the content of dbhub-token>
```

```sh
docker run -d --name dbhub --network <byward's network> --env-file dbhub.env \
  -v "$PWD/dbhub.toml:/config/dbhub.toml:ro" \
  bytebase/dbhub:2.0.0 --transport http --host 0.0.0.0 --port 8080 \
  --allowed-hosts dbhub --config /config/dbhub.toml
```

- `DBHUB_AUTH_TOKEN` (or `--auth-token`) makes every request but `/healthz` need
  `Authorization: Bearer <token>`: the MCP endpoint `/mcp`, the Workbench at `/`, and its API
  under `/api/`, which serves the sources and the Workbench's request traces. A request without
  the token, or with another, gets `401` with `WWW-Authenticate: Bearer`.
- `--allowed-hosts dbhub` lets DBHub accept the `Host` byward sends: the host of
  `BYWARD_UPSTREAM_URL`. DBHub refuses any other host but loopback with `403` (its DNS-rebinding
  check).
- `--host 0.0.0.0` lets byward reach DBHub across the container network. Publish no port: only
  byward's network may reach it.
- `readonly = true` on `execute_sql` refuses statements other than `SELECT`, `WITH`, `EXPLAIN` and
  `SHOW`, and on PostgreSQL runs each one in a `BEGIN READ ONLY` transaction.
- Set `sslmode` as your database needs; the verified run used `disable` on a private Docker
  network.

## 4. Run byward

```sh
BYWARD_UPSTREAM_URL=http://dbhub:8080/mcp
BYWARD_UPSTREAM_CREDENTIAL_FILE=/run/secrets/upstream-credential
BYWARD_ASSERTION_HEADER=X-Byward-Identity
```

Add these to your usual settings, for example those of the
[Entra quickstart](../quickstart-entra.md#3-run-byward) or the [OIDC guide](../oidc.md).

- The credential goes in `Authorization`, the default of `BYWARD_UPSTREAM_CREDENTIAL_HEADER`,
  where DBHub reads its token. byward removes every `Authorization` a client sends, the user's
  byward token among them, before it sets its own.
- The [identity assertion](../identity-assertion.md) also defaults to `Authorization`, so it moves
  to `X-Byward-Identity`. DBHub ignores it.
- byward forwards only the MCP endpoint. The Workbench and `/api/` stay reachable only to someone
  who holds the token.

## 5. Connect a client

Connect the MCP client to byward's public URL as in the
[Entra quickstart](../quickstart-entra.md#4-connect-claude-code). The first request opens the
sign-in page. Afterwards the client lists `execute_sql` and `search_objects`.

## What to check in the logs

- Each sign-in writes a `login` and a `token_issued` audit record with the user's `user_key`
  ([audit events](../../reference/observability.md#events-and-ocsf-mapping)).
- byward's request lines for `/mcp` carry the `request_id` and the status, not the user: a tool call
  is tied to a user through their sign-in, not line by line. DBHub cannot tell users apart either:
  its token is one shared secret.

## How this was verified

On 2026-11-19, on one machine:

| Part | Version | How it ran |
|---|---|---|
| PostgreSQL | 17.12 (`postgres`) | Docker, with the `shop` database: `orders`, which `mcp_reader` may read, and `salaries`, which it may not |
| DBHub | 2.0.0 (`bytebase/dbhub`) | Docker, with the TOML and the options above, its port published on loopback only for the direct calls |
| IdP | byward's fake OIDC IdP (`internal/testutil/fakeidp`, generic profile) | in the test driver, signing in `alice` and then `bob` |
| byward | `main` (d2ed00e4) | the binary on the host, with `--dev` (the fake IdP served http on loopback) and the byward settings above, with DBHub at `http://127.0.0.1:<port>/mcp` |

A scripted MCP client, speaking MCP 2025-11-25, signed in through byward's consent page and the
fake IdP, once as each user, and called DBHub's tools through byward:

1. Without a token, byward answered `401`.
2. `tools/list` listed `execute_sql` and `search_objects`.
3. `execute_sql` with `SELECT 1` returned one row, and with `SELECT * FROM orders` its 3 rows, for
   each user. `SELECT * FROM salaries` got PostgreSQL's "permission denied for table salaries";
   `DELETE FROM orders` got DBHub's `READONLY_VIOLATION`.
4. The client also sent its own `X-Byward-Identity: client-supplied`, which byward removes before it
   sets the assertion; the calls worked.
5. Through byward, `/`, `/api/sources` and `/api/requests` got byward's `404`: only `/mcp` is
   forwarded.
6. Called directly, bypassing byward, DBHub answered `401` with `WWW-Authenticate: Bearer` on
   `/mcp`, `/`, `/api/sources` and `/api/requests` without the token and on `/mcp` with a wrong
   one; `/healthz` answered `200`. With the token, `/mcp` answered `200`. A request whose
   `Host` was the `--allowed-hosts` name passed the host check (and got `401` without the token);
   one with `Host: evil.example` got `403`, even with the token.
7. byward's audit had a `login` and a `token_issued` record for each of `user_key` `alice-sub-211`
   and `bob-sub-211`.
