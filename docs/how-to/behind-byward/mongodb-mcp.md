# The MongoDB MCP Server behind byward

> Verified on 2026-11-19 with mongodb-mcp-server 3.3.0 (released 2026-11-09), MongoDB 8.2.12 and
> byward built from `main`, as described in [How this was verified](#how-this-was-verified). The
> IdP side was byward's fake OIDC IdP from its test suite, not a real IdP. Not run: a real IdP, a
> stdio upstream, MongoDB Atlas.

[mongodb-mcp-server](https://github.com/mongodb-js/mongodb-mcp-server) (Apache-2.0) lets an MCP
client query a MongoDB deployment. Its README says it must not be shared as it is: it "ships with
**no built-in authentication**", it "is not meant to serve multiple users", and you should not run
it "as a shared, internet-facing endpoint without adding your own authentication and identity
layer in front of it" (README, *Deployment Constraints*).

byward is that layer. Every user signs in through your IdP before a request reaches the server,
and the server accepts requests only from byward:

1. mongodb-mcp-server runs over HTTP and refuses, with a 403, every request without a header
   holding a secret (`MDB_MCP_HTTP_HEADERS`).
2. byward sends that secret as its [upstream credential](../upstream-credential.md) on every
   request, and removes any copy a client sends.
3. Only byward can reach the server: don't publish its port.

> **Every user shares one database user and one connection.** The server connects with the
> connection string you configure, for every signed-in user: each of them can read whatever that
> database user can read. The server does not tell users apart, so every request shares one
> MongoDB connection. Give the database user a read-only role on exactly the databases your users
> may see. For a per-user identity on MongoDB Atlas, use the
> [Atlas-managed MCP server](https://github.com/mongodb-js/mongodb-mcp-server#option-2-connect-to-the-mongodb-atlas-managed-mcp-server)
> instead.

## 1. Create a read-only database user

Give it the built-in `read` role on the databases to expose, and nothing else:

```js
db.getSiblingDB("admin").createUser({
  user: "mcp-reader",
  pwd: passwordPrompt(),
  roles: [{ role: "read", db: "shop" }],
})
```

## 2. Choose the shared secret

```sh
(umask 077; openssl rand -hex 24 > upstream-key)
```

byward sends the file's content as the header value ([upstream credential](../upstream-credential.md#1-put-the-credential-in-a-file)),
and mongodb-mcp-server compares the header with the same value.

## 3. Run mongodb-mcp-server

Put its settings in an env file, mode `0600`, so the connection string and the secret stay out of
the command line:

```sh
# mongodb-mcp.env
MDB_MCP_CONNECTION_STRINGS={"preconfigured":"mongodb://mcp-reader:<password>@mongodb:27017/?authSource=admin"}
MDB_MCP_TRANSPORT=http
MDB_MCP_HTTP_HOST=0.0.0.0
MDB_MCP_DANGEROUS_HOST_BINDING=true
MDB_MCP_HTTP_PORT=3000
MDB_MCP_HTTP_HEADERS={"x-byward-key":"<the content of upstream-key>"}
MDB_MCP_READ_ONLY=true
MDB_MCP_DISABLED_TOOLS=connect,atlas,assistant
MDB_MCP_ALLOW_REQUEST_OVERRIDES=false
MDB_MCP_TELEMETRY=disabled
DO_NOT_TRACK=1
```

```sh
docker run -d --name mongodb-mcp --network <byward's network> --env-file mongodb-mcp.env \
  mongodb/mongodb-mcp-server:3.3.0
```

- `MDB_MCP_CONNECTION_STRINGS` names the connection `preconfigured`; tools take it as their
  `connectionId`. (`MDB_MCP_CONNECTION_STRING` still works in 3.3.0 but is deprecated.)
- `MDB_MCP_HTTP_HEADERS` is a JSON object of header names and values. A request without the
  header, or with another value, gets `403 {"error":"Invalid value for header \"x-byward-key\""}`.
- `MDB_MCP_HTTP_HOST=0.0.0.0` lets byward reach the server across the container network, which
  needs `MDB_MCP_DANGEROUS_HOST_BINDING=true`. Publish no port: only byward's network may reach it.
- `MDB_MCP_READ_ONLY=true` offers only the tools of the `read`, `connect` and `metadata` operation
  types; no tool that creates, updates or deletes is listed.
- `MDB_MCP_DISABLED_TOOLS=connect,atlas,assistant` removes the `connect` tools, so a user cannot
  open a connection to another deployment; the Atlas administration tools; and the MongoDB
  Assistant tools, which call `knowledge.mongodb.com`.
- `MDB_MCP_ALLOW_REQUEST_OVERRIDES=false` is the default, set explicitly: no request can change
  the server's settings through its headers or query parameters.
- `MDB_MCP_TELEMETRY=disabled` and `DO_NOT_TRACK=1` turn off the server's telemetry.

The database user's role is still the real limit: read-only mode only removes tools.

## 4. Run byward

```sh
BYWARD_UPSTREAM_URL=http://mongodb-mcp:3000/mcp
BYWARD_UPSTREAM_CREDENTIAL_FILE=/run/secrets/upstream-key
BYWARD_UPSTREAM_CREDENTIAL_HEADER=X-Byward-Key
```

Add these to your usual settings, for example those of the
[Entra quickstart](../quickstart-entra.md#3-run-byward) or the [OIDC guide](../oidc.md). byward
also sends its [identity assertion](../identity-assertion.md) in `Authorization`;
mongodb-mcp-server ignores it.

## 5. Connect a client

Connect the MCP client to byward's public URL as in the
[Entra quickstart](../quickstart-entra.md#4-connect-claude-code). The first request opens the
sign-in page. Afterwards the client lists the server's read tools, such as `find` and `aggregate`,
and calls them with `"connectionId": "preconfigured"`.

## What to check in the logs

- Each sign-in writes a `login` and a `token_issued` audit record with the user's `user_key`
  ([audit events](../../reference/observability.md#events-and-ocsf-mapping)).
- byward's request lines for `/mcp` carry the `request_id` and the status, not the user: a tool call
  is tied to a user through their sign-in, not line by line.

## How this was verified

On 2026-11-19, on one machine:

| Part | Version | How it ran |
|---|---|---|
| MongoDB | 8.2.12 (`mongo`) | Docker, with a root user, the `shop` and `hr` databases, and `mcp-reader` with `read` on `shop` only |
| mongodb-mcp-server | 3.3.0 (`mongodb/mongodb-mcp-server`) | Docker, with the env file above, its port published on loopback only for the direct calls |
| IdP | byward's fake OIDC IdP (`internal/testutil/fakeidp`, generic profile) | in the test driver, signing in `alice` and then `bob` |
| byward | `main` (13a7fc4a) | the binary on the host, with `--dev` (the fake IdP served http on loopback) and the byward settings above |

A scripted MCP client signed in through byward's consent page and the fake IdP, once as each user,
and called the server's tools through byward:

1. Without a token, byward answered `401`.
2. `tools/list` listed `aggregate`, `find`, `count`, `list-databases`, `list-collections` and the
   other read tools, and no `insert-many`, `connect` or Atlas tool. Calling `insert-many` got
   "Tool insert-many not found".
3. `find` on `shop.orders` returned its 3 documents, for each user. `find` on `hr.salaries` got
   MongoDB's "not authorized on hr".
4. The client also sent its own `X-Byward-Key: client-supplied`: the calls still worked, because
   byward replaced it with the credential.
5. Called directly, bypassing byward, the server answered `403 Invalid value for header
   "x-byward-key"` without the header and with a wrong value.
6. byward's audit had a `login` and a `token_issued` record for each of `user_key` `alice-sub-208`
   and `bob-sub-208`.
7. Both users' calls ran in the same MongoDB session, as the shared-connection note above says.
