# The MongoDB MCP Server behind byward

> Verified on 2026-11-19 with mongodb-mcp-server 3.3.0 (released 2026-11-09), MongoDB 8.2.12 and
> byward built from `main`, both patterns below, as described in
> [How this was verified](#how-this-was-verified). The IdP side was byward's fake OIDC IdP from its
> test suite, not a real IdP. Not run: a real IdP, the container image in section 2, MongoDB Atlas.

[mongodb-mcp-server](https://github.com/mongodb-js/mongodb-mcp-server) (Apache-2.0) lets an MCP
client query a MongoDB deployment. Its README says it must not be shared as it is: it "ships with
**no built-in authentication**", it "is not meant to serve multiple users", and you should not run
it "as a shared, internet-facing endpoint without adding your own authentication and identity
layer in front of it" (README, *Deployment Constraints*).

byward is that layer: every user signs in through your IdP before a request reaches the server.
Two ways to run it:

- **One process per user** (sections 2 and 3, recommended): byward starts the server as a
  [stdio upstream](../stdio-upstream.md), so each process, and its MongoDB connection, serves one
  signed-in user only.
- **One shared server over HTTP** ([section 4](#4-or-one-shared-server-over-http)): the server
  accepts only requests that carry byward's [upstream credential](../upstream-credential.md). All
  users share its process and its MongoDB connection.

> **Every user shares one database user.** byward does not hand the server a per-user database
> identity: every process connects with the connection string you configure, so each signed-in
> user can read whatever that database user can read. Give it a read-only role on exactly the
> databases your users may see. For a per-user identity on MongoDB Atlas, use the
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

## 2. Install the server where byward runs

The server needs Node.js 20.19, 22.13, 24 or later. The byward image has no Node: run the byward
binary on a host that has Node, or build your own image from a Node image and copy byward in
([stdio upstream](../stdio-upstream.md#6-container-image)). Install a pinned version, so each
process starts without `npx` (the launcher costs about 40 % of a Node process's memory):

```dockerfile
FROM node:26-slim
RUN npm install -g mongodb-mcp-server@3.3.0
COPY --from=ghcr.io/byward-dev/byward:<version> /usr/local/bin/byward /usr/local/bin/byward
COPY --from=ghcr.io/byward-dev/byward:<version> --chown=node:node /var/lib/byward /var/lib/byward
USER node
ENTRYPOINT ["/usr/local/bin/byward"]
```

On a host, `npm install -g mongodb-mcp-server@3.3.0` does the same.

## 3. Run byward with the server as its upstream

Put the connection string and the server's options in an env file, mode `0600`, so the secret
stays out of the command line and the startup log:

```sh
# /run/secrets/mongodb-mcp-env
MDB_MCP_CONNECTION_STRINGS={"preconfigured":"mongodb://mcp-reader:<password>@db.internal:27017/?authSource=admin"}
MDB_MCP_TRANSPORT=stdio
MDB_MCP_READ_ONLY=true
MDB_MCP_DISABLED_TOOLS=connect,atlas,atlas-local,assistant
MDB_MCP_ALLOW_REQUEST_OVERRIDES=false
MDB_MCP_TELEMETRY=disabled
DO_NOT_TRACK=1
```

```sh
BYWARD_UPSTREAM_COMMAND='["/usr/local/bin/mongodb-mcp-server"]'
BYWARD_UPSTREAM_ENV_FILE=/run/secrets/mongodb-mcp-env
BYWARD_STDIO_MAX_PROCESSES=32
BYWARD_STDIO_MAX_PROCESSES_PER_USER=4
```

Add these to your usual settings, for example those of the
[Entra quickstart](../quickstart-entra.md#3-run-byward) or the [OIDC guide](../oidc.md).

- `MDB_MCP_CONNECTION_STRINGS` names the connection `preconfigured`; tools take it as their
  `connectionId`. (`MDB_MCP_CONNECTION_STRING` still works in 3.3.0 but is deprecated.)
- `MDB_MCP_TRANSPORT=stdio` is the default, set explicitly: the process speaks to byward on its
  standard input and output and opens no port.
- `MDB_MCP_READ_ONLY=true` (the `--readOnly` flag) offers only the tools of the `read`, `connect`
  and `metadata` operation types; no tool that creates, updates or deletes is listed.
- `MDB_MCP_DISABLED_TOOLS=connect,atlas,atlas-local,assistant` removes the `connect` tools, so a
  user cannot open a connection to another deployment; the Atlas administration tools; the Atlas
  Local tools, which manage local Docker deployments on byward's host; and the MongoDB Assistant
  tools, which call `knowledge.mongodb.com`.
- `MDB_MCP_ALLOW_REQUEST_OVERRIDES=false` is the default, set explicitly: no request can change
  the server's settings. The server reads such overrides only from HTTP request headers and query
  parameters, which a stdio process never receives.
- `MDB_MCP_TELEMETRY=disabled` and `DO_NOT_TRACK=1` turn off the server's telemetry.

The database user's role is still the real limit: read-only mode only removes tools.

**Size the two limits by memory.** Each process used about 190 MB in the verified run, started
directly without `npx`; plan on 200 MB. With the limits above, byward runs at most 32 processes
(about 6.4 GB) and at most 4 for one user. How many processes a user gets depends on the MCP
revision their client speaks ([stdio upstream](../stdio-upstream.md#4-limits)): with MCP
2025-11-25, one per MCP session, so a user with two open sessions has two processes.

## 4. Or: one shared server over HTTP

Use this when one server process for everyone is enough. The server runs over HTTP and refuses,
with a 403, every request without a header holding a secret; byward sends that secret on every
request and removes any copy a client sends. Unlike the stdio pattern, all users share one process
and one MongoDB connection: the server does not tell them apart.

Choose the secret:

```sh
(umask 077; openssl rand -hex 24 > upstream-key)
```

Run the server with its settings in an env file, mode `0600`:

```sh
# mongodb-mcp.env
MDB_MCP_CONNECTION_STRINGS={"preconfigured":"mongodb://mcp-reader:<password>@mongodb:27017/?authSource=admin"}
MDB_MCP_TRANSPORT=http
MDB_MCP_HTTP_HOST=0.0.0.0
MDB_MCP_DANGEROUS_HOST_BINDING=true
MDB_MCP_HTTP_PORT=3000
MDB_MCP_HTTP_HEADERS={"x-byward-key":"<the content of upstream-key>"}
MDB_MCP_READ_ONLY=true
MDB_MCP_DISABLED_TOOLS=connect,atlas,atlas-local,assistant
MDB_MCP_ALLOW_REQUEST_OVERRIDES=false
MDB_MCP_TELEMETRY=disabled
DO_NOT_TRACK=1
```

```sh
docker run -d --name mongodb-mcp --network <byward's network> --env-file mongodb-mcp.env \
  mongodb/mongodb-mcp-server:3.3.0
```

- `MDB_MCP_HTTP_HEADERS` is a JSON object of header names and values. A request without the
  header, or with another value, gets `403 {"error":"Invalid value for header \"x-byward-key\""}`.
- `MDB_MCP_HTTP_HOST=0.0.0.0` lets byward reach the server across the container network, which
  needs `MDB_MCP_DANGEROUS_HOST_BINDING=true`. Publish no port: only byward's network may reach it.
- The other settings are those of section 3.

Then give byward the server's URL and the secret as its upstream credential
([upstream credential](../upstream-credential.md)):

```sh
BYWARD_UPSTREAM_URL=http://mongodb-mcp:3000/mcp
BYWARD_UPSTREAM_CREDENTIAL_FILE=/run/secrets/upstream-key
BYWARD_UPSTREAM_CREDENTIAL_HEADER=X-Byward-Key
```

byward also sends its [identity assertion](../identity-assertion.md) in `Authorization`;
mongodb-mcp-server ignores it.

## 5. Connect a client

Connect the MCP client to byward's public URL as in the
[Entra quickstart](../quickstart-entra.md#4-connect-claude-code). The first request opens the
sign-in page. Afterwards the client lists the server's read tools, such as `find` and `aggregate`,
and calls them with `"connectionId": "preconfigured"`.

## What to check in the logs

- Each sign-in writes a `login` and a `token_issued` audit record with the user's `user_key`
  ([audit events](../../reference/observability.md#events-and-ocsf-mapping)).
- With the stdio pattern, each new process logs `upstream process started` with its `process`
  (PID) and `user_key`.
- byward's request lines for `/mcp` carry the `request_id` and the status, not the user: a tool call
  is tied to a user through their sign-in, or through their process.

## How this was verified

On 2026-11-19, on one machine (macOS, arm64):

| Part | Version | How it ran |
|---|---|---|
| MongoDB | 8.2.12 (`mongo`) | Docker, with a root user, the `shop` and `hr` databases, and `mcp-reader` with `read` on `shop` only |
| mongodb-mcp-server | 3.3.0 | stdio: from npm, installed in a local directory, run by byward with the host's Node 25.1.0. HTTP: Docker (`mongodb/mongodb-mcp-server`), its port published on loopback only for the direct calls |
| IdP | byward's fake OIDC IdP (`internal/testutil/fakeidp`, generic profile) | in the test driver, signing in `alice` and then `bob` |
| byward | `main` (13a7fc4a) | the binary on the host, with `--dev` (the fake IdP served http on loopback) and the settings above |

The image in section 2 was not built: the stdio run used the byward binary on the host. A scripted
MCP client, speaking MCP 2025-11-25, signed in through byward's consent page and the fake IdP,
once as each user, and called the server's tools through byward, for each pattern:

1. Without a token, byward answered `401`.
2. `tools/list` listed `aggregate`, `find`, `count`, `list-databases`, `list-collections` and the
   other read tools, and no `insert-many`, `connect`, Atlas, Atlas Local or Assistant tool. Calling
   `insert-many` got "Tool insert-many not found". (Without `atlas-local` in the disabled list, the
   stdio process also listed `atlas-local-list-deployments`.)
3. `find` on `shop.orders` returned its 3 documents, for each user. `find` on `hr.salaries` got
   MongoDB's "not authorized on hr".
4. stdio: `ps` showed two `mongodb-mcp-server` processes, both children of byward, of about 190 MB
   each; byward logged `upstream process started` for one with `user_key` `alice-sub-208` and for
   the other with `bob-sub-208`. Each user's calls ran in a MongoDB session of their own.
5. HTTP: the client also sent its own `X-Byward-Key: client-supplied`, and the calls still worked,
   because byward replaced it with the credential. Called directly, bypassing byward, the server
   answered `403 Invalid value for header "x-byward-key"` without the header and with a wrong
   value. Both users' calls ran in the same MongoDB session.
6. byward's audit had a `login` and a `token_issued` record for each of `user_key` `alice-sub-208`
   and `bob-sub-208`.
