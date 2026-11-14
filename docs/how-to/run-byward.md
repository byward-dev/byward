# Run byward

This page takes you from an app registered at your IdP to a running proxy: the data directory, the
keys, the settings, and the proxy itself, as a container or as a binary. It is the same for every
IdP; only the IdP's own settings differ, and those come from your IdP guide.

1. [Register the proxy at your IdP](#1-register-the-proxy-at-your-idp)
2. [Create the keys](#2-create-the-keys)
3. [Collect the settings](#3-collect-the-settings)
4. [Start the proxy](#4-start-the-proxy)
5. [Check it](#5-check-it)
6. [Connect a client](#6-connect-a-client)

**You need** a public HTTPS host for the proxy (`mcp.example.com` below), an HTTP MCP server to
protect, `openssl`, and the image `ghcr.io/byward-dev/byward:v0.2.0-rc.1` or the `byward` binary of
that release ([what a release contains](../reference/packaging.md#what-a-release-contains)).

## 1. Register the proxy at your IdP

Follow the first steps of your IdP's guide, up to its byward settings, and keep the client secret or
key file it gives you:

| IdP | Guide | `BYWARD_IDP` |
|---|---|---|
| Microsoft Entra ID | [quickstart](quickstart-entra.md#1-register-the-entra-app) | `entra` (the default) |
| Google | [Google](google.md#1-the-oauth-client) | `google` |
| Okta | [Okta](okta.md#1-the-app) | `okta` |
| Auth0 | [Auth0](auth0.md) | `auth0` |
| Keycloak | [Keycloak](keycloak.md#1-the-realm-and-the-client) | `keycloak` |
| Any other OpenID Connect IdP | [OIDC](oidc.md#1-register-the-proxy-at-the-idp) | `oidc` |

The callback URL to register is `https://<public host>/callback/<idp>`, with the `BYWARD_IDP` value
as `<idp>`.

## 2. Create the keys

byward keeps its keys, its client list and its state in one **data directory**: `/var/lib/byward`
by default, or the absolute path in `BYWARD_DATA_DIR`. Below it is `./byward-data`.

Create the first sealing key, which seals the proxy's tokens ([sealing keys](sealing-keys.md)):

```sh
install -d -m 0700 byward-data/keys && (umask 077; openssl rand -base64 32 > "byward-data/keys/$(date -u +%Y-%m-%d)")
```

And the key that signs the identity assertion the upstream receives
([identity assertion](identity-assertion.md)):

```sh
install -d -m 0700 byward-data/assertion-keys && (umask 077; openssl genpkey -algorithm EC \
  -pkeyopt ec_paramgen_curve:P-256 -out "byward-data/assertion-keys/$(date -u +%Y-%m-%d)")
```

Once the proxy has run, the data directory holds:

```text
byward-data/
├── keys/             sealing keys
├── assertion-keys/   identity assertion signing keys
├── clients.json      static clients, optional (static-clients.md)
├── state/            the SQLite store, created on first start; back this up (state.md)
└── store-writes      restore-detection counter, kept outside state/
```

Each path has a setting of its own (`BYWARD_KEYS_DIR`, `BYWARD_ASSERTION_KEYS_DIR`,
`BYWARD_STATIC_CLIENTS_FILE`, `BYWARD_STORE_DIR`, `BYWARD_STORE_COUNTER_FILE`); see
[state and backups](state.md) and the [static clients reference](../reference/static-clients.md).
With the PostgreSQL store (on `main`), the state lives in the database instead
([PostgreSQL](postgres.md)).

## 3. Collect the settings

Every IdP needs these two:

| Setting | Value |
|---|---|
| `BYWARD_PUBLIC_URL` | `https://mcp.example.com/mcp`: the URL users enter |
| `BYWARD_UPSTREAM_URL` | your HTTP MCP server, reachable from where byward runs |

Then `BYWARD_IDP` and that IdP's settings, from its guide: `BYWARD_ENTRA_*` for Entra,
`BYWARD_OIDC_*` for the others, and the [access gate](access-gate.md) settings your guide recommends. Put
them in a file, one `NAME=value` per line, for example `byward.env` for an Okta app:

```sh
BYWARD_PUBLIC_URL=https://mcp.example.com/mcp
BYWARD_UPSTREAM_URL=http://upstream:3001/mcp
BYWARD_IDP=okta
BYWARD_OIDC_ISSUER=https://<domain>/oauth2/default
BYWARD_OIDC_CLIENT_ID=<client id>
BYWARD_OIDC_CLIENT_SECRET_FILE=/run/secrets/idp-client-secret
BYWARD_GATE_GROUPS=byward-users
```

Secrets are read only from files. A secret file that other users can read is refused at startup
(outside `--dev`), unless it is on a read-only mount: `chmod 600` it and make the proxy's user its
owner, or mount it read-only. Everything else has a default: [settings reference](../reference/settings.md).

## 4. Start the proxy

byward serves two listeners:

| Listener | Setting | Default | Serves |
|---|---|---|---|
| public | `BYWARD_LISTEN` | `127.0.0.1:8080` | the MCP endpoint, OAuth and discovery |
| internal | `BYWARD_INTERNAL_LISTEN` | `127.0.0.1:9090` | `/metrics`, `/livez` and `/readyz`, without authentication; empty turns it off |

The two must differ. Put your TLS terminator (reverse proxy, load balancer or tunnel) in front of
the public listener, or let byward serve TLS itself ([TLS](tls.md), on `main`). Never route the
internal listener through it ([hardening](harden-a-deployment.md#the-internal-listener)). At startup
the proxy logs each setting with its source, then `listening` and `internal listener` with their
addresses.

**As a container.** The image runs as uid 65532 with `/var/lib/byward` as its data directory. Inside
a container the default loopback addresses are unreachable from outside, so set `BYWARD_LISTEN`.
`--user` makes the proxy run as you, so it can write the data directory you created:

```sh
docker run --rm -p 8080:8080 --user "$(id -u):$(id -g)" \
  -v "$PWD/byward-data:/var/lib/byward" \
  -v "$PWD/idp-client-secret:/run/secrets/idp-client-secret:ro" \
  --env-file byward.env \
  -e BYWARD_LISTEN=0.0.0.0:8080 \
  ghcr.io/byward-dev/byward:v0.2.0-rc.1
```

Mount each secret file read-only, as above. Without `--user`, make the data directory writable by
uid 65532 instead. To reach the probes from the host, add `-e BYWARD_INTERNAL_LISTEN=0.0.0.0:9090
-p 127.0.0.1:9090:9090`; `127.0.0.1` inside a container is the container itself, which also applies
to `BYWARD_UPSTREAM_URL`.

**As a binary.** Unpack the release archive (`byward_<version>_linux_<arch>.tar.gz`; the darwin
archives are for development only). Fill in the placeholders in `byward.env`, then export the same settings, with `BYWARD_DATA_DIR` set to an
absolute path and the secret file paths pointing at your files, then run `byward`:

```sh
set -a; . ./byward.env; set +a
export BYWARD_DATA_DIR="$PWD/byward-data" BYWARD_OIDC_CLIENT_SECRET_FILE="$PWD/idp-client-secret"
./byward
```

A missing or empty key directory stops startup with a message naming the path and its setting. The
startup log also says which client sources are active, for example
`msg="client sources" static_clients=0 cimd=true dcr=true`.

## 5. Check it

- `byward check --offline`, with the same settings, validates them, the keys, the secret files'
  permissions and the clients file without network access
  ([reference](../reference/commands.md#byward-check---offline)). In the container:
  `docker run --rm … ghcr.io/byward-dev/byward:v0.2.0-rc.1 check --offline` with the same options.
- `byward doctor`, once the proxy runs, fetches its discovery documents the way MCP clients do and
  checks the IdP app ([checks](../reference/commands.md#checks)). For Entra it checks the tenant,
  the client ID and the credential; for the other IdPs, the discovery and client credential checks
  are on `main`.
- `curl http://127.0.0.1:9090/readyz` (the binary, or the container with the probes published)
  answers 200 when the proxy has a signing key and its store answers, and 503 otherwise.

## 6. Connect a client

Add `https://mcp.example.com/mcp` to your MCP client and sign in. For Claude Code, see
[Connect Claude Code](quickstart-entra.md#4-connect-claude-code); it works the same with every IdP.

## Next steps

- Deploy it for real users: [deploy](deploy.md).
- Work through the [hardening checklist](harden-a-deployment.md) before real users sign in.
- Restrict who may sign in with the [access gate](access-gate.md).
- Back up the state directory: [state and backups](state.md).
