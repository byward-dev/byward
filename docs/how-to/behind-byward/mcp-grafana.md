# mcp-grafana behind byward: each user is themselves in Grafana

> Verified on 2026-11-15 with mcp-grafana 2.3.0 and Grafana OSS 13.3.1 (both released 2026-11-10),
> Keycloak 26.8.0 and byward built from `main`, as described in [How this was verified](#how-this-was-verified).
> Not run: Entra, Okta and the other IdPs, `jwk_set_url`, and a user with no Grafana role.

[mcp-grafana](https://github.com/grafana/mcp-grafana) talks to Grafana for every tool call. Behind
byward, each call runs **as the signed-in user, with their Grafana role**:

1. byward signs the user in at the IdP and sends mcp-grafana its
   [identity assertion](../identity-assertion.md) in a header, `X-JWT-Assertion`.
2. mcp-grafana copies that header to every Grafana request (`GRAFANA_FORWARD_HEADERS`, streamable
   HTTP only).
3. Grafana's [JWT authentication](https://grafana.com/docs/grafana/latest/setup-grafana/configure-access/configure-authentication/jwt/)
   verifies it against byward's keys, signs the user in (or creates them), and maps byward's
   `roles` claim to Viewer, Editor or Admin.

No On-Behalf-Of and no IdP-specific Grafana setup: Grafana sees only byward's assertion. The IdP
must put the user's roles in the ID token, as Keycloak (a realm-role mapper) and Entra (app roles)
do; for another OIDC IdP, name its claim with `BYWARD_OIDC_ROLES_CLAIM` (since
v0.3.0; [OIDC](../oidc.md)).
**Google cannot:** its ID token has no roles claim
([Google](../google.md)), so Grafana can map no role, and with `role_attribute_strict = true` it
refuses every user. With Google, give users a Grafana role some other way, or use another IdP.

## byward

```sh
BYWARD_UPSTREAM_URL=http://mcp-grafana:8000/mcp
BYWARD_ASSERTION_HEADER=X-JWT-Assertion
BYWARD_ASSERTION_CLAIMS=roles,email,name
# mcp-grafana's own caller token, sent as Authorization (see below):
BYWARD_UPSTREAM_CREDENTIAL_FILE=/run/secrets/mcp-grafana-token   # holds: Bearer <token>
# the headers mcp-grafana reads from a client per call (see below):
BYWARD_UPSTREAM_STRIP_HEADERS=X-Grafana-Service-Account-Token,X-Grafana-API-Key,X-Grafana-Org-Id,X-Grafana-URL
```

- The assertion goes in `X-JWT-Assertion`, so `Authorization` is free for mcp-grafana's own token.
  byward removes every client copy of both headers before setting its own.
- `sub` is the identity, and it becomes the Grafana login: with Keycloak, the user's ID such as
  `a5e8280e-…`, not their user name. Grafana needs `email` and `name` only to show the user nicely.
- With Entra, `email` is asserted only with `BYWARD_ASSERTION_UNVERIFIED_EMAIL=true`, marked
  `email_verified: false`. Grafana uses it for display here, never to authorize.

## mcp-grafana

```sh
mcp-grafana -t streamable-http --address 0.0.0.0:8000 --allowed-hosts mcp-grafana:8000
GRAFANA_URL=http://grafana:3000
GRAFANA_FORWARD_HEADERS=X-JWT-Assertion
MCP_GRAFANA_SERVER_TOKEN=<token>          # byward sends it as Authorization: Bearer <token>
# no GRAFANA_SERVICE_ACCOUNT_TOKEN: the user's JWT is the only Grafana credential
# GRAFANA_ALLOW_URL_OVERRIDE unset: the per-request X-Grafana-URL stays off (the default)
```

- **No service account:** mcp-grafana starts and works without `GRAFANA_SERVICE_ACCOUNT_TOKEN`. In
  the run, Grafana had no service account at all; every call ran as the user.
- **The image** (`grafana/mcp-grafana:2.3.0`; the tags have no `v`) starts with `--transport sse`
  in its entrypoint. Replace the entrypoint to get streamable HTTP:
  `docker run --entrypoint /app/mcp-grafana grafana/mcp-grafana:2.3.0 -t streamable-http …`.
- `--allowed-hosts` must list the Host byward sends: the host and port of `BYWARD_UPSTREAM_URL`.
- `MCP_GRAFANA_SERVER_TOKEN` makes mcp-grafana refuse anything that does not come through byward.
  It must not be combined with `GRAFANA_FORWARD_HEADERS=Authorization`, which mcp-grafana refuses
  at startup; forwarding `X-JWT-Assertion` avoids that.
- mcp-grafana reports anonymous usage statistics to Grafana Labs by default; it logs this at
  startup. `GRAFANA_USAGE_STATS=disabled` turns it off.

## Grafana

```ini
[auth.jwt]
enabled = true
header_name = X-JWT-Assertion
username_claim = sub
email_claim = email
jwk_set_file = /etc/grafana/byward-jwks.json      ; byward jwks > byward-jwks.json
expect_claims = {"iss": "https://mcp.example.com", "aud": "http://mcp-grafana:8000/mcp"}
role_attribute_path = contains(roles[*], 'grafana-admin') && 'Admin' || contains(roles[*], 'grafana-editor') && 'Editor' || contains(roles[*], 'grafana-viewer') && 'Viewer'
role_attribute_strict = true
auto_sign_up = true
```

- **The `Bearer ` prefix:** byward sends `X-JWT-Assertion: Bearer <JWT>`, and Grafana strips the
  prefix from whatever header it reads (`retrieveToken` in Grafana's
  `pkg/services/authn/clients/jwt.go`). No raw-JWT option is needed.
- **Keys:** a pinned `byward jwks` export (`jwk_set_file`) is the safe choice: Grafana's
  `jwk_set_url` would fetch the internal listener's JWKS over plain http, which is safe only on the
  same host or under a NetworkPolicy and mesh mTLS
  ([identity assertion](../identity-assertion.md#2-point-the-upstream-at-the-public-keys)). With the
  public https JWKS reachable, `jwk_set_url = https://mcp.example.com/.well-known/jwks.json` should
  work too (not run). Re-export the file when you rotate the assertion key.
- **`expect_claims`** must match exactly: `iss` is byward's public origin, without the `/mcp` path;
  `aud` is `BYWARD_UPSTREAM_URL` exactly as set.
- **`role_attribute_strict = true`** denies a user with none of the roles, instead of giving them
  `auto_assign_org_role`.

## Strip the client's `X-Grafana-*` headers

mcp-grafana reads some request headers per call, over streamable HTTP:

| Header | What a client could do with it |
|---|---|
| `X-Grafana-Service-Account-Token` | send another Grafana credential with the user's assertion |
| `X-Grafana-API-Key` | the same, deprecated name |
| `X-Grafana-Org-Id` | pick another organization |
| `X-Grafana-URL` | pick another Grafana (only with URL override on, which is off here) |

`BYWARD_UPSTREAM_STRIP_HEADERS` (in [byward](#byward) above) removes all four from every client
request. In the run:

- With the setting, a client's `X-Grafana-Org-Id: 2` and `X-Grafana-Service-Account-Token` changed
  nothing: the user stayed in organization 1.
- Without it, `X-Grafana-Org-Id: 2` reached mcp-grafana and switched the user's current
  organization to 2. A bogus service account token reached Grafana too, but Grafana's JWT
  authentication runs before its API-token check, so the user's assertion still won. Strip all four
  anyway: nothing else stops a client from choosing what mcp-grafana sends Grafana.

## How this was verified

On 2026-11-15, on one machine:

| Part | Version | How it ran |
|---|---|---|
| Grafana OSS | 13.3.1 (`grafana/grafana`) | Docker, with the `[auth.jwt]` settings above as `GF_AUTH_JWT_*` |
| mcp-grafana | 2.3.0 (`grafana/mcp-grafana`) | Docker, with the settings above and no `GRAFANA_SERVICE_ACCOUNT_TOKEN` |
| Keycloak | 26.8.0 | Docker, `start-dev`, as in [Keycloak](../keycloak.md#try-it-on-your-machine) |
| byward | `main` | the binary on the host, with `--dev` (Keycloak served http on loopback) |

The Keycloak realm had the realm roles `grafana-editor` and `grafana-viewer`, a realm-role mapper
named `roles` on byward's client ([OIDC](../oidc.md)), `alice` with `grafana-editor` and `bob` with
`grafana-viewer`. A scripted MCP client registered with byward, signed in as each user through
byward's consent page and Keycloak's login, and called mcp-grafana's tools through byward:

1. `user_info` returned each user's login (their Keycloak ID), email and name, with role **Editor**
   for alice and **Viewer** for bob in organization 1. Grafana created both users on first use,
   marked as JWT users.
2. As bob, `update_dashboard` failed with Grafana's 403: "Permissions needed: any of
   dashboards:create, dashboards:write". As alice, it created the dashboard, which Grafana recorded
   as created by alice.
3. Grafana had no service account: no call used any credential but the user's assertion.
4. The strip results are in [Strip the client's headers](#strip-the-clients-x-grafana--headers).
