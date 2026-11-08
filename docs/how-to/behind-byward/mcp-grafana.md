# mcp-grafana behind byward: each user is themselves in Grafana

> **Status: draft, not yet verified end to end.** The settings below come from each project's docs
> and code (checked 2026-11-08). The items marked **[verify]** are confirmed by the run in
> [Verify it](#verify-it); until then, treat them as expected, not known.

[mcp-grafana](https://github.com/grafana/mcp-grafana) (v2.2.0, 2026-11-02) talks to Grafana for
every tool call. Behind byward, each call can run **as the signed-in user, with their Grafana role**:

1. byward signs the user in at the IdP and sends mcp-grafana its
   [identity assertion](../identity-assertion.md) in a header, `X-JWT-Assertion`.
2. mcp-grafana copies that header to every Grafana request (`GRAFANA_FORWARD_HEADERS`, streamable
   HTTP only).
3. Grafana's [JWT authentication](https://grafana.com/docs/grafana/latest/setup-grafana/configure-access/configure-authentication/jwt/)
   verifies it against byward's keys, signs the user in (or creates them), and maps byward's
   `roles` claim to Viewer, Editor or Admin.

No On-Behalf-Of and no IdP-specific Grafana setup: it works the same with Entra, Okta, Google or
Keycloak.

## byward

```sh
BYWARD_UPSTREAM_URL=http://mcp-grafana:8000/mcp
BYWARD_ASSERTION_HEADER=X-JWT-Assertion
BYWARD_ASSERTION_CLAIMS=roles,email,name
# mcp-grafana's own caller token, sent as Authorization (see below):
BYWARD_UPSTREAM_CREDENTIAL_FILE=/run/secrets/mcp-grafana-token   # holds: Bearer <token>
```

- The assertion goes in `X-JWT-Assertion`, so `Authorization` is free for mcp-grafana's own token.
  byward removes every client copy of both headers before setting its own.
- Grafana needs `email` and `name` only to show the user nicely; `sub` is the identity.
- With Entra, `email` is asserted only with `BYWARD_ASSERTION_UNVERIFIED_EMAIL=true`, marked
  `email_verified: false`. Grafana uses it for display here, never to authorize.

## mcp-grafana

```sh
mcp-grafana -t streamable-http --address 0.0.0.0:8000 --allowed-hosts mcp-grafana:8000
GRAFANA_URL=http://grafana:3000
GRAFANA_FORWARD_HEADERS=X-JWT-Assertion
MCP_GRAFANA_SERVER_TOKEN=<token>          # byward sends it as Authorization: Bearer <token>
# no GRAFANA_SERVICE_ACCOUNT_TOKEN: the user's JWT is the only Grafana credential [verify]
# GRAFANA_ALLOW_URL_OVERRIDE unset: the per-request X-Grafana-URL stays off (the default)
```

- `--allowed-hosts` must list the Host byward sends, the host and port of `BYWARD_UPSTREAM_URL`.
- `MCP_GRAFANA_SERVER_TOKEN` makes mcp-grafana refuse anything that does not come through byward.
  It must not be combined with `GRAFANA_FORWARD_HEADERS=Authorization`, which mcp-grafana refuses
  at startup; forwarding `X-JWT-Assertion` avoids that.

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

- **Keys:** a pinned `byward jwks` export (`jwk_set_file`) is the safe choice: Grafana's
  `jwk_set_url` would fetch the internal listener's JWKS over plain http, which is safe only on the
  same host or under a NetworkPolicy and mesh mTLS
  ([identity assertion](../identity-assertion.md#2-point-the-upstream-at-the-public-keys)). With the
  public https JWKS reachable, `jwk_set_url = https://mcp.example.com/.well-known/jwks.json` works
  too. Re-export the file when you rotate the assertion key.
- **`expect_claims`** must match exactly: `iss` is byward's public origin, `aud` is
  `BYWARD_UPSTREAM_URL` exactly as set.
- **`role_attribute_strict = true`** denies a user with none of the roles, instead of giving them
  `auto_assign_org_role`.
- **The `Bearer ` prefix [verify]:** byward sends `X-JWT-Assertion: Bearer <JWT>`. Grafana's docs do
  not say whether it strips the prefix from a custom header. If it does not, byward needs an option
  to send the raw JWT (to be filed).

## Known gap: client-supplied `X-Grafana-*` headers

byward does not remove `X-Grafana-*` headers a client sends. mcp-grafana reads some per request:
`X-Grafana-Service-Account-Token` (a Grafana credential for that call) and `X-Grafana-Org-Id` (the
organization). So a client could choose another credential or organization than the user's
assertion gives. Until byward can strip extra headers (to be filed), only use MCP clients you
trust not to send them, or put a proxy in front of mcp-grafana that removes them.

## Verify it

A run with Grafana OSS in Docker, a Keycloak realm with two users (as byward's Keycloak lane sets
up), mcp-grafana and byward:

1. **Two users:** `alice` with realm role `grafana-editor`, `bob` with `grafana-viewer`; a realm-role
   mapper named `roles` on byward's client (as in [the OIDC how-to](../oidc.md)).
2. Sign in as each through an MCP client; call `user_info`: it returns that user's login, and the
   role in the current organization is Editor for alice, Viewer for bob.
3. As bob, try to create a dashboard: Grafana denies it.
4. With mcp-grafana's `GRAFANA_SERVICE_ACCOUNT_TOKEN` unset, mcp-grafana starts and Grafana sees only
   the forwarded JWT.
5. The `Bearer ` prefix question above is answered by step 2 working (or failing with Grafana's
   "invalid JWT" error).
6. A client-sent `X-Grafana-Org-Id: 2` changes the organization (expected, the known gap).

Versions to pin in the run: Grafana OSS 13.3.0 (2026-10-27), mcp-grafana 2.2.0 (2026-11-02),
Keycloak 26.8.0 (as byward's lane), and byward at the commit under test.
