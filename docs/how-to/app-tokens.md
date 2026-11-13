# Let headless callers in with Entra app-only tokens

CI jobs, scheduled tasks, managed identities and agents cannot open a browser to sign in. With
`BYWARD_APP_TOKENS=entra`, they can call the MCP endpoint with an **app-only token** that Entra issued
to their own app registration or managed identity (client credentials), sent as
`Authorization: Bearer <token>`. Users keep signing in through byward as before. Decision:
[ADR-0022](../adr/0022-machine-to-machine.md).

This works with Entra only (`BYWARD_IDP=entra`, the default). It is off by default.

## 1. Give the caller a role on the proxy's app

`byward init entra` already creates the app role `byward.app` for applications, turns on
**assignment required**, and adds the `idtyp` optional claim to access tokens
([commands](../reference/commands.md#byward-init-entra)). With an app registration made by hand, add
all three:

- an app role whose allowed member types include **Applications**;
- the `idtyp` optional claim on access tokens. Without it, an app-only token cannot be told from a
  user's, and byward refuses it; `byward doctor` fails its "entra idtyp claim" check while app-only
  tokens are on;
- `requestedAccessTokenVersion: 2`, as the quickstart sets for users.

Then assign the role to each caller: the caller's service principal or managed identity gets the
`byward.app` role on the proxy's enterprise application. A caller without a role still gets a token
from Entra unless assignment required is on, and byward then refuses it with `403`.

## 2. Turn it on

| Setting | Example | What it does |
|---|---|---|
| `BYWARD_APP_TOKENS` | `entra` | accept Entra app-only tokens at the MCP endpoint (default `off`) |
| `BYWARD_APP_ROLES` | `byward.app` | required: the caller needs at least one of these app roles |
| `BYWARD_APP_CLIENT_IDS` | `<caller's application ID>` | optional: only these callers (`azp`), each also needing a role |

`BYWARD_GATE_TENANTS`, when set, applies to app-only callers too. The user [access gate](access-gate.md)'s
roles and groups do not: users and apps have their own lists.

byward refuses to start with app-only tokens on and no app role, since a token proves only that some
service principal of the tenant got it. The startup log says that app-only tokens are accepted and
for which roles.

## 3. Get a fresh token on every run

The caller asks Entra for a token for the scope `api://<proxy's client ID>/.default` and sends it to
the MCP endpoint. Tokens last 60 to 90 minutes
([Microsoft](https://learn.microsoft.com/entra/identity-platform/access-tokens)), so fetch one per
run rather than storing it.

**Claude Code** runs a `headersHelper` command at every connection and takes the JSON object it
prints as the request headers. When a tool call gets a `401` or `403`, it runs the helper again,
reconnects and retries the call once; a credential refused while connecting fails the connection
([Claude Code MCP docs](https://code.claude.com/docs/en/mcp)). So a role missing from the start
shows up as a failed connection, not a retry loop. In `.mcp.json`:

```json
{
  "mcpServers": {
    "byward": {
      "type": "http",
      "url": "https://mcp.example.com/mcp",
      "headersHelper": "./get-byward-token.sh"
    }
  }
}
```

`get-byward-token.sh`, with the Azure CLI signed in as the caller:

```sh
#!/bin/sh
set -eu
token=$(az account get-access-token --scope "api://<proxy's client ID>/.default" --query accessToken -o tsv)
printf '{"Authorization":"Bearer %s"}' "$token"
```

Claude Code removes environment variables whose names look like credentials (`TOKEN`, `SECRET`,
`KEY`, …) before running the helper of a project `.mcp.json`, so the helper should get its token
from the Azure CLI's own sign-in, not from such a variable.

**A managed identity** (an Azure VM, container or function) signs the Azure CLI in with
`az login --identity` (`--client-id <id>` for a user-assigned one), then runs the same helper.
Role changes for a managed identity can take **several hours** to show in its tokens, because Azure
caches them ([Microsoft](https://learn.microsoft.com/entra/identity/managed-identities-azure-resources/managed-identity-best-practice-recommendations)).
To cut an identity off at once, use `revoke-user` (below).

**GitHub Actions** signs in to Entra with OIDC, with no secret in the repository: give an app
registration a federated credential for the repository
([Microsoft](https://learn.microsoft.com/azure/developer/github/connect-from-azure-openid-connect)),
assign that app the role from step 1, and log in with
[`azure/login`](https://github.com/Azure/login):

```yaml
permissions:
  id-token: write
steps:
  - uses: azure/login@v3
    with:
      client-id: ${{ vars.AZURE_CLIENT_ID }}
      tenant-id: ${{ vars.AZURE_TENANT_ID }}
      allow-no-subscriptions: true
  - run: claude -p "..."   # .mcp.json with the headersHelper above
```

Other clients that take a static header can use `${VAR}` in `.mcp.json` headers, with the variable
set from `az account get-access-token` just before the run. A token in a variable expires within the
hour, so set it per run.

## What byward checks

Every request, since an app has no grant (ADR-0022 §3, §4):

- the signature, from the tenant's keys, with `alg` `RS256` and header `typ` `JWT`;
- `iss`: the v2 issuer of the configured tenant (with `organizations`, of an allowed tenant), and
  `ver` 2.0; `aud`: the proxy's client ID only;
- `exp`, `iat` and `nbf`, with 30 seconds of clock skew;
- `idtyp` is `app` and there is no `scp`, so a user's token is never taken as an app's;
- the caller holds one of `BYWARD_APP_ROLES`, is in `BYWARD_APP_CLIENT_IDS` when set, and its tenant
  is in `BYWARD_GATE_TENANTS` when set;
- `revoke-user` has not cut the caller off.

The token's format picks the check: a token starting `byw_` is a proxy token and is checked only as
one; a three-part JWT is checked only as an app-only token; a token that fails is never tried the
other way.

| Answer | When |
|---|---|
| `401 invalid_token` | the token is invalid, expired, a user's, or revoked, or the tenant's keys could not be fetched, or the revocation list could not be checked |
| `403 insufficient_scope` | the token is valid, but the caller lacks a role or is not on a list |

## What the upstream sees

The caller's token never reaches the upstream. An HTTP upstream gets byward's
[identity assertion](identity-assertion.md) with `principal_type: client`, `sub` the service
principal's `tid:oid`, `client_id` the caller's application ID, and `roles` its app roles; with
[plain identity headers](plain-identity-headers.md) on, `X-Byward-Principal-Type: client` says the
same. A stdio
upstream gets one process per caller, with `BYWARD_PRINCIPAL_TYPE=client` and `BYWARD_SUBJECT` its
`tid:oid`; users get `BYWARD_PRINCIPAL_TYPE=user`. A user and an app never share a process or an MCP
session.

There is no consent page, refresh or On-Behalf-Of for app-only callers.

## Cut a caller off

Remove its role assignment in Entra; tokens it already holds keep working until they expire (an hour
or more, several hours for managed identities). To end its access at once:

```sh
byward revoke-user <tenant ID>:<service principal object ID>
```

Tokens issued before that moment are refused; a token Entra issues after it works again unless the
role is gone too. Expect the caller to stay out until the tokens it holds expire, up to about an
hour: in the real-tenant test (2026-11-13), both the Azure CLI 2.92.0 (even after `az logout` and
`az login`) and Entra's token endpoint itself kept returning tokens issued before the revocation.
Remove the role assignment as well when the caller must stay out. byward assumes an object ID is never both a user's and a service principal's in one
tenant; Microsoft describes `oid` as identifying "the user or service principal" but does not state
that the two never share a value [unverified].

## Watch it

- Audit: `app_token_accepted` once per token (by Entra's `uti`), and `app_token_rejected` with the
  reason ([observability](../reference/observability.md)).
- Metrics: `byward_app_tokens_total{outcome}` counts every request.
