# Quickstart: Microsoft Entra ID and Claude Code

This guide puts an HTTP MCP server behind byward, with users signing in through your
Microsoft Entra tenant and Claude Code as the MCP client. It takes four steps:

1. [Register the Entra app](#1-register-the-entra-app) (Azure CLI)
2. [Create the keys](#2-create-the-keys)
3. [Run byward](#3-run-byward)
4. [Connect Claude Code](#4-connect-claude-code)

Claude Code needs no registration: it identifies itself with its client metadata document (CIMD).
To give it a fixed client ID instead, see [Optional: Claude Code as a static
client](#optional-claude-code-as-a-static-client).

[Troubleshooting](#troubleshooting) lists the Entra errors the proxy recognises and what to fix.
Background: [ADR-0012](../adr/0012-entra-specifics.md) (Entra), [ADR-0008](../adr/0008-client-registration.md)
(clients), [ADR-0009](../adr/0009-redirect-uri-policy.md) (redirect URIs).

**You need:**

- a public HTTPS host for the proxy, called `mcp.example.com` below; the MCP endpoint is
  `https://mcp.example.com/mcp`. TLS can end at a reverse proxy, a load balancer or a tunnel in
  front of byward, or at byward itself with your certificate ([TLS](tls.md), on `main` only so far);
- the container image `ghcr.io/byward-dev/byward:v0.2.0-rc.1` or a later release, or the `byward`
  binary of that release. The `latest` tag is still v0.1.1 until v0.2.0 is final;
- the Azure CLI (`az`), signed in to your tenant (`az login --tenant <tenant-id>`) as a user who may
  create app registrations. Granting admin consent (optional, step 1.5) needs an administrator. In a
  checkout of this repository, `mise exec -- az` runs the pinned version;
- `uuidgen` and `openssl` (preinstalled on macOS and most Linux distributions);
- an HTTP MCP server to protect. To try the proxy first, run the MCP reference server in a pinned
  Node container, with the command under "You need" in [run byward](run-byward.md). Its endpoint is
  `http://upstream:3001/mcp` for byward in a container on the `byward` network, and
  `http://127.0.0.1:3001/mcp` for the `byward` binary on the same host.

## 1. Register the Entra app

**Shortcut:** `byward init entra --tenant <tenant-id> --public-url https://mcp.example.com/mcp >
byward-entra.sh` prints this whole step as a script, plus assignment required and the app roles
app-only callers need, and an env file for step 3. byward runs none of it; review it and run it
with `sh byward-entra.sh` ([commands reference](../reference/commands.md#byward-init-entra)). The
steps below explain each command.

The proxy is a confidential client of Entra. It needs one **single-tenant** app registration with:

| Property | Value | Why |
|---|---|---|
| Supported accounts | this tenant only (`AzureADMyOrg`) | single tenant is the default (ADR-0012 §2) |
| Web redirect URI | `https://<public-host>/callback/entra` | where Entra returns the user to the proxy |
| Application ID URI | `api://<application-id>` | prefix of the scope the proxy requests |
| Exposed delegated scope | `access_as_user` | the proxy asks for its own API's token at login (ADR-0012 §4) |
| `api.requestedAccessTokenVersion` | `2` | the proxy accepts only v2 tokens |
| Microsoft Graph delegated permissions | `openid`, `profile`, `email`, `offline_access` | sign-in, display name and refresh tokens |
| Client secret | written to a file | how the proxy authenticates to Entra |

At login the proxy requests exactly
`openid profile email offline_access api://<application-id>/access_as_user`. It does not call
Microsoft Graph, so `User.Read` is not needed. (The Entra admin center adds `User.Read` to new
registrations by default; the CLI does not. Leaving it there is harmless.)

### 1.1 Create the registration

```sh
PUBLIC_HOST=mcp.example.com
TENANT_ID=$(az account show --query tenantId -o tsv)
APP_ID=$(az ad app create --display-name byward --sign-in-audience AzureADMyOrg \
  --web-redirect-uris "https://$PUBLIC_HOST/callback/entra" --query appId -o tsv)
echo "tenant $TENANT_ID, client ID $APP_ID"
```

### 1.2 Expose the `access_as_user` scope with v2 tokens

`az ad app` has no flag for exposed scopes, so this step sets the Application ID URI, the scope and
the token version in one Microsoft Graph request:

```sh
SCOPE_ID=$(uuidgen | tr '[:upper:]' '[:lower:]')
cat > api.json <<EOF
{
  "identifierUris": ["api://$APP_ID"],
  "api": {
    "requestedAccessTokenVersion": 2,
    "oauth2PermissionScopes": [{
      "id": "$SCOPE_ID",
      "value": "access_as_user",
      "type": "User",
      "isEnabled": true,
      "adminConsentDisplayName": "Use MCP servers behind byward",
      "adminConsentDescription": "Lets byward sign users in and call MCP servers on their behalf.",
      "userConsentDisplayName": "Use MCP servers behind byward",
      "userConsentDescription": "Lets byward sign you in and call MCP servers on your behalf."
    }]
  }
}
EOF
az rest --method patch --url "https://graph.microsoft.com/v1.0/applications(appId='$APP_ID')" --body @api.json
rm api.json
```

The display names and descriptions are what Entra shows on its consent and admin pages; word them
for your users.

### 1.3 Add the OpenID Connect permissions

These are the Microsoft Graph delegated permissions `openid`, `profile`, `email` and
`offline_access` (their IDs are the same in every tenant; `az ad sp show --id
00000003-0000-0000-c000-000000000000 --query oauth2PermissionScopes` lists them):

```sh
az ad app permission add --id "$APP_ID" --api 00000003-0000-0000-c000-000000000000 \
  --api-permissions 37f7f235-527c-4136-accd-4a02d197296e=Scope 14dad69e-099b-42c9-810b-d002981feec1=Scope \
  64a6cdd6-aab1-4aaf-94b8-3cc8405e90d0=Scope 7427e0e9-2fba-42fe-b0c0-848c9e6a8182=Scope
```

The command prints a warning that `az ad app permission grant` is needed. Ignore it: users consent
at their first sign-in, or an administrator grants consent for everyone in step 1.5.

### 1.4 Create the service principal and the client secret

```sh
az ad sp create --id "$APP_ID" --query id -o tsv
(umask 077; az ad app credential reset --id "$APP_ID" --append --display-name byward --years 1 \
  --query password -o tsv > entra-client-secret)
```

The secret goes straight into the `0600` file `entra-client-secret` and is never shown; the warning
that "the output includes credentials" refers to that file. `--append` keeps any existing
credentials (without it the command removes them). The trailing newline is ignored by the proxy.

- Note the expiry (`--years 1` here; Entra allows at most two years) and rotate before it: add a
  new secret with the same command, restart the proxy with it, then delete the old one with
  `az ad app credential delete`. An expired secret makes every sign-in and refresh fail
  (AADSTS7000222, see [Troubleshooting](#troubleshooting)).
- Optional: set `BYWARD_ENTRA_CLIENT_SECRET_EXPIRES_AT` to the end date (one year from today here,
  e.g. `2027-11-06`). The proxy then warns at every start, and `byward doctor` from 30 days before.
- A client secret suits development and small setups. For production, ADR-0012 §5 and Microsoft
  recommend a certificate: `byward init entra --credential certificate`, or by hand with the
  [certificate how-to](entra-certificate.md).

### 1.5 Optional: grant admin consent

```sh
az ad app permission admin-consent --id "$APP_ID"
```

This records tenant-wide consent for the permissions from step 1.3, so no user is asked by Entra.
The Azure CLI documentation says this needs a Global Administrator. The grant can take a minute to
appear in `az ad app permission list-grants --id "$APP_ID"`.

**Without admin consent**, every user first sees the proxy's own consent page
([ADR-0010](../adr/0010-consent-screen.md)) and then signs in at Entra. Whether Entra adds a consent
screen of its own depends on the tenant's user-consent settings: in the project's real-tenant test,
these login scopes produced no Entra consent screen (ADR-0012), but a tenant that restricts user
consent can stop users with an approval request or AADSTS65001; a run with Claude Code on 2026-11-06
showed the proxy's consent page only. Admin consent is recommended in any case, and
[On-Behalf-Of](downstream-apis.md) needs it for the downstream API's permissions (ADR-0012 §12).

### 1.6 Optional: allow only assigned users

By default every user of the tenant can sign in. To limit sign-in to users and groups you assign to
the app (in the Entra admin center under **Enterprise applications**):

```sh
az ad sp update --id "$APP_ID" --set appRoleAssignmentRequired=true
```

Unassigned users then get AADSTS50105. The proxy's own [access gate](access-gate.md) can restrict
sign-in by app role or group as well.

## 2. Create the keys

byward keeps its keys, its client list and its state in one **data directory**
(`/var/lib/byward` by default; `BYWARD_DATA_DIR` moves it). Below it is `./byward-data`. The proxy
seals its tokens with keys you provide; create the first one (details and rotation:
[sealing keys](sealing-keys.md)):

```sh
install -d -m 0700 byward-data/keys && (umask 077; openssl rand -base64 32 > "byward-data/keys/$(date -u +%Y-%m-%d)")
```

It also signs the **identity assertion** that tells the upstream who the user is, with a key of
its own (details: [identity assertion](identity-assertion.md)):

```sh
install -d -m 0700 byward-data/assertion-keys && (umask 077; openssl genpkey -algorithm EC \
  -pkeyopt ec_paramgen_curve:P-256 -out "byward-data/assertion-keys/$(date -u +%Y-%m-%d)")
```

## 3. Run byward

Five settings ([ADR-0020](../adr/0020-configuration.md) §8); everything else has a default:

| Setting | Value |
|---|---|
| `BYWARD_PUBLIC_URL` | `https://mcp.example.com/mcp`: the URL users enter, behind your TLS terminator |
| `BYWARD_UPSTREAM_URL` | your HTTP MCP server, e.g. `http://upstream:3001/mcp` for the reference server from the container below, `http://127.0.0.1:3001/mcp` from the binary |
| `BYWARD_ENTRA_TENANT` | `$TENANT_ID` from step 1.1 |
| `BYWARD_ENTRA_CLIENT_ID` | `$APP_ID` from step 1.1 |
| `BYWARD_ENTRA_CLIENT_SECRET_FILE` | the `entra-client-secret` file from step 1.4 |

The data directory then holds:

```text
byward-data/
├── keys/             sealing keys (step 2)
├── assertion-keys/   identity assertion signing keys (step 2)
├── clients.json      static clients, optional (see the end of this guide)
├── state/            the SQLite store, created on first start; back this up (state.md)
└── store-writes      restore-detection counter, kept outside state/
```

With the container image. It runs as uid 65532 by default; `--user` makes it run as you, so it can
write the data directory you created:

```sh
docker run --rm --network byward -p 8080:8080 --user "$(id -u):$(id -g)" \
  -v "$PWD/byward-data:/var/lib/byward" \
  -v "$PWD/entra-client-secret:/run/secrets/entra-client-secret:ro" \
  -e BYWARD_PUBLIC_URL=https://mcp.example.com/mcp \
  -e BYWARD_UPSTREAM_URL=http://upstream:3001/mcp \
  -e BYWARD_ENTRA_TENANT="$TENANT_ID" \
  -e BYWARD_ENTRA_CLIENT_ID="$APP_ID" \
  -e BYWARD_ENTRA_CLIENT_SECRET_FILE=/run/secrets/entra-client-secret \
  -e BYWARD_LISTEN=0.0.0.0:8080 \
  ghcr.io/byward-dev/byward:v0.2.0-rc.1
```

Or with the binary: export the same five settings plus `BYWARD_DATA_DIR="$PWD/byward-data"` and run
`byward`. A missing or empty key directory stops startup with a message naming the path and the
setting that moves it. The clients file is optional while CIMD or DCR is on, as it is by default;
a `BYWARD_STATIC_CLIENTS_FILE` you set must exist. The startup log says which client sources are
active, for example `msg="client sources" static_clients=0 cimd=true dcr=true`.
`BYWARD_UPSTREAM_URL` must be reachable from where byward runs (from inside the container, `127.0.0.1` is the container itself). Put your TLS
terminator (reverse proxy or load balancer) in front of `:8080` so that `https://mcp.example.com`
reaches it, or have byward serve TLS itself ([TLS](tls.md)). All settings: [settings reference](../reference/settings.md).

To check the setup: `byward check --offline` with the same settings validates them, the key and the
clients file, if there is one, without network access. Once the proxy runs, `byward doctor` fetches its discovery
documents the way MCP clients do and checks the Entra tenant, the client ID and the secret; each
problem comes with its fix ([commands reference](../reference/commands.md#byward-doctor)).

## 4. Connect Claude Code

Add the server; Claude Code signs in with its client metadata document
(`https://claude.ai/oauth/claude-code-client-metadata`, [CIMD how-to](cimd.md)):

```sh
claude mcp add --transport http my-mcp https://mcp.example.com/mcp
```

Then sign in: run `/mcp` inside Claude Code, or `claude mcp login my-mcp` from a shell. The browser
shows the proxy's consent page, then Entra's sign-in. With the reference server behind the proxy,
ask Claude Code to call its `echo` tool to see a request go all the way through. This was verified
against Entra on 2026-11-06.

Claude Code registers the `refresh_token` grant, so it receives a refresh token and the consent page
says "up to 30 days". It renews its access token before the hour is up, without opening the browser (checked
with Claude Code 2.1.311 against a real tenant on 2026-11-06).

## Optional: Claude Code as a static client

Register Claude Code in the static clients file when you want a fixed client ID, or when you run
with `BYWARD_CIMD=false`. Claude Code is a public client: it has no secret and authenticates with
PKCE. Write `byward-data/clients.json`:

```json
{
  "clients": [
    {
      "client_id": "claude-code",
      "client_name": "Claude Code",
      "token_endpoint_auth_method": "none",
      "redirect_uris": [
        "http://localhost:8080/callback",
        "http://127.0.0.1:8080/callback"
      ]
    }
  ]
}
```

- **Register both host names.** The proxy accepts any port on a loopback redirect URI but matches
  the host literally, so `localhost` and `127.0.0.1` are separate entries (ADR-0009 §2). Current
  Claude Code sends `http://localhost:<port>/callback`; v2.1.229 sent
  `http://127.0.0.1:<port>/callback` instead (fixed in v2.1.231), and the second entry keeps that
  version working.
- The `client_id` is yours to choose: printable ASCII without spaces, at most 255 characters. The
  file accepts no unknown fields and no inline secrets.
- byward reads the file at startup; restart it after a change.

Add the server with the static client ID and a fixed callback port, without `--client-secret`:

```sh
claude mcp add --transport http --client-id claude-code --callback-port 8080 my-mcp https://mcp.example.com/mcp
```

`claude mcp get my-mcp` shows the configured OAuth client. The callback port must be free on the
machine running Claude Code. If it is taken, `claude mcp login` stops with "OAuth callback port …
is already in use"; `lsof -ti:<port> -sTCP:LISTEN` shows the process holding it. Pick another port
(remove the server with `claude mcp remove my-mcp` and add it again with the new
`--callback-port`); the registered `redirect_uris` need no change because the proxy ignores the
port on loopback.

Source: Claude Code MCP documentation, "Use pre-configured OAuth credentials" and "Use a fixed OAuth
callback port" (<https://code.claude.com/docs/en/mcp>).

## Next steps

- Work through the [hardening checklist](harden-a-deployment.md) before real users sign in.
- Restrict who may sign in with the [access gate](access-gate.md) (app roles, groups, tenants).
- Back up the state directory: [state and backups](state.md).
- Use a certificate instead of the client secret: [Entra certificate](entra-certificate.md).
- Let the MCP server call Microsoft Graph or another API as the user: [downstream APIs](downstream-apis.md).

## Troubleshooting

The proxy never shows Entra's raw error text. Users see a short message; the operator hint below is
logged with the AADSTS code, Entra's trace ID and correlation ID.

### Errors at sign-in

| Code | What the user sees | Fix |
|---|---|---|
| AADSTS50011 | The service is misconfigured. | The redirect URI is not registered: add `https://<public-host>/callback/entra` under the **Web** platform (step 1.1). It must match the host of `BYWARD_PUBLIC_URL` exactly. |
| AADSTS700016 | The service is misconfigured. | The client ID is not an app in this tenant: check `BYWARD_ENTRA_CLIENT_ID` and `BYWARD_ENTRA_TENANT`. |
| AADSTS65001 | This service has not been approved in your organisation yet. | Consent is missing: grant admin consent (step 1.5). |
| AADSTS50105 | You have not been given access to this service. | Assignment is required (step 1.6): assign the user, or a group they are in, to the enterprise application. |
| AADSTS50020 | Your account is not from the organisation this service belongs to. | The user's home tenant is not your tenant: invite them as a guest, or check `BYWARD_ENTRA_TENANT`. |
| AADSTS90072 | Your account cannot sign in to this organisation. | The external account does not exist in your tenant: invite it as a guest. |
| AADSTS53003 | Your organisation's access policy blocked this sign-in. | Conditional Access blocked the sign-in: the Entra sign-in log names the policy. |
| AADSTS7000222 | The service is temporarily unavailable. | The client secret has expired: create a new one (step 1.4) and restart the proxy. |

**"no access token for access_as_user"** or **"access token lacks scp access_as_user"** in the log,
or a token rejected as not v2: the app registration does not expose `access_as_user`, or
`api.requestedAccessTokenVersion` is not `2`. Repeat step 1.2 and check with:

```sh
az ad app show --id "$APP_ID" --query "{uris:identifierUris, version:api.requestedAccessTokenVersion, scopes:api.oauth2PermissionScopes[].value}"
```

**"redirect URI not registered: registered …, sent …"** on the proxy's error page: Claude Code sent
a redirect URI that is not in `clients.json` (static client only). Add the URI it sent (usually the
other loopback host name, see [the static client](#optional-claude-code-as-a-static-client)) and
restart the proxy.

### Errors on refresh and the proxy's credentials

| Code | Effect | Fix |
|---|---|---|
| AADSTS700082, 70043, 50076, 65001, or `invalid_grant` | The client is told to sign in again (`invalid_grant`). | Nothing: the refresh token expired from inactivity (700082) or by a sign-in frequency policy (70043), the user needs multifactor authentication (50076), or consent was removed (65001). |
| AADSTS7000215, 7000222, 700016, or `invalid_client` | `503` to the client, an operator alert in the log, and nobody is signed out. | The proxy's own credential is wrong (7000215: invalid secret), expired (7000222) or names no app (700016). Fix the secret file or client ID and restart. |
| Entra `5xx`, `429` or a timeout | `503` to the client. | Usually transient; check the Entra service health if it persists. |

AADSTS5002723 and AADSTS700027 are certificate-credential errors and do not occur with a client
secret; see the [certificate how-to](entra-certificate.md#troubleshooting).
