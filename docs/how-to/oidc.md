# Sign users in with an OpenID Connect IdP (Google, Okta, Auth0, Keycloak)

Instead of Microsoft Entra, the proxy can sign users in with any OpenID Connect IdP. It uses the
authorization code flow with PKCE and validates the ID token per OIDC Core §3.1.3.7. Presets carry the
quirks of Google, Okta, Auth0 and Keycloak. Background: [ADR-0011](../adr/0011-idp-adapters.md). One
IdP per proxy.

## 1. Register the proxy at the IdP

Create a **confidential** web application (the proxy holds a secret or a key; a public client is
refused) with:

- **Redirect URI:** `https://<public host>/callback/<idp>`, where `<idp>` is the `BYWARD_IDP` value
  below, for example `https://mcp.example.com/callback/keycloak`. The proxy logs the exact URI at
  startup.
- **Grant types:** authorization code and refresh token. The IdP must return an ID token when the
  proxy refreshes (OIDC Core §12.2 makes it optional): the [access gate](access-gate.md) is checked
  on fresh claims at every refresh, so a refresh without one ends the grant, and the log says "the IdP
  returned no ID token on refresh". Entra and Keycloak return one (Keycloak is checked by the
  integration test); for other IdPs check that the refresh response carries `id_token`.
- **Scopes:** `openid`, plus what the preset asks for (below).

## 2. Configure the proxy

| Setting | Default | Meaning |
|---|---|---|
| `BYWARD_IDP` | `entra` | `oidc` for any OIDC IdP, or a preset: `google`, `okta`, `auth0`, `keycloak`. Also names the callback path, the `idp` field of audit records and the `idp` metric label. |
| `BYWARD_OIDC_ISSUER` | — (`google`: `https://accounts.google.com`) | The issuer, exactly as the IdP's discovery document (`/.well-known/openid-configuration`) states it. `https` only. |
| `BYWARD_OIDC_CLIENT_ID` | — | The application's client ID. |
| `BYWARD_OIDC_CLIENT_SECRET_FILE` | — | A file holding the client secret. |
| `BYWARD_OIDC_CLIENT_KEY_FILE` | — | Instead of a secret: a PEM private key (RSA or EC P-256) for `private_key_jwt`. byward signs with PS256 for an RSA key and ES256 for an EC key, so the IdP's client must accept that algorithm (not RS256). |
| `BYWARD_OIDC_CLIENT_KEY_ID` | — | The key ID (`kid`) the IdP registered for that key. |
| `BYWARD_OIDC_SCOPES` | — | Extra scopes, comma-separated, besides `openid` and the preset's. |
| `BYWARD_OIDC_SUBJECT_CLAIM` | `sub` | The claim that identifies a user. A claim users can change (`email`, `preferred_username`, `upn`, `name`) logs a warning at every start: someone could take over another user's grants by changing it. |
| `BYWARD_OIDC_NAME` | the preset's name, or the issuer's host | The IdP's name on the consent page ("You'll sign in with … next"), up to 80 characters. |

Give exactly one of the secret and the key. `BYWARD_ENTRA_*` settings with an OIDC IdP, or
`BYWARD_OIDC_*` settings with Entra, refuse to start and name both sides.

**Network:** the IdP is yours, so the proxy reaches it directly, not through the SSRF guard that
client-supplied URLs go through. A self-hosted Keycloak or Okta on a private address works. The
issuer and every endpoint in its discovery document must use `https`; only `--dev` accepts `http` on
a loopback host. The proxy checks the issuer at the first sign-in and `byward doctor` checks it on
demand.

## 3. Presets

| `BYWARD_IDP` | Issuer | Scopes asked | Notes |
|---|---|---|---|
| `google` | `https://accounts.google.com` | `profile email` | Refresh tokens come from `access_type=offline` with `prompt=consent` (see below). `email_verified` may be a string. |
| `okta` | `https://<domain>/oauth2/<server>` | `profile email offline_access` | Only a custom authorization server issues tokens for the proxy; the org server (`https://<domain>`) is refused. Not yet verified against a real Okta org (#281). |
| `auth0` | `https://<tenant>.auth0.com/` | `profile email offline_access` | The issuer ends with a slash. Auth0 drops `roles` and `groups` claims, so gate by email domain (below). |
| `keycloak` | `https://<host>/realms/<realm>` | `profile email` | Enable "Client authentication" on the client. Step by step: [keycloak.md](keycloak.md). |
| `oidc` | any | `profile email offline_access` | No quirks. |

**Google shows its consent screen at every sign-in.** Google returns a refresh token only on the
first code exchange for a user and the proxy's app; without one, a grant cannot refresh, and the user
would sign in again every hour. So the `google` preset sends `prompt=consent`, which makes Google
issue a new refresh token each time. Remembered consent ([ADR-0010](../adr/0010-consent-screen.md))
skips only the proxy's own consent page, never Google's. If an IdP still returns no refresh token for
a client that asked for `offline_access`, the proxy issues no refresh token of its own either (it
could not refresh), and logs a warning, "the IdP returned no refresh token, so this grant cannot
refresh", naming the IdP.

A silent sign-in (the client sent `prompt=none`) is the exception. `none` may not be combined with
other values (OIDC Core §3.1.2.1), so Google gets `prompt=none` alone. Google may then return no new
refresh token, and that grant cannot refresh: the client signs in again when its access token
expires.

## 4. Who may sign in

An OIDC IdP usually lets anyone with an account sign in, so an empty
[access gate](access-gate.md) refuses to start unless `BYWARD_GATE_ALLOW_EMPTY=true`. Useful lists:

- `BYWARD_GATE_EMAIL_DOMAINS`: verified email domains.
- `BYWARD_GATE_HOSTED_DOMAINS` (`google` only): Google Workspace domains (`hd`). With exactly one
  domain the proxy also asks Google to show only that Workspace's accounts.
- `BYWARD_GATE_ROLES` and `BYWARD_GATE_GROUPS`: they read the top-level `roles` and `groups` claims,
  and each value must match a claim value exactly. Keycloak's Group Membership mapper sends full paths
  (`/byward-users`) unless "Full group path" is off.
  Keycloak puts realm roles under `realm_access.roles` by default; add a "User Realm Role" mapper
  with the token claim name `roles` (and a "Group Membership" mapper for `groups`) so the gate sees
  them. The integration test checks this against Keycloak 26.8.0
  (`TestIntegrationKeycloakSignsAUserInAndRefreshes`).
- **Auth0: no role or group gate yet.** Auth0 reserves the `roles` and `groups` claim names and silently
  drops custom claims that use them; roles can only arrive under a namespaced claim such as
  `https://example.com/roles`, which the gate does not read yet (#286). With `BYWARD_IDP=auth0`, a role or
  group gate refuses everyone, so gate on `BYWARD_GATE_EMAIL_DOMAINS` instead. Found in a real-tenant test
  on 2026-11-13.

## 5. Check it

`byward check --offline` validates the settings; `byward doctor` fetches discovery and checks that
its issuer matches. The consent page says "You'll sign in with `<name>` next".
