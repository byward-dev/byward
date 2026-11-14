# Sign users in with Auth0

Step by step: an Auth0 application for byward, roles in the ID token for the
[access gate](access-gate.md), and the proxy settings. The general OIDC guide is [oidc.md](oidc.md);
every setting is in the [settings reference](../reference/settings.md). The steps to run the proxy
itself are in [run byward](run-byward.md).

> Verified on 2026-11-13 with byward v0.2.0-rc.1 and an Auth0 Free plan tenant: sign-in, the email
> domain gate (allowed and refused), refresh, revoke, and a client secret. The role gate through
> `BYWARD_OIDC_ROLES_CLAIM` was verified on 2026-11-14 with the code on `main`: a user with the role
> admitted, one without refused, and the role still there after a refresh. `private_key_jwt` was not
> tested. Use the image `ghcr.io/byward-dev/byward:v0.2.0-rc.1` or a later release.

## 1. The application

In the Auth0 Dashboard, **Applications › Applications**:

1. Create an application of type **Regular Web App**. byward is a confidential client: it holds a
   secret or a key, and a public client is refused.
2. **Allowed Callback URLs**: `https://<public host>/callback/auth0`. byward logs the exact URI at
   startup.
3. **Advanced Settings › Grant Types**: the authorization code and refresh token grants.
4. Authentication method: **Client Secret**, Auth0's default. byward sends the secret in the request
   body (`client_secret_post`). Copy the secret into a file only the proxy's user can read.
5. Enable a connection for the application (for example the Username-Password database) so your
   users can sign in.

byward asks for `offline_access`, so Auth0 returns a refresh token with the ID token. On a refresh,
Auth0 returns a new ID token, which byward needs to recheck the access gate.

## 2. Roles in the ID token

byward reads the ID token, not an access token for an API, so no Auth0 API or audience is needed.

Auth0 reserves the claim names `roles` and `groups` and does not add a custom claim with either
name ([Create Custom Claims](https://auth0.com/docs/secure/tokens/json-web-tokens/create-custom-claims)).
A role gate on the default `roles` claim therefore admits nobody. Send the roles under a namespaced
claim instead:

1. **User Management › Roles › Create Role**, for example `byward.user`, and assign it to the users
   (**User Management › Users**, **Assign Roles**).
2. **Actions › Library › Create Action › Build from scratch**, trigger **Login / Post Login**, with the
   code below (Auth0's sample "Add user roles to tokens",
   [Actions with authorization](https://auth0.com/docs/manage-users/access-control/sample-use-cases-actions-with-authorization)).
   The namespace is any `http` or `https` URL that is not an Auth0 domain; it need not resolve.

   ```js
   exports.onExecutePostLogin = async (event, api) => {
     const namespace = 'https://byward.example.com';
     if (event.authorization) {
       api.idToken.setCustomClaim(`${namespace}/roles`, event.authorization.roles);
     }
   };
   ```

3. **Deploy** the Action, then add it to the login flow: **Actions › Flows › Login**, drag it into
   the flow, **Apply**.

A deployed Action can take a few seconds to reach new tokens: a sign-in right after the deploy may
not carry the claim yet.

## 3. Configure byward

```sh
BYWARD_IDP=auth0
BYWARD_OIDC_ISSUER=https://<tenant>.auth0.com/
BYWARD_OIDC_CLIENT_ID=<client id>
BYWARD_OIDC_CLIENT_SECRET_FILE=/run/secrets/auth0-client-secret
# on `main`, not in v0.2.0-rc.1:
BYWARD_OIDC_ROLES_CLAIM=https://byward.example.com/roles
BYWARD_GATE_ROLES=byward.user
```

- **The issuer ends with a slash**, exactly as the tenant's discovery document
  (`https://<tenant>.auth0.com/.well-known/openid-configuration`) states it; without the slash byward
  refuses to start. A tenant in a region has the region in its domain
  (`https://<tenant>.<region>.auth0.com/`).
- The `auth0` preset asks for `openid profile email offline_access`; add others with
  `BYWARD_OIDC_SCOPES`.
- `BYWARD_OIDC_ROLES_CLAIM` is on `main`, not in v0.2.0-rc.1. With v0.2.0-rc.1, gate by email domain
  (section 4).

## 4. Who may sign in

An empty access gate refuses to start with an OIDC IdP, so set at least one of:

- `BYWARD_GATE_ROLES` (on `main`, with `BYWARD_OIDC_ROLES_CLAIM` set as above): Auth0 role names,
  matched exactly against the namespaced claim. A user without one of them gets "You don't have access
  to this server." and the audit records `access_denied` with `reason` `role`. The identity assertion
  and `X-Byward-Roles` carry the same roles. Without `BYWARD_OIDC_ROLES_CLAIM`, byward reads the
  top-level `roles` claim, which Auth0 never sends, so every sign-in and every refresh is refused.
- `BYWARD_GATE_EMAIL_DOMAINS`: verified email domains. A user whose email Auth0 has not verified is
  refused with `reason` `email_domain`.

`BYWARD_OIDC_GROUPS_CLAIM` does the same for a groups claim an Action sets; that was not tested with
Auth0. The gate lists are explained in [the access gate](access-gate.md).

## 5. A key instead of the secret (`private_key_jwt`)

Not tested with Auth0. Auth0 offers Private Key JWT on its Enterprise plan only, and accepts RS256,
RS384 and PS256 assertions ([Configure Private Key JWT Authentication](https://auth0.com/docs/get-started/applications/configure-private-key-jwt)).
byward signs an RSA key with PS256 by default and an EC key with ES256, so:

- Use an RSA key of 2048 to 4096 bits, not an EC key.
- Register its public key (PEM) on the application with the algorithm byward signs with: **PS256**,
  or Auth0's default **RS256** if you set `BYWARD_OIDC_CLIENT_KEY_ALG=RS256` (on `main`, not in
  v0.2.0-rc.1).
- Replace the secret with `BYWARD_OIDC_CLIENT_KEY_FILE` and `BYWARD_OIDC_CLIENT_KEY_ID` (the `kid`
  Auth0 generates for the credential).

## 6. Check it

- `byward check --offline`, then `byward doctor`: "discovery … matches the configured issuer". On
  `main`, doctor also checks that Auth0 accepts the client ID and the secret; the doctor in
  v0.2.0-rc.1 does not, and a wrong secret shows only at the first sign-in.
- Sign in from an MCP client ([run byward](run-byward.md#6-connect-a-client)): byward's consent page,
  then Auth0's login page. The user's `sub` looks like `auth0|…`.
- Refresh: byward gives a refresh token to every client that registered the `refresh_token` grant, whether or not it asks for `offline_access` ([ADR-0006](../adr/0006-token-model.md), amended for #287).
