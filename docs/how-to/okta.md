# Sign users in with Okta

Step by step: an Okta app and authorization server for byward, groups for the
[access gate](access-gate.md), and the proxy settings. The general OIDC guide, with every setting, is
[oidc.md](oidc.md).

> Verified on 2026-11-13 with the byward v0.2.0-rc.1 code and an Okta Integrator Free Plan org: sign-in,
> the group gate (allowed and refused), refresh, revoke, a client secret, and `private_key_jwt` with an
> EC key. An RSA key does not work yet (section 5). Use the image
> `ghcr.io/byward-dev/byward:v0.2.0-rc.1` or a later release: `latest` is still v0.1.1, which has no
> OIDC IdPs.

## 1. The app

In the Okta admin console:

1. **Applications › Create App Integration**: **OIDC - OpenID Connect**, **Web Application**.
2. **Grant types**: Authorization Code and **Refresh Token**.
3. **Sign-in redirect URIs**: `https://<public host>/callback/okta`. byward logs the exact URI at
   startup.
4. **Client authentication**: **Client secret** (copy it into a file only the proxy's user can read),
   or **Public key / Private key** (section 5).
5. **Assignments**: the users or groups that may use it.

The app's authentication policy decides which factors users need; byward accepts whatever Okta
enforces.

## 2. The authorization server

byward needs a **custom authorization server**: the org authorization server (`https://<domain>`) is
refused. Every org has one called `default`; its issuer is `https://<domain>/oauth2/default`.

**Security › API › Authorization Servers › default**:

- **Access Policies**: a policy that includes the byward app, with a rule allowing the Authorization
  Code grant. Refresh tokens come from the `offline_access` scope that byward asks for.
- **Claims › Add Claim**, for the group gate: name `groups`, include in **ID Token**, value type
  **Groups**, a filter such as *Starts with* `byward-`, include in **any scope**.

## 3. Configure byward

```sh
BYWARD_IDP=okta
BYWARD_OIDC_ISSUER=https://<domain>/oauth2/default
BYWARD_OIDC_CLIENT_ID=<client id>
BYWARD_OIDC_CLIENT_SECRET_FILE=/run/secrets/okta-client-secret
BYWARD_GATE_GROUPS=byward-users
```

Use the org's own domain in the issuer (`https://<org>.okta.com/...`), not the admin console's
(`https://<org>-admin.okta.com`).

## 4. Who may sign in

- `BYWARD_GATE_GROUPS`: Okta group **names**, matched exactly against the `groups` claim. A user
  outside them gets "You don't have access to this server." and the audit records `access_denied`
  with `reason` `group`.
- `BYWARD_GATE_EMAIL_DOMAINS`: verified email domains. Okta reports a user's email as unverified until
  the user has confirmed it, so users created by an admin or the API may not pass this gate, and their
  email is left out of the identity assertion.

## 5. A key instead of the secret (`private_key_jwt`)

**Use an EC P-256 key with Okta.** byward signs EC keys with ES256, which Okta accepts. It signs RSA
keys with PS256, which Okta refuses ("The client_assertion JWT signature algorithm is invalid."); an
option to sign with RS256 is tracked in [#306](https://github.com/byward-dev/byward/issues/306).

1. `openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out okta-client.pem`, readable only
   by the proxy's user.
2. On the app, **Client authentication › Public key / Private key**: add the public key (as a JWK)
   with a key ID.
3. Settings: replace the secret with

   ```sh
   BYWARD_OIDC_CLIENT_KEY_FILE=/run/secrets/okta-client.pem
   BYWARD_OIDC_CLIENT_KEY_ID=<the key ID>
   ```

A refused key shows up at the first sign-in as an IdP alert, `credential_rejected`.

## 6. Check it

`byward check --offline`, then `byward doctor`: "discovery … matches the configured issuer", and
"client credential": Okta accepted the client ID and the secret or key. A wrong one fails, with the
setting to fix. (The client credential check is on `main`; the doctor in v0.2.0-rc.1 does not have
it, and a wrong secret or key shows at the first sign-in as an IdP alert.) Then sign in from an MCP
client ([oidc.md](oidc.md#5-check-it)).
