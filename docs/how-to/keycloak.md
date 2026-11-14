# Sign users in with Keycloak

Step by step: a Keycloak realm and client for byward, roles and groups for the
[access gate](access-gate.md), and the proxy settings. The general OIDC guide, with every setting, is
[oidc.md](oidc.md).
The data directory, the keys and starting the proxy are in [run byward](run-byward.md).

> Verified on 2026-11-13 with Keycloak 26.8.2 and the byward v0.2.0-rc.1 image, over https with a
> private CA and without `--dev`: sign-in, the role and group gates, refresh, revoke, and both a client
> secret and `private_key_jwt`. Use that image, `ghcr.io/byward-dev/byward:v0.2.0-rc.1`, or a later
> release: `latest` is still v0.1.1, which has no OIDC IdPs.

## 1. The realm and the client

In the Keycloak admin console, in the realm your users are in (below: `byward`):

1. **Clients › Create client**: type **OpenID Connect**, client ID `byward`.
2. **Capability config**: **Client authentication** on (byward is a confidential client; a public
   client is refused), **Standard flow** on, **Direct access grants** off.
3. **Login settings › Valid redirect URIs**: `https://<public host>/callback/keycloak`. byward logs the
   exact URI at startup ("register this redirect URI with the IdP app").
4. **Credentials** tab: keep **Client Id and Secret** and copy the secret into a file only the proxy's
   user can read, or use a key (section 4).

## 2. Roles and groups in the token

byward's gate reads the top-level `roles` and `groups` claims of the ID token. Keycloak puts realm roles
elsewhere by default, so add two mappers: **Clients › byward › Client scopes › byward-dedicated ›
Configure a new mapper**.

| Mapper type | Name | Token claim name | Settings |
|---|---|---|---|
| **User Realm Role** | realm roles | `roles` | Multivalued on, Add to ID token on |
| **Group Membership** | groups | `groups` | Add to ID token on; Full group path as you like (below) |

Then create the role (**Realm roles › Create role**, for example `byward.user`) and assign it, or put
the users in a group.

- **Group values must match the claim exactly.** With **Full group path** on (the default), the claim
  holds paths such as `/byward-users`, so set `BYWARD_GATE_GROUPS=/byward-users`; `byward-users` alone
  matches nobody. Turn Full group path off to use bare names.
- The realm-role mapper also sends Keycloak's default roles (`default-roles-<realm>`, `offline_access`,
  `uma_authorization`). They reach the upstream in the identity assertion and `X-Byward-Roles` if you
  assert roles; gate on your own role, never on those.

## 3. Configure byward

```sh
BYWARD_IDP=keycloak
BYWARD_OIDC_ISSUER=https://keycloak.example.com/realms/byward
BYWARD_OIDC_CLIENT_ID=byward
BYWARD_OIDC_CLIENT_SECRET_FILE=/run/secrets/keycloak-client-secret
BYWARD_GATE_ROLES=byward.user          # or BYWARD_GATE_GROUPS=/byward-users
```

The issuer is the realm URL exactly as Keycloak's discovery document states it
(`https://<host>/realms/<realm>/.well-known/openid-configuration`), and must use https.

**A Keycloak behind a private CA:** the image trusts the CAs Go finds. Mount your CA file and point
`SSL_CERT_FILE` at it:

```sh
docker run … -v /etc/pki/my-ca.pem:/etc/byward/ca.pem:ro -e SSL_CERT_FILE=/etc/byward/ca.pem …
```

The file needs only your CA. Go still reads the image's public bundle in `/etc/ssl/certs`, so
public IdPs and upstreams keep working. Details, Kubernetes and the pitfalls are in
[trust a private CA](private-ca.md).

## 4. A key instead of the secret (`private_key_jwt`)

1. Make an RSA (2048 bits or more) or EC P-256 key: `openssl genpkey -algorithm RSA -pkeyopt
   rsa_keygen_bits:2048 -out keycloak-client.pem`, readable only by the proxy's user.
2. **Credentials** tab: **Client Authenticator** = **Signed Jwt**, **Signature algorithm** = the
   algorithm byward signs with: **PS256** for an RSA key by default, **RS256** if you set
   `BYWARD_OIDC_CLIENT_KEY_ALG=RS256` (on `main`, not in v0.2.0-rc.1), **ES256** for an EC key. If they differ, Keycloak refuses the
   sign-in and byward logs an IdP alert, `credential_rejected`. When Keycloak answers with the OAuth
   error `invalid_client`, the alert's fix names the algorithm byward signed with.
3. **Keys** tab: give Keycloak the public key, as a JWKS URL or by importing it, with a key ID.
4. Settings: replace the secret with

   ```sh
   BYWARD_OIDC_CLIENT_KEY_FILE=/run/secrets/keycloak-client.pem
   BYWARD_OIDC_CLIENT_KEY_ID=<the key ID Keycloak has for it>
   ```

## 5. Check it

- `byward check --offline`, then `byward doctor`: "discovery … matches the configured issuer", and
  "client credential": Keycloak accepted the client ID and the secret or key. A wrong secret fails
  with `unauthorized_client`, a wrong key with `invalid_client`, each with the setting to fix. (The
  client credential check is on `main`, not in v0.2.0-rc.1.)
- Sign in from an MCP client. A user without the role or group gets "You don't have access to this
  server." and the audit has `access_denied` with `reason` `role` or `group`.
- Refresh: Keycloak returns an ID token on refresh, which byward needs to recheck the gate. A client gets
  a refresh token from byward only if it asks for `offline_access`.
