# Sign users in with Keycloak

Step by step: a Keycloak realm and client for byward, roles and groups for the
[access gate](access-gate.md), and the proxy settings. The general OIDC guide, with every setting, is
[oidc.md](oidc.md).
The data directory, the keys and starting the proxy are in [run byward](run-byward.md).

> Verified on 2026-11-13 with Keycloak 26.8.2 and the byward v0.2.0-rc.1 image, over https with a
> private CA and without `--dev`: sign-in, the role and group gates, refresh, revoke, and both a client
> secret and `private_key_jwt`. Use that image, `ghcr.io/byward-dev/byward:v0.2.0-rc.1`, or a later
> release: `latest` is still v0.1.1, which has no OIDC IdPs. The local trial below was run on
> 2026-11-14 with Keycloak 26.8.2 `start-dev` and the binary built from `main`.

## Try it on your machine

The whole path on one machine, over plain http on `localhost`: Keycloak in Docker, the MCP reference
server, the `byward` binary, and a short client. Production uses https throughout (sections 1–5).

**Why the binary, and why `--dev`.** byward refuses an http public URL and an http issuer, except on
a loopback host (`localhost`, `127.0.0.1`) with `--dev` ([what `--dev` relaxes](deploy.md#what---dev-relaxes)).
Inside a container, Keycloak is not on a loopback host, so the image refuses
`http://keycloak:8080/…` even with `--dev`. Your browser and byward must also see the same issuer
URL, which a Docker network name breaks. So run the `byward` binary on the host. To run the image
instead, give Keycloak https with a CA the container trusts ([trust a private CA](private-ca.md))
and a host name both your browser and the container resolve.

1. **Keycloak**, with a throwaway admin, on port 8180:

   ```sh
   docker run --rm -d --name byward-keycloak -p 127.0.0.1:8180:8080 \
     -e KC_BOOTSTRAP_ADMIN_USERNAME=admin -e KC_BOOTSTRAP_ADMIN_PASSWORD=admin \
     quay.io/keycloak/keycloak:26.8.2 start-dev
   ```

2. **The realm, client, mappers, role and two users** (sections 1 and 2 by hand, or this script with
   Keycloak's `kcadm.sh`). `alice` gets the role, `bob` does not:

   ```sh
   kc() { docker exec byward-keycloak /opt/keycloak/bin/kcadm.sh "$@"; }
   kc config credentials --server http://localhost:8080 --realm master --user admin --password admin
   kc create realms -s realm=byward -s enabled=true
   CID=$(kc create clients -r byward -i -s clientId=byward -s publicClient=false -s standardFlowEnabled=true \
     -s directAccessGrantsEnabled=false -s 'redirectUris=["http://localhost:8080/callback/keycloak"]')
   kc create clients/$CID/protocol-mappers/models -r byward -s name=roles -s protocol=openid-connect \
     -s protocolMapper=oidc-usermodel-realm-role-mapper \
     -s 'config={"claim.name":"roles","multivalued":"true","id.token.claim":"true","access.token.claim":"true","jsonType.label":"String"}'
   kc create clients/$CID/protocol-mappers/models -r byward -s name=groups -s protocol=openid-connect \
     -s protocolMapper=oidc-group-membership-mapper \
     -s 'config={"claim.name":"groups","full.path":"true","id.token.claim":"true","access.token.claim":"true"}'
   kc create roles -r byward -s name=byward.user
   for u in alice bob; do
     kc create users -r byward -s username=$u -s enabled=true -s email=$u@example.com -s emailVerified=true \
       -s firstName=$u -s lastName=Example
     kc set-password -r byward --username $u --new-password "change-me-$u"
   done
   kc add-roles -r byward --uusername alice --rolename byward.user
   (umask 077; kc get clients/$CID/client-secret -r byward --fields value --format csv --noquotes > keycloak-client-secret)
   ```

   `kcadm.sh` runs inside the container, so it reaches Keycloak at `http://localhost:8080`.

3. **The MCP reference server**, with the `docker run` under "You need" in [run byward](run-byward.md).
4. **The keys**: [create the keys](run-byward.md#2-create-the-keys) in `./byward-data`.
5. **byward**, the [binary](run-byward.md#4-start-the-proxy) on the host, with this `byward.env`:

   ```sh
   BYWARD_DEV=true
   BYWARD_PUBLIC_URL=http://localhost:8080/mcp
   BYWARD_UPSTREAM_URL=http://127.0.0.1:3001/mcp
   BYWARD_IDP=keycloak
   BYWARD_OIDC_ISSUER=http://localhost:8180/realms/byward
   BYWARD_OIDC_CLIENT_ID=byward
   BYWARD_GATE_ROLES=byward.user
   ```

   ```sh
   set -a; . ./byward.env; set +a
   export BYWARD_DATA_DIR="$PWD/byward-data" BYWARD_OIDC_CLIENT_SECRET_FILE="$PWD/keycloak-client-secret"
   ./byward check --offline && ./byward
   ```

   The startup log names each relaxation `--dev` applied. If port 9090 is taken, move the internal
   listener (`BYWARD_INTERNAL_LISTEN=127.0.0.1:9190`).
6. **Check it**: in another shell with the same settings, `./byward doctor`. Then sign in with
   [`mcp-check.py`](run-byward.md#without-an-ai-client): `uv run --script mcp-check.py
   http://localhost:8080/mcp`, open the URL it prints, allow on byward's consent page, and sign in as
   `alice`. It prints `echo: Echo: hello through byward`. Run it again as `bob`: byward shows "You
   don't have access to this server", and the audit log has `access_denied` with `reason` `role`.
7. **Clean up**: stop byward, then `docker rm -f byward-keycloak upstream && docker network rm byward`.

## 1. The realm and the client

In the Keycloak admin console (`/admin`), create the realm if your users are not in one yet:
**Manage realms › Create realm**, name `byward`. Then, in that realm:

1. **Clients › Create client**: type **OpenID Connect**, client ID `byward`.
2. **Capability config**: **Client authentication** on (byward is a confidential client; a public
   client is refused), **Standard flow** on, **Direct access grants** off.
3. **Login settings › Valid redirect URIs**: `https://<public host>/callback/keycloak`. byward logs the
   exact URI at startup ("register this redirect URI with the IdP app").
4. **Credentials** tab: keep **Client Id and Secret** and copy the secret into a file only the proxy's
   user can read, or use a key (section 4). `kcadm.sh` can write it for you, as in the local trial
   above (`kc get clients/<id>/client-secret`).

## 2. Roles and groups in the token

byward's gate reads the top-level `roles` and `groups` claims of the ID token. Keycloak puts realm roles
elsewhere by default, so add two mappers: **Clients › byward › Client scopes › byward-dedicated ›
Configure a new mapper**.

| Mapper type | Name | Token claim name | Settings |
|---|---|---|---|
| **User Realm Role** | realm roles | `roles` | Multivalued on, Add to ID token on |
| **Group Membership** | groups | `groups` | Add to ID token on; Full group path as you like (below) |

Then create the role and give it to your users:

1. **Realm roles › Create role**, for example `byward.user`.
2. For each user: **Users › Create new user** (or open an existing one); on its **Credentials** tab,
   fill in **Set password** (with **Temporary** off for a test user); on its **Role mappings** tab,
   **Assign role** and pick `byward.user`. Or put the users in a group (**Groups**, create one, then
   the user's **Groups** tab › **Join Group**) and gate on the group.

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
- Sign in from an MCP client, or with [`mcp-check.py`](run-byward.md#without-an-ai-client). A user
  without the role or group gets "You don't have access to this server." and the audit has
  `access_denied` with `reason` `role` or `group`. The client receives no error redirect; it waits
  until its own sign-in times out.
- Refresh: Keycloak returns an ID token on refresh, which byward needs to recheck the gate. A client gets
  a refresh token from byward only if it asks for `offline_access`.
