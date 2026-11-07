# Tell the upstream who the user is: the identity assertion

The upstream never sees the MCP client's token (the MCP spec forbids passing it through). Instead,
byward sends every request to an HTTP upstream with an **identity assertion**: a short-lived JWT,
signed by byward, that says who the user is and which MCP client they use. The upstream verifies it
with byward's public keys. Decisions: [ADR-0016](../adr/0016-identity-propagation.md). The claims
and verification examples for go-sdk, the TypeScript SDK and FastMCP are in the
[identity assertion reference](../reference/identity-assertion.md).

Every assertion says what kind of principal it is for: `principal_type` is `user`, or `client` for
a headless caller with an [app-only token](app-tokens.md). Check it before treating `sub` as a
person.

A stdio upstream gets no assertion. Each user has their own process, started with
`BYWARD_SUBJECT`, `BYWARD_ISSUER` and `BYWARD_PRINCIPAL_TYPE` in its environment
([stdio upstream](stdio-upstream.md)).

## 1. Create a signing key

byward signs with a key you provide, kept apart from the sealing keys (ADR-0006 §8). Each file in
`BYWARD_ASSERTION_KEYS_DIR` (default `assertion-keys` in the data directory) is one PEM ECDSA P-256
private key, and the file name is its key ID (`kid`). Create the first one:

```sh
install -d -m 0700 byward-data/assertion-keys
(umask 077; openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 \
  -out "byward-data/assertion-keys/$(date -u +%Y-%m-%d)")
```

`openssl ecparam -name prime256v1 -genkey -noout` output works too.

- With authentication on and an HTTP upstream, byward refuses to start without a key, naming
  `BYWARD_ASSERTION_KEYS_DIR`. `byward check --offline` reports the same.
- A key file that other users can read is refused, like the client secret file. Make it `0600`
  and owned by the proxy's user, or mount it read-only, as Kubernetes secret volumes are; `--dev`
  relaxes the check.
- The startup log names the key IDs, never key material.

## 2. Point the upstream at the public keys

The upstream verifies assertions with byward's JWKS:

- `https://<public host>/.well-known/jwks.json` on the public listener, and
- `http://<internal listener>/.well-known/jwks.json` (`BYWARD_INTERNAL_LISTEN`), for an upstream that
  reaches only the internal network.

Both are served with `Cache-Control: public, max-age=300`. An upstream that loads keys from a file
instead gets them with `byward jwks > jwks.json`. Run it again after every rotation.

Configure the verifier's audience as **`BYWARD_UPSTREAM_URL` exactly as you set it**, for example
`http://mcp-upstream.internal:3001/mcp`. That is often an internal name, not the public URL, and a
verifier that expects anything else refuses every request. The issuer is byward's public origin
(`https://<public host>`).

## 3. Choose the header and the claims

| Setting | Default | What it does |
|---|---|---|
| `BYWARD_ASSERTION_HEADER` | `Authorization` | the header that carries `Bearer <assertion>` |
| `BYWARD_ASSERTION_CLAIMS` | `roles` | optional claims to add: `roles`, `groups`, `email`, `name`, or `none` |
| `BYWARD_ASSERTION_UNVERIFIED_EMAIL` | `false` | with `email`: also assert an email the IdP has not verified, marked `email_verified: false` |

- byward removes every copy of the assertion header a client sends, in any spelling (`_` for `-`
  included), before setting its own. A client can never supply the assertion.
- The client's own token is never forwarded, whichever header you choose.
- An upstream that cannot verify a JWT can read the same values from plain `X-Byward-*` headers, but
  only behind a network boundary ([plain identity headers](plain-identity-headers.md)).
- If the upstream also needs the proxy's own credential in `Authorization`, move the assertion to
  another header ([upstream credential](upstream-credential.md)).
- `email` and `name` are personal data (ADR-0021 §4): add them only when the upstream needs them.
- `email` is asserted only when the IdP vouched for it: an [OIDC IdP](oidc.md)'s ID token said
  `email_verified: true`. Otherwise it is left out, and every start logs that it is. `email_verified`
  comes with every asserted `email` (ADR-0016, 2026-11-07 amendment).
- Entra never verifies an email (ADR-0012 §3), so with Entra `email` asserts nothing unless you also
  set `BYWARD_ASSERTION_UNVERIFIED_EMAIL=true`. That asserts any IdP's unverified email, marked
  `email_verified: false`.
- Even a verified email is a display value: it can change, and it is not a unique identifier (OIDC
  Core §5.7; Microsoft: "Never use it for authorization"). Never authorize on it; use `sub`.
- `sub` is the user key: `tid:oid` with Entra, the IdP's subject claim (`BYWARD_OIDC_SUBJECT_CLAIM`)
  with an OIDC IdP. The issuer is always byward's, whichever IdP signed the user in.
- `groups` can be large. With 200 groups, Entra's limit, a client's proxy token is about 11 KB;
  with roles only it stays under 1 KB. Groups that do not fit a token at all are left out with a
  warning in the log, and an Entra user over 200 groups has none asserted (groups overage).

## 4. How fresh the claims are

The claims come from the user's proxy token, which byward seals at sign-in and at every refresh,
so a request needs no database lookup. Roles and groups in an assertion can therefore be up to
**one access-token lifetime (1 hour) old**, the same as the [access gate](access-gate.md). A removed
role stops being asserted at the client's next refresh. To end a user's access at once, use
`byward revoke-user` ([hardening](harden-a-deployment.md)).

After upgrading to a version with the identity assertion, existing proxy tokens are refused once
with `401 invalid_token`. Clients refresh, and the new tokens carry the claims. Users do not sign in
again.

## 5. Rotate the signing key

1. Add a new key file whose name sorts after the current one (the dated names above do), then restart.
   The new key signs; the old one stays in the JWKS.
2. Wait at least 6 minutes: an assertion lives 60 seconds, and verifiers cache the JWKS for 5 minutes.
3. Remove the old file and restart. An upstream that loads a static JWKS needs `byward jwks` again
   at step 1 and at step 3.

With several replicas, give them the same key files and restart them all at step 1 before step 3.
