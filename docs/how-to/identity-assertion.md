# Tell the upstream who the user is: the identity assertion

The upstream never sees the MCP client's token (the MCP spec forbids passing it through). Instead,
byward sends every request to an HTTP upstream with an **identity assertion**: a short-lived JWT,
signed by byward, that says who the user is and which MCP client they use. The upstream verifies it
with byward's public keys. Decisions: [ADR-0016](../adr/0016-identity-propagation.md). The claims,
the rules a verifier applies, and verification examples for go-sdk, the TypeScript SDK and FastMCP
are in the [identity assertion reference](../reference/identity-assertion.md).

A stdio upstream gets no assertion; it learns the user from its environment
([reference](../reference/identity-assertion.md#stdio-upstream)).

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

The upstream verifies assertions with byward's JWKS. Whoever can change the keys the upstream
fetches can forge any assertion, so the way the keys travel matters as much as the keys. In order
of preference:

1. **The public JWKS over https:** `https://<public host>/.well-known/jwks.json`. TLS protects it
   end to end. Use it whenever the upstream can reach the public URL.
2. **A pinned file:** `byward jwks > jwks.json`, copied to the upstream with your deployment (a
   secret, a ConfigMap, the image) and loaded from disk. Nothing travels at request time. Export
   and ship it again when you rotate: after adding the new key file and before the restart that
   makes it sign, then after removing the old one ([section 5](#5-rotate-the-signing-key)).
3. **The internal listener's JWKS**, `http://<internal listener>/.well-known/jwks.json`
   (`BYWARD_INTERNAL_LISTEN`). It is **plain http**: anyone on the path between byward and the
   upstream can substitute keys and forge assertions. Use it only when that path cannot be
   tampered with:
   - **the same host**, over loopback (the default `127.0.0.1:9090`), or the same pod;
   - or a network you control end to end: in Kubernetes, a NetworkPolicy that lets only the
     upstream reach byward's internal port, **and** a service mesh with mutual TLS between them.
     A NetworkPolicy alone does not stop an on-path attacker; mTLS alone does not stop other
     workloads from reaching the port.

   Anything else, such as a different host over a shared network or a VPC without mTLS, uses option
   1 or 2.

Then set the verifier's audience and issuer as [Verifying](../reference/identity-assertion.md#verifying)
says; a wrong audience is the usual reason an upstream refuses every request. How long a verifier
may cache the JWKS is in [Keys](../reference/identity-assertion.md#keys).

## 3. Choose the header and the claims

| Setting | Default | What it does |
|---|---|---|
| `BYWARD_ASSERTION_HEADER` | `Authorization` | the header that carries `Bearer <assertion>` |
| `BYWARD_ASSERTION_CLAIMS` | `roles` | optional claims to add: `roles`, `groups`, `email`, `name`, or `none` |
| `BYWARD_ASSERTION_UNVERIFIED_EMAIL` | `false` | with `email`: also assert an email the IdP has not verified, marked `email_verified: false` |

- An upstream that cannot verify a JWT can read the same values from plain `X-Byward-*` headers, but
  only behind a network boundary ([plain identity headers](plain-identity-headers.md)).
- If the upstream also needs the proxy's own credential in `Authorization`, move the assertion to
  another header ([upstream credential](upstream-credential.md)).
- Before adding `email` or `name`, read [Email](../reference/identity-assertion.md#email); before
  adding `groups`, read [Groups](../reference/identity-assertion.md#groups).
- Build the upstream's authorization on [the user key](../reference/identity-assertion.md#the-user-key-sub).

## 4. How fresh the claims are

How old an asserted role can be, and how to end a user's access at once, is in
[How fresh the claims are](../reference/identity-assertion.md#how-fresh-the-claims-are).

After upgrading to a version with the identity assertion, existing proxy tokens are refused once
with `401 invalid_token`. Clients refresh, and the new tokens carry the claims. Users do not sign in
again.

## 5. Rotate the signing key

1. Add a new key file whose name sorts after the current one (the dated names above do), then restart.
   The new key signs; the old one stays in the JWKS.
2. Wait at least 6 minutes: an assertion lives 60 seconds, and verifiers cache the JWKS for 5 minutes.
3. Remove the old file and restart. An upstream that loads a static JWKS needs `byward jwks` again
   at step 1, after adding the file and before restarting, and at step 3.

With several replicas, give them the same key files and restart them all at step 1 before step 3.
