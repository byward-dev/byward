# Give the upstream the proxy's own credential

Some HTTP upstreams want a credential of their own on every request, such as an API key, to know
the caller is your proxy. byward can send one. It is the **operator's** credential: never the
user's token and never the client's ([ADR-0016](../adr/0016-identity-propagation.md) §7).

It does not replace the [identity assertion](identity-assertion.md), which still says who the user
is. The two always travel in separate headers.

This is not for an upstream that has its own authorization server and expects a token issued to the
user. A stdio upstream gets its credentials from its environment instead: put them in
`BYWARD_UPSTREAM_ENV_FILE` ([stdio upstream](stdio-upstream.md)).

## 1. Put the credential in a file

The file holds the exact header value, on one line. A trailing newline is ignored.

```sh
(umask 077; printf '%s\n' 'Bearer <the API key>' > byward-data/upstream-credential)
```

- Like every secret file, it must not be readable by other users (`0600` or `0400`, owned by the
  proxy's user), unless it is on a read-only mount such as a Kubernetes secret volume.
- The value must have no control characters and no leading or trailing spaces, and be at most
  4096 bytes.
- byward reads it at start. To rotate, replace the file and restart.

## 2. Choose the header

| Setting | Default | What it does |
|---|---|---|
| `BYWARD_UPSTREAM_CREDENTIAL_FILE` | none | the file from step 1 |
| `BYWARD_UPSTREAM_CREDENTIAL_HEADER` | `Authorization` | the header it is sent in |

The credential and the identity assertion never share a header. Both default to `Authorization`,
so set one of them:

- **The upstream expects the credential in `Authorization`:** move the assertion, e.g.
  `BYWARD_ASSERTION_HEADER=X-Byward-Identity`, and verify it there.
- **The upstream reads the credential from a header of its own:** set that, e.g.
  `BYWARD_UPSTREAM_CREDENTIAL_HEADER=X-Api-Key`, and the assertion stays in `Authorization`.

If both name the same header, in any spelling (`X_Api_Key` and `X-Api-Key` are one header to
byward), the proxy refuses to start and says which to change.

## What byward guarantees

- Every copy of the credential's header a client sends is removed before byward sets its own, in
  any case and with `_` for `-`. A client can never supply the credential, and byward never sends
  it to a client.
- The value is never logged and never in an error: the startup log and `byward --print-config`
  show `<redacted>`, and `byward doctor` reports only that a credential is set and its header.
- It is sent to the HTTP upstream only, on every request, also with `--insecure-no-auth`.
