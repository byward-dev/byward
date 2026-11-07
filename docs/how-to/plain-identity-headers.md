# Plain identity headers for an upstream that cannot verify a JWT

> **Safe only when the upstream is reachable through this proxy alone.** A plain header proves
> nothing by itself: anyone who can send the upstream a request directly can write
> `X-Byward-Subject: <anyone>`. Use these headers only behind a network boundary, such as a
> private network, a Kubernetes NetworkPolicy, or the upstream listening on loopback next to the
> proxy. Wherever the upstream can verify a JWT, verify the
> [identity assertion](identity-assertion.md) instead.

With `BYWARD_IDENTITY_HEADERS=true`, byward sends the user in plain headers as well as the identity
assertion ([ADR-0016](../adr/0016-identity-propagation.md) §5). Both carry the same values. The
setting is off by default and needs authentication. A stdio upstream gets the user in its
environment instead ([stdio upstream](stdio-upstream.md)).

## The headers

| Header | Value | Sent |
|---|---|---|
| `X-Byward-Subject` | the user key, `tid:oid` for Entra (the assertion's `sub`) | always |
| `X-Byward-Client-Id` | the MCP client (`client_id`) | always |
| `X-Byward-Roles` | the user's app roles | with `roles` in `BYWARD_ASSERTION_CLAIMS` (the default) |
| `X-Byward-Groups` | the user's group IDs | with `groups` |
| `X-Byward-Email` | the user's email | with `email` |
| `X-Byward-Name` | the user's display name | with `name` |

- A claim the user does not have sends no header, never an empty one. With Entra's groups overage
  there is no `X-Byward-Groups`; byward never sends an incomplete list.
- `X-Byward-Email` is the same value as the assertion's `email`. Don't authorize on it: Entra does
  not verify it. Use `X-Byward-Subject`.
- The values are as fresh as the assertion's: up to one hour old
  ([identity assertion](identity-assertion.md)).

## Reading them

Every value is percent-encoded as UTF-8. Every byte other than `A–Z a–z 0–9 - . _ ~` is written as
`%XX`, so no value can contain a comma, a line break or a space. A list is its encoded items joined
by commas. Read a header by splitting on `,`, then decoding each item:

```text
X-Byward-Subject: 00000000-0000-0000-0000-000000000001%3A00000000-0000-0000-0000-000000000002
X-Byward-Roles: byward.user,Data.Read
X-Byward-Name: Ren%C3%A9e%20Martin
```

```python
from urllib.parse import unquote
roles = [unquote(r) for r in request.headers.get("X-Byward-Roles", "").split(",") if r]
```

```js
const roles = (req.headers['x-byward-roles'] ?? '').split(',').filter(Boolean).map(decodeURIComponent);
```

## What byward guarantees

- Every copy of these six headers a client sends is removed first, in any case and with `_` for `-`
  (`X_Byward_Roles` included). This happens even while the setting is off and without
  authentication, so turning the headers on or off never lets a forged one through.
- No other setting can use these names: `BYWARD_ASSERTION_HEADER` and
  `BYWARD_UPSTREAM_CREDENTIAL_HEADER` refuse them.
- While the setting is on, the proxy logs a warning at startup.
- `byward doctor` looks up the upstream's host. If any of its addresses is public, or the host does
  not resolve, doctor warns. Loopback, private, link-local and shared (CGNAT, `100.64.0.0/10`)
  addresses pass. This is a hint, not a guarantee: doctor sees addresses, not who can reach them.
