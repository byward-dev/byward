# Let apps register themselves (DCR)

Cursor, Gemini CLI and MCP Inspector register with **Dynamic Client Registration** (RFC 7591):
they send their name and redirect URIs to `/register` and get a client ID back. This is on by
default, and the proxy advertises the endpoint in its metadata (`registration_endpoint`). The MCP
specification (2026-07-28) keeps DCR for compatibility; apps that publish a client metadata
document use [CIMD](cimd.md) instead. Background: [ADR-0008](../adr/0008-client-registration.md)
§2–3 and §8–10.

Anyone who can reach the proxy can register an app. A registration grants nothing by itself: every
sign-in still shows the consent page, marks the app **"Not verified"**, and passes the access gate.

## Settings

| Setting | Default | Effect |
|---|---|---|
| `BYWARD_DCR` | `true` | `false` stops serving `/register` (404) and advertising it. Apps registered earlier are unknown from then on; turning it back on brings back those that have not expired. |
| `BYWARD_CLIENT_DENYLIST` | — | Comma-separated entries the proxy refuses: a CIMD client ID (an `https` URL) or a host name. A host refuses every DCR or CIMD app that returns to it; a subdomain is another host. Spellings of the same host or URL match too: letter case, a trailing dot, and for a URL `:443` and percent-encoding in the path. Static clients are never checked. |

A DCR client ID alone cannot be denied: the app would just register again. Deny the host it
returns to instead.

## What the proxy accepts

- **Redirect URIs** follow the [redirect policy](../adr/0009-redirect-uri-policy.md): `https`, or
  `http` on a loopback host; no custom schemes. URIs that fail are **dropped** and the
  registration keeps the others. If none passes, the answer is 400 `invalid_redirect_uri`. A host
  on the denylist refuses the registration.
- **Authentication:** `none` (the default) or `private_key_jwt` with `jwks` or `jwks_uri`, which
  is fetched through the SSRF guard. A client secret is never issued, and a registration asking for
  one is refused.
- **Grants:** `authorization_code`, optionally `refresh_token`; `response_type` `code`. Scopes
  other than the proxy's scope and `offline_access` are dropped.
- **No management endpoint** (RFC 7592): an app cannot read, change or delete its registration.

The answer (201) echoes every registered field, with the values the proxy substituted, as RFC
7591 §3.2.1 requires.

**Cursor:** the desktop app registers `cursor://anysphere.cursor-mcp/oauth/callback` and
`https://www.cursor.com/agents/mcp/oauth/callback`. The `cursor://` URI is dropped, so the
desktop app's custom-scheme callback is not accepted. Whether Cursor desktop then signs in is
verified in the human compatibility run, not by the proxy's tests.

## Limits and lifetime

| Control | Value |
|---|---|
| Rate limit | 30 registrations per minute per client address, at most 10 at once (IPv6 grouped by /64); over it, 429 with `Retry-After` ([rate limits](../reference/rate-limits.md)) |
| Cap | 10,000 live registrations; over it, 503 `temporarily_unavailable` with `Retry-After: 60` |
| Never used | deleted 24 h after registering if the app never redeemed a code |
| Lifetime | 90 days after the last use: every code redemption or refresh renews it, at most once a day |

An expired or deleted registration is unknown: the sign-in page says the app is not registered,
`/token` answers 401 `invalid_client`, and the app registers again.
A store failure while registering is 503 with `Retry-After: 60`, never a refusal.

## Watching it

Every registration and every refusal is audited as `client_registered`, with outcome `success`
and reason `dcr`, or outcome `failure` and the reason: `invalid_redirect_uri`,
`invalid_client_metadata`, `full`, `unavailable` or `rate_limited`. Those audit records are
rate-limited per client address. `byward_dcr_registrations_total` counts the same outcomes
([observability](../reference/observability.md)). Dropped redirect URIs are logged at info as
"client registration dropped redirect URIs", with the client ID and the URIs (scheme, host and
path, never the query).
