# Let apps sign in with a client metadata document (CIMD)

Claude, Claude Code and VS Code identify themselves with a **Client ID Metadata Document**: their
client ID is an `https` URL, and the document at that URL names the app and lists where it may
return after sign-in. The proxy fetches the document when the app first connects, so these apps
need no registration. This is on by default, and the proxy advertises it in its metadata
(`client_id_metadata_document_supported`). Background: [ADR-0008](../adr/0008-client-registration.md) §4 and §8.

## Settings

| Setting | Default | Effect |
|---|---|---|
| `BYWARD_CIMD` | `true` | `false` stops accepting and advertising CIMD clients. Static clients still work. |
| `BYWARD_CIMD_TRUSTED_HOSTS` | — | Hosts whose documents you vouch for, for example `claude.ai,vscode.dev`. Their apps show as "Trusted by your operator". Consent for their apps is remembered for 30 days per user ([ADR-0010](../adr/0010-consent-screen.md) §2-3); apps of other hosts are asked every time. |
| `BYWARD_CIMD_ALLOWED_HOSTS` | — | When set, only these hosts and the trusted ones may publish documents; any other app is refused before its document is fetched. Empty allows any host. |

Hosts are exact, comma-separated ASCII names, with no scheme, port, path or wildcard: letters,
digits and `- . _` only, at least one dot, no leading, trailing or double dot, and no label that
starts or ends with a hyphen. A subdomain is a different host. An internationalized host goes in its
`xn--` form. An IP address (`203.0.113.5`, `::1`) and a name ending in a number (`127.1`,
`0x7f.0.0.1`, `mcp.10`), which a browser reads as an IPv4 address, are refused at startup: an address
is reached by other spellings too, which no entry could match.

A client ID's host matches an entry in any letter case and with one trailing dot, so
`https://claude.ai./…` is the trusted `claude.ai`; the document's `client_id` must still be its URL
exactly. Nothing else is folded: a client ID whose host is written in Unicode (percent-encoded) never
matches the entry for its `xn--` form, so it shows as "Identified by its web address", or is refused
when `BYWARD_CIMD_ALLOWED_HOSTS` is set.

Entries that name the same host (in any letter case), and an allowed host that is also trusted
(trusted hosts are always allowed), still load, with a warning that names them by their place in the
list. When every allowed host is also trusted there is no such warning: removing them all would
empty `BYWARD_CIMD_ALLOWED_HOSTS`, which allows any host.

Any other host's apps show as "Identified by its web address". Every CIMD app's consent page shows
the host that published its document ("Published by"), and warns when the app returns to an
address outside that host's registrable domain (for example claude.ai returning to evil.example;
app.example.com returning to auth.example.com is not flagged).

## What the proxy checks

- **The URL**:
  - `https` on port 443, with a path other than `/`;
  - no user information, query, fragment or `.`/`..` segments;
  - at most 512 characters.
- **The fetch** goes through the SSRF guard:
  - only public addresses, checked after DNS resolution;
  - no redirects, and no environment proxy;
  - at most 5 KB and 5 s.
- **The document**:
  - `client_id` equals the URL exactly, and `client_name` is present;
  - `redirect_uris` follow the [redirect policy](../adr/0009-redirect-uri-policy.md);
  - `authorization_code` is among the grant types. Refresh tokens are issued if `refresh_token` is too, whether or not the app asks for `offline_access`; without it, none are, even with `offline_access`, and the consent page says "up to 1 hour";
  - no client secret. The auth method is `none` or `private_key_jwt`, with `jwks` or `jwks_uri`, which is fetched through the guard too.
- **Caching**:
  - a document is cached for its `Cache-Control` lifetime, kept between 1 minute and 24 hours. A `no-store` document is still reused for 1 minute;
  - errors and invalid documents are never cached;
  - if a refetch fails for a network reason, a timeout, a 5xx, 408 or 429, the last valid copy keeps working for up to 24 hours after it was fetched. Any other 4xx or an invalid document ends it at once;
  - each URL is fetched at most once at a time, and a failing URL at most every 10 seconds.

If an app's document is refused for good (for example, it no longer matches, is invalid or gone)
when it refreshes, redeems one of its own codes or sends one of its own tokens to `/revoke`, the
grant behind that token or code is revoked, so restoring the document does not bring it back; a
temporary fetch failure never revokes anything.

A refused app sees "This app is not registered with the proxy". If its document can't be fetched
for now, the app sees "Try again in a minute", or HTTP 503 with `Retry-After: 60` at `/token` and `/revoke`. The proxy never redirects
back to the app in either case. Each refusal is logged as a warning, "client metadata refused", with the client ID (when it is a valid one) and the reason: the document, or
the keys at a `jwks_uri`, was unacceptable, and `/token` and `/revoke` answer 401 `invalid_client`.
A temporary failure is logged as "client metadata unavailable" and answered with 503 and
`Retry-After: 60`: network trouble, a timeout, a 5xx, 408 or 429 while fetching the document or the
keys. `byward_cimd_fetches_total` counts fetches by outcome
([observability](../reference/observability.md)).

## App notes

**VS Code** may ask you to sign in twice when you add the server. If the server stays at
"Starting", sign in again from VS Code (the run re-authenticated through VS Code's UI). Both were
observed against Entra on 2026-11-06; the cause is not known.
