# ADR-0006: Token model — minted, sealed proxy tokens with a revocation deny list

- Status: Accepted; amended by ADR-0007, and 2026-11-14 (#287)
- Date: 2026-11-05
- Issue: #5 (F4)

## Context

The spec forbids passthrough ("The MCP server **MUST NOT** pass through the token it received from
the MCP client"), requires audience-bound tokens, and requires refresh-token rotation for public
clients. Relaying IdP tokens (only agentgateway does — its Entra `/token` forwards the form and
returns Entra's response) hands the MCP client a 90-day Entra refresh token bound to our IdP app
and a GUID audience; every other surveyed project mints its own tokens and keeps IdP refresh
tokens server-side.

Nothing but the broker ever reads a proxy token (no passthrough; MCP clients treat tokens as
opaque), so a JWT's portability buys nothing and exposes claims. OWASP ASVS 5.0.0 7.4.1 (L1)
requires that terminated sessions cannot be used again and names, for self-contained tokens,
"a list of terminated tokens, disallowing tokens produced before a per-user date and time"; 7.4.2
(L1) requires ending all sessions of a disabled account. RFC 7009 §3 accepts short-lived access
tokens as the alternative to immediate revocation. Closest competitor babs seals tokens but can
only revoke all users at once (`REVOKE_BEFORE`) and has no revocation endpoint; Pomerium
advertises `revocation_endpoint` without a route. MCP Inspector revokes on "Clear OAuth state"
and Claude Code reads `revocation_endpoint` on logout.

Refresh rotation grace in practice: Okta 0–60 s (default 30 s); Auth0 lets "only the previous
token" be reused inside its overlap period; RFC 9700 §4.14.2 defines no grace. Claude Code
shares one refresh token across concurrent sessions and reuses it minutes apart
(anthropics/claude-code#91641, open; not fixed as of 2.1.318), which fails against any compliant
server.

## Decision

1. **The broker mints its own proxy tokens.** IdP tokens never reach MCP clients; the IdP refresh
   token is stored encrypted and deleted when the grant ends.
2. **Access token: sealed, self-contained** (AEAD, e.g. XChaCha20-Poly1305) bound to our resource
   URL and token type as associated data. Minimal claims: grant ID, subject, `iat`, `exp`. Carries
   a key ID and a format version so sealing keys rotate with overlap and the format can change.
3. **Revocation deny list:** revoked grant IDs and per-user "issued before T" cut-offs, kept for
   one access-token lifetime, held in memory and synced from the store. A replica whose list is
   staler than 30 s rejects tokens (fail closed).
4. **Refresh token:** random, stored only as a hash, rotated on every use. Reuse of the
   immediately previous token within the grace window (default 30 s, range 0–60 s) issues a new
   token; any other reuse revokes the grant.
   _Amended 2026-11-14 (#287):_ a refresh token goes to every client that registered the
   `refresh_token` grant, whether or not it asks for `offline_access`; see the amendment below.
5. **Lifetimes (configurable, bounds checked at startup):** authorization code 60 s single-use (a
   reused code revokes its tokens); access token 1 h (5 min–1 h); refresh token 30 days absolute,
   14 days idle, and never beyond the IdP session — each refresh also refreshes the IdP token.
6. **IdP failures during refresh:** `invalid_grant` from the IdP revokes the grant; a transient
   failure returns `503 temporarily_unavailable` without consuming the refresh token. The IdP call
   budget keeps a refresh well inside Claude's 30 s refresh timeout.
7. **`/revoke` (RFC 7009) in v0.1:** revoking either token revokes the grant (refresh token
   deleted, grant deny-listed, IdP tokens deleted); best-effort revocation at the IdP runs in the
   background with a timeout; tokens are revocable only by the client they were issued to; unknown
   tokens get 200; a store failure gets 503 with `Retry-After`, never a false 200. Advertised with
   `revocation_endpoint_auth_methods_supported` `none` and `private_key_jwt`. No introspection.
8. **Separate keys per purpose:** proxy-token sealing, F13 identity-assertion signing, IdP-token
   encryption at rest. Type prefixes distinguish access and refresh tokens (names decided in
   implementation) and enable secret scanning.
9. **Operator controls:** revoke-user and revoke-all commands; metrics for reuse detections,
   revocations and deny-list size.

## Consequences

- A user disabled at the IdP keeps access for at most one access-token lifetime (1 h), comparable
  to Entra's own 60–90 min tokens. Revocations in the proxy apply within the 30 s sync bound.
- Losing the sealing key only forces refreshes. Restoring an old store resurrects revoked grants
  and rotated refresh tokens: the runbook rotates the sealing key after any restore, and
  _amended by ADR-0007_, a store epoch refuses refresh tokens from before the restore.
- Constraint on F6: DCR client registrations must outlive the 30-day absolute refresh lifetime.
- Claude Code users running several sessions may be asked to sign in again (#91641) — documented
  limitation.

## Considered options

- Relay IdP tokens — rejected: IdP refresh token in the client, no rotation of our own, GUID
  audience.
- JWT access tokens — rejected: no external verifier exists; exposes claims; RFC 8725 pitfalls.
- Opaque reference with a store lookup per request (Pomerium, workers-oauth-provider) — rejected:
  store on every MCP request; the deny list meets ASVS 7.4.1 without it.
- Wider grace window to absorb #91641 — rejected: weakens replay detection for every client.

## Amendment 2026-11-14 (refresh tokens without `offline_access`, #287)

**Context.** byward issued a refresh token only when the client asked for `offline_access`. MCP
clients that follow the spec's scope selection request the scope in the `WWW-Authenticate`
challenge (`mcp`), so they got no refresh token and their users signed in again every hour: the MCP
Python SDK 1.30.0 (verified on Auth0, #282) and the TypeScript SDK 1.x never add `offline_access`.

The MCP specification (revision 2026-07-28, Authorization, "Refresh Tokens") says clients that want
refresh tokens "**SHOULD** include `refresh_token` in their `grant_types` client metadata" and "**MAY**
add `offline_access` to the `scope` parameter ... when the Authorization Server metadata contains it in
`scopes_supported`", that they "**MUST NOT** assume refresh tokens will be issued; the AS retains
discretion", and that servers "**SHOULD NOT** include `offline_access` in `WWW-Authenticate` scope or
Protected Resource Metadata `scopes_supported`, as refresh tokens are not a resource requirement".
OAuth 2.1 (draft-ietf-oauth-v2-1-17, §3.2.3) names both policies an authorization server may use:
issuing refresh tokens "only to clients that are registered to receive them" or "only when the client
requests a particular scope (such as the offline_access scope ...)". OIDC Core §11 and RFC 6749 §1.5
leave issuance to the authorization server.

**Decision.**

1. A refresh token goes to every client that registered the `refresh_token` grant (`grant_types` in
   its DCR or CIMD metadata, or a static client), whether or not it asks for `offline_access`. A
   client that did not register it gets none, even when it asks for `offline_access`.
2. The grant records it as `offline_access` in its scopes, and the token response reports that scope
   as granted (RFC 6749 §5.1). A grant whose IdP returned no refresh token still gets none of ours
   (its first refresh could only revoke the grant), with the warning that names the IdP.
3. `offline_access` stays in the authorization server metadata's `scopes_supported`, for clients that
   add it, and is never in the challenge or the protected resource metadata.
4. The consent page shows the grant's lifetime ("up to 30 days") for a client that registered the
   grant, otherwise one access token's (ADR-0010 §4), and a remembered consent covers a grant that
   refreshes only if it was given for that lifetime (ADR-0010 §3). The lifetime is fixed when the
   login starts at `/authorize`: the callback grants refresh tokens only if the page said "up to 30
   days" and the client still registers the grant, and `/token` checks the registration again, so a
   registration change during a sign-in never lengthens the grant past what the page showed.
5. No setting restores the old rule: a client that registered the grant has declared that it wants
   refresh tokens, and the rotation, reuse detection and lifetimes of this ADR apply to it unchanged.

**Consequences.** Spec-following clients keep a session for up to 30 days instead of an hour. An
attacker gains nothing: it always chose its own scope. Clients whose metadata leaves out the
`refresh_token` grant get one access token, as before. Consents remembered before this change for
a client that registered the grant were given while the page said "up to 1 hour": they do not cover
the longer grant, so those users see the page once more.

**Considered.** Adding `offline_access` to the challenge's scope or to the protected resource
metadata — rejected: the spec advises servers against both, and the challenge's scope would wrongly
tell clients that the resource requires long-lived access (the protected resource metadata would not
even reach clients that take the challenge's scope). A setting to keep the old rule — rejected, as in
decision 5.
