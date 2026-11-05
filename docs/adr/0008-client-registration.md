# ADR-0008: Client registration — static, CIMD and DCR, strictly validated

- Status: Accepted
- Date: 2026-11-05
- Issue: #7 (F6)

## Context

MCP 2026-07-28: clients try pre-registered → CIMD → DCR; "Dynamic Client Registration is
deprecated" and servers MAY support it; PKCE S256 is a client MUST, and clients MUST refuse a
server without `code_challenge_methods_supported`; "MCP proxy servers using static client IDs
**MUST** obtain user consent for each dynamically registered client". CIMD draft -03: the
`client_id` URL rules (§3), no redirects (§6), never cache errors or invalid documents (§6.2),
read at most 5 KB, and "MUST NOT fetch a Client ID Metadata Document URL or any URLs contained
within" it that resolve to special-use addresses (§10.7).

Clients (2026-11-05): Claude, ChatGPT and VS Code use CIMD when advertised (Claude only if
`none` is advertised too); ChatGPT's CIMD client and Claude's `/confidential_client` use
`private_key_jwt`; CIMD is unverified for Cursor, Gemini CLI and Windsurf, which use DCR.
VS Code, the TypeScript SDK and Claude Code re-register on `invalid_client`; claude.ai registers
a new client on every fresh connection. All send PKCE S256 (babs's claim that Cursor and MCP
Inspector omit it is outdated).

Competitors (source, 2026-11-05): registration lifetimes range from none (Pomerium, FastMCP,
sigbit — unbounded growth) to 168 h (babs — expires before our 30-day refresh tokens) to 90 days
sliding (workers-oauth-provider). Pomerium only logs the redirect URI at `/token` and accepts
PKCE `plain`; agentgateway echoes redirect URIs unchecked; sigbit stores DCR input unvalidated
(its #191: code interception). ToolHive labels names "(not verified)"; FastMCP badges any CIMD
domain; nobody offers operator-trusted hosts.

## Decision

1. **All three methods; DCR on by default, can be switched off.** Advertise
   `client_id_metadata_document_supported`, `token_endpoint_auth_methods_supported`
   `["none","private_key_jwt"]`, `code_challenge_methods_supported` `["S256"]` and
   `authorization_response_iss_parameter_supported`.
2. **DCR accepts** `token_endpoint_auth_method` `none` or `private_key_jwt` (with `jwks` or
   `jwks_uri`), never issues a client secret, only `authorization_code` + `refresh_token` and
   `response_type=code`, only supported scopes, redirect URIs per ADR-0009; `software_statement`
   ignored; no RFC 7592 management endpoint.
3. **DCR records** live in the store (ADR-0007): 90-day sliding expiry renewed by a conditional
   update; never-used registrations deleted after 24 h; per-IP limit 30/min with burst 10 (IPv6
   grouped by /64); global cap 10,000 (503). Unknown or expired clients get exactly
   `invalid_client`.
4. **CIMD:** §3 URL rules; the SSRF guard (`code.dny.dev/ssrf`, pinned) covers the document,
   `jwks_uri` and `logo_uri` — https only, no redirects, 5 KB, 5 s; cache per HTTP headers clamped
   to 60 s–24 h; errors never cached, fetches rate-limited per URL; optional host allowlist, off by
   default. Any failure returns `invalid_client` and never redirects to the client.
5. **Static clients** from operator config: `none`, `private_key_jwt`, or `client_secret_basic`/
   `post` (static only; secrets via `*_FILE`, constant-time comparison).
6. **`/token` re-checks** client ID, exact redirect URI, S256 verifier and client
   authentication; `private_key_jwt` assertions need `aud` = our token endpoint, a short `exp`,
   and a `jti` replay cache in the store.
7. **PKCE S256 required**; `plain` or a missing challenge is rejected. No override.
8. **Client trust level** for consent: verified (CIMD host on the operator's trusted list), domain
   (other CIMD hosts), not verified (DCR). A redirect host different from the CIMD host triggers a
   warning, never a block; loopback reads "an app on this computer".
9. **Denylist** by CIMD URL or redirect host (a client ID alone is re-registered around).
10. **Consent** is mandatory for DCR and CIMD clients; whether static clients see it, and how
    scopes are worded (operator text per scope), is F7.

## Consequences

- Hosted clients that register from shared egress IPs can hit the per-IP limit; documented, and
  mitigated because Claude, ChatGPT and VS Code use CIMD instead.
- Expiring registrations is safe: every surveyed client re-registers on `invalid_client`.
- Startup rejects DCR without consent and static secrets supplied inline instead of `*_FILE`.

## Considered options

- Static + CIMD only (DCR off) — rejected for v0.1: Cursor, Gemini CLI, Windsurf need DCR.
- Sealed, stateless `client_id` (babs) — rejected: no cap, listing, deletion or denylist.
- Signed software statements, attestation-based client auth, RFC 7592, OpenID Federation, a
  curated registry of known clients, initial access tokens — rejected: no client uses them, or
  they go stale. DPoP is v0.2; an operator approval queue and per-host quotas are later.
- Showing registration age on consent — rejected: claude.ai re-registers on every connection.
