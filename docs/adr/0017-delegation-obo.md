# ADR-0017: Delegation — proxy-side Entra On-Behalf-Of in v0.1

- Status: Accepted
- Date: 2026-11-06
- Issue: #15 (F14)

## Context

ADR-0001 names On-Behalf-Of to downstream APIs as part of the Entra differentiator. Microsoft Learn
(OBO flow, updated 2026-06-15): the assertion "must have an audience (`aud`) claim of the app making
this OBO request"; OBO "only works for user principals"; a refresh token is returned only with
`offline_access`; Conditional Access challenges come back as `interaction_required` (AADSTS50079) with a
`claims` value. ADR-0012 already stores, encrypted, the access token for our own `access_as_user` scope.
The real-tenant test (2026-11-05) showed that token works as an OBO assertion for Graph `User.Read` once
Graph is consented (AADSTS65001 before), while a Graph token fails (AADSTS50013).

Competitors (source): agentgateway exchanges proxy-side (RFC 8693 / jwt-bearer) with a cache of 8192
entries capped at the subject token's expiry; FastMCP does OBO inside the MCP server; babs forwards the
raw IdP token to the upstream (its docs warn the audience is not checked); ToolHive's Entra OBO is an
enterprise stub. No project turns AADSTS65001 or Conditional Access into an actionable result.

Clients (source): only 401 and 403 trigger re-authentication — VS Code `isAuthStatusCode` is `401 || 403`;
the TypeScript SDK special-cases 401, 403 and 405 and throws on other statuses. Admin consent (Learn,
v2-admin-consent): `https://login.microsoftonline.com/{tenant}/v2.0/adminconsent?client_id&scope&
redirect_uri&state`, all required except `state`; `redirect_uri` must be registered; success returns
`admin_consent=True`. The test tenant has no Entra ID P1/P2 licence, so Conditional Access could not be
tested.

## Decision

1. **Proxy-side OBO, Entra only (`entra-obo`), in v0.1.** Only our IdP app holds the credential the
   exchange needs. A generic RFC 8693 adapter (Keycloak, Okta) comes later.
2. **Downstream scopes are configured per upstream;** the assertion is the stored `access_as_user`
   token.
3. **The downstream token goes in a dedicated header,** stripped from inbound requests (ADR-0016), never
   in `Authorization`.
4. **Cache** keyed by `tid`, `oid` and downstream scopes; in-memory LRU, bounded; TTL = the token's
   `exp` − 60 s, never beyond the stored assertion's `exp`. Downstream tokens are not refreshed — OBO
   runs again. They are never stored or logged.
5. **Errors:** AADSTS65001 returns HTTP 503 with a JSON body (`downstream_consent_required`) and an
   operator alert containing the admin-consent URL (tenant GUID, our client ID, the configured scopes,
   our registered `/callback/entra`); the callback recognises an `admin_consent=True` response and shows
   a confirmation page. `interaction_required` returns 503 plus an operator hint in v0.1. No 401 or 403
   (they make clients loop). Other errors follow ADR-0012.
6. **Setup guide:** grant admin consent for every downstream API.

## Consequences

- Passing Conditional Access `claims` through to the next login is v0.2 and needs a tenant with Entra
  ID P1 for testing.
- Upstream authors read the downstream token from one header; MCP clients see a plain error on
  consent problems, never a re-login loop.
