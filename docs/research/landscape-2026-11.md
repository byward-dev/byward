# Landscape detail — MCP auth spec, IdPs, proxies, clients (2026-11-05)

Full research brief behind `docs/research.md`. *[unverified]* = no primary source found;
*[secondary]* = third-party only (Zuplo, blogs, forums). Versions via `gh` on the date above.

## A. MCP authorization spec

### A1. Revisions

| Revision | Released | Auth / transport highlights |
|---|---|---|
| 2025-03-26 | 2025-03-26 | First OAuth 2.1 framework; Streamable HTTP replaces HTTP+SSE |
| 2025-06-18 | 2025-06-18 | Server = OAuth RS; PRM (RFC 9728); RFC 8707 required; security best practices page; `MCP-Protocol-Version` header |
| 2025-11-25 | 2025-11-25 | OIDC discovery (PR #797); step-up (SEP-835); CIMD (SEP-991); `WWW-Authenticate` optional w/ well-known fallback (SEP-985); 403 on bad Origin |
| **2026-07-28** | 2026-07-28 (RC 05-29) | RFC 9207 `iss` (SEP-2468); DCR deprecated (PR #2858); DCR clients send `application_type` (SEP-837); credentials bound to issuing AS (SEP-2352); sessions removed (SEP-2567); stateless, no `initialize`, `server/discover`, `subscriptions/listen` (SEP-2575); `Mcp-Method`/`Mcp-Name` headers (SEP-2243); HTTP+SSE deprecated (SEP-2596) |

Sources: https://modelcontextprotocol.io/specification/2026-07-28/changelog (and the
2025-06-18 / 2025-11-25 changelogs), https://github.com/modelcontextprotocol/modelcontextprotocol/releases

### A2. Requirements (2026-07-28)

| Topic | Requirement |
|---|---|
| Applicability | Auth OPTIONAL; HTTP SHOULD conform; stdio SHOULD NOT (env credentials) — a proxy is how a stdio server gets OAuth |
| OAuth 2.1 | AS MUST implement draft-ietf-oauth-v2-1-13 |
| PRM | MUST serve PRM with ≥1 `authorization_servers` |
| PRM discovery | `resource_metadata` in 401 `WWW-Authenticate` **or** well-known; clients try path-inserted then root |
| AS discovery | RFC 8414 or OIDC; fetched `issuer` MUST equal URL-derived issuer (new) |
| PKCE | S256 MUST; clients refuse if `code_challenge_methods_supported` absent |
| RFC 8707 | Clients MUST send `resource` on authorize and token; omit trailing slash |
| Registration order | pre-registered → CIMD (if `client_id_metadata_document_supported`) → DCR → ask user |
| CIMD | `client_id` = HTTPS URL; doc has `client_id` (exact), `client_name`, `redirect_uris`; AS validates redirects and shows redirect host |
| Scopes / step-up | SHOULD include `scope` in 401; 403 `insufficient_scope` with `scope` + `resource_metadata` |
| Audience | Server MUST validate token was issued for it; MUST NOT accept or transit other tokens |
| No passthrough | Upstream calls use a separate token from the upstream AS |
| RFC 9207 | Clients MUST compare `iss` when present; reject if advertised but absent |
| Misc | HTTPS AS endpoints; redirects localhost or HTTPS; rotate refresh tokens for public clients |

Source: https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization

### A3. Authorization extensions (https://github.com/modelcontextprotocol/ext-auth)

| Extension | ID | Stage | Mechanism |
|---|---|---|---|
| Enterprise-Managed Authorization (ID-JAG) | `io.modelcontextprotocol/enterprise-managed-authorization` | Stable | IdP ID token/SAML → ID-JAG at enterprise IdP → jwt-bearer grant at MCP AS; no redirect |
| OAuth Client Credentials | `io.modelcontextprotocol/oauth-client-credentials` | Stable | RFC 6749 §4.4; RFC 7523 assertions recommended |

ID-JAG draft is at -06 (2026-10-30), not an RFC. Listed support: Keycloak 26.7+ (experimental),
Okta XAA, PingFederate 13.1, workers-oauth-provider 0.7+, FastMCP 4.0+ (beta).
*[unverified]* normative ext-auth `.mdx` text not read.

### A4. Security best practices binding on a proxy

| Threat | Requirement |
|---|---|
| Confused deputy | MUST obtain per-client consent before forwarding upstream: per-user registry of approved `client_id`s; consent UI shows client name, scopes, redirect_uri; CSRF; `frame-ancestors`/`X-Frame-Options: DENY`; `__Host-` Secure HttpOnly SameSite=Lax signed cookie bound to `client_id`; exact redirect match; `state` random, stored after consent, single-use, short TTL |
| Token passthrough | Never accept tokens not issued for the proxy |
| Session / state-handle hijacking | Never authenticate by session; bind `<user_id>:<session_id>` |
| SSRF | Fetching PRM, AS metadata, CIMD: HTTPS only, block private/loopback/link-local/ULA, validate redirect hops, guard DNS rebinding |
| Mix-up | RFC 9207 `iss`; PKCE alone insufficient |

Source: https://modelcontextprotocol.io/docs/2026-07-28/tutorials/security/security_best_practices

### A5. Transport facts

| Item | 2025-06-18 / 2025-11-25 | 2026-07-28 |
|---|---|---|
| Methods | POST, GET (SSE), DELETE | POST only; GET/DELETE → 405 |
| `Mcp-Session-Id` | Optional; 404 → re-init | Removed |
| `MCP-Protocol-Version` | After init | Every POST, must match `_meta`; mismatch 400 `HeaderMismatch` (-32020); missing MAY = 2025-03-26 |
| New headers | — | `Mcp-Method`, `Mcp-Name` REQUIRED, must match body — enables tool-level authz without body parsing |
| SSE | Resumable (`Last-Event-ID`) | Per-request; close = cancel; send `X-Accel-Buffering: no` |
| Compat | — | Client tries modern first, falls back to `initialize` on 400 |

Source: https://modelcontextprotocol.io/specification/2026-07-28/basic/transports/streamable-http

## B. IdPs — details

**Entra ID.** No DCR ("doesn't publish an RFC 7591 registration endpoint"), no CIMD (Microsoft
"working with the Entra team"). Direct mode (no broker) works for clients with pre-registered
IDs if: `requestedAccessTokenVersion=2`; App ID URI == MCP URL exactly, no trailing slash;
PRM `authorization_servers` = `https://login.microsoftonline.com/<tenant>/v2.0`; validate
`aud` = client-ID GUID; requested scope belongs to the same app (else AADSTS9010010).
v1 tokens: `aud` nondeterministic unless `aud` optional claim with `use_guid`. OBO =
jwt-bearer + `requested_token_use=on_behalf_of` (not RFC 8693), user principals only, may
return Conditional Access claim challenges. agentgateway's Entra bridge strips `resource`.
Older reports (AADSTS901002, "use `.default` instead of `resource`") conflict with the
2026-09 Microsoft doc — official doc wins, test it.
- https://learn.microsoft.com/en-us/entra/agent-id/secure-mcp-server-with-entra-id
- https://learn.microsoft.com/en-us/microsoft-365/copilot/extensibility/plugin-authentication-dynamic-client-registration
- https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth2-on-behalf-of-flow
- https://agentgateway.dev/docs/standalone/latest/integrations/auth/entra/

**Others.**
- Okta: DCR protected (`okta.clients.register` or admin token); no RFC 8707 — fixed `aud` per
  custom AS. https://developer.okta.com/docs/api/secures-ai/mcp-servers
- Auth0: CIMD (500/tenant cap); RFC 8707 needs "Resource Parameter Compatibility Profile";
  Custom Token Exchange, Token Vault. https://support.auth0.com/center/s/article/mcp-audience-error-with-auth0
- Keycloak 26.8.1: anonymous DCR via policies; CIMD `--features=cimd` (since 26.6.0);
  `--features=resource-indicators`; RFC 9207; token exchange since 26.2.0.
  https://www.keycloak.org/2026/10/keycloak-2680-released
- Google: no DCR *[secondary]*. https://gofastmcp.com/v3/integrations/google
- GitHub: PKCE since 2025-07-14 (not enforced); no DCR/CIMD/8707 found.
- Cognito: RFC 8707 since 2025-10-27 (Essentials/Plus); no DCR *[secondary]*.
- Ping AIC: open DCR + AI-agent DCR, may_act token exchange.
  https://docs.pingidentity.com/pingoneaic/identity-for-ai/ai-agent-identities-configure-dcr-onboarding-flow.html
- WorkOS (CIMD 2025-11-30), Descope (CIMD), Stytch (CIMD beta), Clerk (CIMD GA 2026-09-17).
  https://docs.descope.com/agentic-identity-hub/core-components/mcp-servers ,
  https://stytch.com/docs/connected-apps/oauth-learn-more/client-types

## C. Products — details beyond `docs/research.md`

| Product | Notes |
|---|---|
| agentgateway v1.7.0 | AS-proxy mode: DCR proxied (Keycloak) or bridged (Entra: pre-registered ID, synthesized RFC 8414, strips `resource`); CIMD not stated; CEL authz auto-filters tools/list; token exchange documented for Solo Enterprise only. https://agentgateway.dev/docs/standalone/latest/mcp/mcp-authn/ |
| Pomerium v0.34.0 | Is the AS; CIMD inbound, DCR behind flag; `upstream_oauth2` per-user token cache/refresh/inject; PPL `mcp_tool`; logs method/tool/params. https://www.pomerium.com/docs/capabilities/mcp/mcp-upstream-oauth |
| ToolHive v0.62.0 | Embedded AS (K8s operator only): CIMD preferred, DCR fallback; upstream token keyed by `tsid`; RFC 8693; Cedar default-deny. https://docs.stacklok.com/toolhive/concepts/auth-framework |
| sigbit/mcp-auth-proxy v2.10.2 | `-- <cmd>` stdio wrap; own AS with DCR at `/.idp/register`; BoltDB; ACME; claim→header mapping; user/attribute allowlists. https://github.com/sigbit/mcp-auth-proxy |
| FastMCP v4.1.6 | OAuthProxy: DCR emulation + CIMD (default on), consent screen, own JWTs; `EntraOBOToken` (3.0+); ID-JAG beta. https://gofastmcp.com/servers/auth/oauth-proxy |
| TS SDK | `ProxyOAuthServerProvider` frozen in `server-legacy@2.4.0`; SDK says use a dedicated IdP. https://github.com/modelcontextprotocol/typescript-sdk/blob/main/docs/serving/authorization.md |
| workers-oauth-provider v1.2.4 | Full AS (DCR, CIMD, PRM) targeting 2026-07-28; `tokenExchangeCallback`. |
| mcp-remote v0.16.0 | OAuth *client* bridge: DCR, `--static-oauth-client-info`, `--client-metadata-url`, `--resource`. https://github.com/geelen/mcp-remote |
| oauth2-proxy v7.15.5 | No PRM/DCR/CIMD; PR #3488 open since 2026-08; issue #3284 open. |
| Envoy AI Gateway → Agent Router v1.2.0 | RS only, PRM, `toolSelector` + CEL; K8s-first. https://theagentrouter.ai/docs/capabilities/mcp/ |
| Kong (Enterprise MCP plugins 3.12+) | RS only; introspection/JWKS; token exchange 3.14+; per-tool ACL 3.13+. https://developer.konghq.com/plugins/ai-mcp-oauth2/ |
| Azure APIM | RS (`validate-azure-ad-token`); tools only; credential manager injects upstream OAuth tokens; no per-tool policy. |
| Docker MCP Gateway v0.44.3 (pre-release) | Static bearer `MCP_GATEWAY_AUTH_TOKEN`; OAuth client (DCR) to remotes. |
| kgateway v2.5.0 | MCP moved to agentgateway in 2.3.0. |
| IBM ContextForge v1.1.0 | `mcpgateway.translate` stdio bridge; per-user upstream OAuth, `X-Upstream-Authorization`; Postgres + Redis. |
| Microsoft mcp-gateway v1.0.0 (tag) | 2026-07-28 clients only; Entra is the AS; `requiredRoles` per tool; K8s + Redis/Cosmos. |
| Obot v0.27.0 | Platform; per-user/group tool access. |
| Teleport v18.10.0 (AGPL) | `tsh mcp connect`; Teleport-signed JWT upstream; role allowlists. |
| Traefik Hub v3.19+ | RS only; `forwardAuthorization`; tool- and argument-level TBAC. |
| Aembit (beta 2026-02-24) | Own AS; credential injection; Okta token exchange. |
| supergateway v4.2.1 / sparfenyuk mcp-proxy v0.14.0 / TBXark mcp-proxy v1.1.0 | Transport bridges; static auth only. |
| MCPJungle 0.4.7 | No OAuth documented; tool groups. |
| hyprmcp/mcp-gateway | Archived 2026-04-29. |
| atrawog/mcp-oauth-gateway | Stale (2025-08), not for production. |

## D. Patterns

| Pattern | Notes |
|---|---|
| Resource server only | Works only when IdP serves CIMD/DCR to your clients, or clients use pre-registered IDs (Entra v2 direct) |
| Broker / proxy AS | Required for Entra/Google/GitHub with DCR-only clients; MUST do per-client consent |
| Token exchange | RFC 8693 (`subject_token`, `audience`/`resource`, `act`); Entra OBO is different; pass CA claim challenges back as 401 |
| Identity propagation | `X-Forwarded-*` only when upstream is reachable solely via proxy; signed JWT assertion (Pomerium `X-Pomerium-Jwt-Assertion`, Cloudflare `Cf-Access-Jwt-Assertion`); stdio: env at spawn (per-user process) or `_meta` — design inference, spec defines nothing |
| Credential vaulting | Pomerium `upstream_oauth2`, ToolHive `tsid`, Arcade, Composio, APIM credential manager |
| Session affinity | 2025-11-25: sticky on `Mcp-Session-Id` or stateless upstream (go-sdk `StreamableHTTPOptions.Stateless`); 2026-07-28: none needed |
| Multi-tenant | Credentials keyed by AS `issuer` (SEP-2352); Claude reads only the first `authorization_servers` entry |
| Tool-level authz | Filter `tools/list` (needs body rewrite), deny `tools/call` (`Mcp-Name` header in 2026) |
| Audit / rate limit | Pomerium per-call logs; Cloudflare Logpush; Kong consumer mapping; OTel `traceparent` in `_meta` (2026) |

## E. Clients — details

| Client | Notes |
|---|---|
| Claude.ai / Desktop | CIMD only if AS advertises CIMD **and** `none`; else DCR; static ID + optional secret; `https://claude.ai/api/mcp/auth_callback`; reads first `authorization_servers` only; timeouts 10 s discovery/registration/token, 30 s refresh. https://claude.com/docs/connectors/building/authentication.md |
| Claude Code | CIMD `https://claude.ai/oauth/claude-code-client-metadata`; `--client-id`, `--client-secret`, `--callback-port`, `oauth.authServerMetadataUrl`; no auto step-up (issue #44652, not planned); issues #68853, #67258 (static clientId casing; DCR without `registration_endpoint`) — fix status unverified |
| VS Code | CIMD `https://vscode.dev/oauth/client-metadata.json`; `http://127.0.0.1:33418/` (random if busy), `https://vscode.dev/redirect`; RFC 8707 only when PRM discovered *[secondary]* |
| Cursor | `http://localhost:8787/callback`, `https://www.cursor.com/agents/mcp/oauth/callback`, legacy `cursor://anysphere.cursor-mcp/oauth/callback` |
| ChatGPT | CIMD `https://chatgpt.com/oauth/client.json` (`private_key_jwt` or `none`); `https://chatgpt.com/connector_platform_oauth_redirect` (with RFC 9207) else `https://chatgpt.com/connector/oauth/{callback_id}`; step-up via `_meta["mcp/www_authenticate"]`. https://developers.openai.com/plugins/build/auth |
| MCP Inspector | `http://localhost:6274/oauth/callback` (web), `http://127.0.0.1:6276/oauth/callback` (CLI); always sends `resource` |
| Gemini CLI | `oauth.clientId/clientSecret`, `redirectUri`; `http://localhost:<random>/oauth/callback` |
| Windsurf / Devin | *[unverified]* |

Broker must therefore support: DCR **and** CIMD (both `none` and `private_key_jwt`),
port-agnostic loopback (RFC 8252 §7.3), exact HTTPS redirect match, RFC 9207 `iss`, Claude's
timeouts, a single `authorization_servers` entry, static clients.

## Unverified / contradictions

| Item | Status |
|---|---|
| Entra `resource` support | Official 2026-09 doc says yes for v2; older reports say no — test |
| Cognito RFC 8707 | AWS says yes; Zuplo says no — AWS authoritative |
| Gemini CLI `iss` validation | Docs yes, Zuplo no — unresolved |
| Okta XAA GA; Auth0 CIMD GA vs EA; Keycloak RFC 8707 landing version | Unverified |
| agentgateway OSS token exchange; AAIF move | Unverified |
| go-sdk 2026-07-28 support | v1.8.0 (2026-09-04) exists; spec support not checked |
