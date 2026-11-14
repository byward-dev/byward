# Research: generic MCP authentication proxy (2026-11-05)

Snapshot of the landscape that informed ADR-0001. Full detail:
[research/landscape-2026-11.md](research/landscape-2026-11.md).
Claims marked *[unverified]* had no primary
source; *[secondary]* rests on third-party sources only. Versions checked via `gh` on the date
above — re-check before relying on them.

## 1. MCP authorization spec

| Revision | Auth / transport highlights |
|---|---|
| 2025-06-18 | Server = OAuth Resource Server; Protected Resource Metadata (RFC 9728); RFC 8707 required; security best-practices page |
| 2025-11-25 | OIDC discovery; step-up (SEP-835); CIMD (SEP-991); `WWW-Authenticate` optional with well-known fallback |
| **2026-07-28 (current)** | RFC 9207 `iss`; **DCR deprecated**; credentials bound to issuing AS; **sessions removed**, POST-only, no `initialize`; required `Mcp-Method`/`Mcp-Name` headers; HTTP+SSE deprecated |

Key requirements (2026-07-28): OAuth 2.1; PRM with `authorization_servers`; clients try
path-inserted then root well-known URIs; PKCE S256 mandatory; clients always send `resource`;
registration order pre-registered → CIMD → DCR; servers MUST validate audience and MUST NOT
pass tokens through; 403 `insufficient_scope` for step-up.

Extensions (stable): Enterprise-Managed Authorization (ID-JAG) and OAuth Client Credentials.

Security best practices binding on a proxy: per-client **consent** before forwarding upstream
(confused deputy), no token passthrough, sessions never used for auth (bind `user:session`),
SSRF guards when fetching metadata and CIMD documents, mix-up protection via `iss`.

Sources:
- https://modelcontextprotocol.io/specification/2026-07-28/changelog
- https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization
- https://modelcontextprotocol.io/specification/2026-07-28/basic/transports/streamable-http
- https://modelcontextprotocol.io/docs/2026-07-28/tutorials/security/security_best_practices
- https://modelcontextprotocol.io/extensions/auth/enterprise-managed-authorization
- https://modelcontextprotocol.io/extensions/auth/oauth-client-credentials
- https://datatracker.ietf.org/doc/draft-ietf-oauth-client-id-metadata-document/

## 2. Identity providers

| IdP | DCR | CIMD | RFC 8707 | Delegation |
|---|---|---|---|---|
| Entra ID | No | No (in progress) | Yes for v2 resources, exact App ID URI match | OBO (not RFC 8693) |
| Okta | Protected | No *[secondary]* | No (fixed aud per AS) | XAA *[GA unverified]* |
| Auth0 | Yes *[secondary]* | Yes | Toggle | RFC 8693, Token Vault |
| Keycloak 26.8 | Yes | Experimental | Experimental | RFC 8693 |
| Google | No *[secondary]* | ? | ? | ? |
| GitHub OAuth | No | No | No | No |
| Cognito | No *[secondary]* | No | Yes (2025-10) | ? |
| WorkOS / Descope / Stytch / Clerk / Ping | Yes | Mostly | Varies | Varies |

Entra notes: v2 `aud` = client-ID GUID; v1 `aud` nondeterministic; trailing slash →
AADSTS9010010; requesting only `openid profile email` yields a Graph token.

Sources:
- https://learn.microsoft.com/en-us/entra/agent-id/secure-mcp-server-with-entra-id
- https://learn.microsoft.com/en-us/microsoft-365/copilot/extensibility/plugin-authentication-dynamic-client-registration
- https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth2-on-behalf-of-flow
- https://support.okta.com/help/s/article/oidc-does-okta-support-the-resource-parameter-and-audience-switching
- https://auth0.com/docs/get-started/auth0-overview/create-applications/cimd-overview
- https://www.keycloak.org/securing-apps/mcp-authz-server
- https://aws.amazon.com/about-aws/whats-new/2025/10/amazon-cognito-resource-indicators-protection-oauth-2-0-resources
- https://github.blog/changelog/2025-07-14-pkce-support-for-oauth-and-github-app-authentication/
- https://workos.com/changelog/client-id-metadata-support-for-mcp-auth
- https://clerk.com/changelog/2026-09-17-client-id-metadata-documents-ga

## 3. Existing proxies and gateways

| Product | Lang / license | Latest | AS facade (DCR/CIMD) | stdio | Tool authz | Fit |
|---|---|---|---|---|---|---|
| agentgateway | Rust / Apache-2.0 | v1.7.0 (2026-10-27) | Proxy mode; Entra bridge | Yes | CEL | Full gateway |
| Pomerium | Go / Apache-2.0 | v0.34.0 (2026-11-04) | Yes (CIMD; DCR flag) | No | PPL | Full IAP |
| ToolHive | Go / Apache-2.0 | v0.62.0 (2026-11-04) | K8s operator only | Yes | Cedar | Platform |
| sigbit/mcp-auth-proxy | Go / MIT | v2.10.2 (2026-05-08) | DCR only | Yes | No | Closest shape; slowing |
| FastMCP OAuthProxy | Python / Apache-2.0 | v4.1.6 (2026-11-03) | DCR + CIMD + consent; Entra OBO | n/a | Framework | Python only |
| workers-oauth-provider | TS / MIT | v1.2.4 (2026-10-22) | Full AS | No | No | Workers only |
| oauth2-proxy | Go / MIT | v7.15.5 (2026-10-01) | No (PR #3488 open) | No | No | Not MCP-aware |
| Envoy Agent Router / Kong / APIM / Traefik Hub | various | — | Resource server only | No | Some | Need an AS behind them |
| supergateway / sparfenyuk mcp-proxy | TS / Python | v4.2.1 / v0.14.0 | No | Yes | No | Transport bridges |
| mcp-airlock (Shalimov04) | ? | — | ? | ? | Policy | Overlapping "stateless governance proxy" — evaluate |

Sources:
- https://github.com/agentgateway/agentgateway, https://agentgateway.dev/docs/standalone/latest/integrations/auth/entra/
- https://www.pomerium.com/docs/capabilities/mcp
- https://docs.stacklok.com/toolhive/concepts/embedded-auth-server
- https://github.com/sigbit/mcp-auth-proxy
- https://gofastmcp.com/servers/auth/oauth-proxy, https://gofastmcp.com/integrations/azure
- https://github.com/cloudflare/workers-oauth-provider
- https://github.com/oauth2-proxy/oauth2-proxy/pull/3488
- https://learn.microsoft.com/en-us/azure/api-management/secure-mcp-servers
- https://github.com/supercorp-ai/supergateway, https://github.com/sparfenyuk/mcp-proxy
- https://github.com/Shalimov04/mcp-airlock

## 4. Client compatibility

| Client | DCR | CIMD | Static ID | Redirect URI |
|---|---|---|---|---|
| Claude.ai / Desktop | Yes | Yes (needs `none` auth advertised) | Yes | `https://claude.ai/api/mcp/auth_callback` |
| Claude Code | Yes | Yes | `--client-id` | `http://localhost:<port>/callback`; no auto step-up |
| VS Code | Yes *[secondary]* | Yes | Yes | `http://127.0.0.1:33418/`, `https://vscode.dev/redirect` |
| Cursor | Yes | *[unverified]* | Yes | `http://localhost:8787/callback`, https variant |
| ChatGPT | Yes | Preferred (`private_key_jwt`/`none`) | Partial | Needs RFC 9207 `iss` |
| MCP Inspector | Yes *[secondary]* | User-supplied | Yes | `http://localhost:6274/oauth/callback` |

Constraints: Claude reads only the first `authorization_servers` entry; Claude timeouts 10 s
(discovery/registration/token), 30 s (refresh).

Sources:
- https://claude.com/docs/connectors/building/authentication.md
- https://code.claude.com/docs/en/mcp
- https://vscode.dev/oauth/client-metadata.json
- https://cursor.com/docs/mcp
- https://developers.openai.com/plugins/build/auth
- https://zuplo.com/learn/mcp/compatibility/clients *[secondary]*

## 5. Lessons from prior implementations

| Keep | Avoid |
|---|---|
| off / bearer / broker modes; per-provider audience defaults | Encryption key derived from the IdP client secret |
| Stateless HMAC-signed state; PKCE passed end-to-end | Identical access/refresh tokens, no `exp`, wrapping the IdP refresh token |
| Session bound to user `sub` | DCR returning one shared ID without binding client/redirect at `/token` |
| RFC 8693 exchange with `act` claim | Hard-coded email allowlist; backend skipping `aud` check |
| Claim-based gating | No consent step; random per-process state key |
