# Reference projects (2026-11-05)

Competitors and projects to learn from while grilling F1–F22. Repo metadata checked via
GitHub GraphQL on the date above; behaviour notes come from reading shallow clones or official
docs. *[unverified]* = no primary source read. Re-check versions before relying on them.

Last updated 2026-11-05 (after F1–F8). Source commits for the F6–F8 notes: Pomerium `15c549f`,
Obot `439bdb2`, xnyzer `e32765a`, babs `bf0eb24`, agentgateway `2faf7b4`, ToolHive `9d4eeab`,
FastMCP `1f9d32e`, workers-oauth-provider `b4cec31`, sigbit `76cf8e0`, lethek `c1d351d`.

## 1. Direct competitors — auth proxies with an AS facade

| Project | Lang / license | Latest | Maintained | DCR / CIMD / consent | stdio | Entra | Learn from | Weakness |
|---|---|---|---|---|---|---|---|---|
| [babs/mcp-auth-proxy](https://github.com/babs/mcp-auth-proxy) | Go / Apache-2.0 | v2.4.0 (2026-10-28) | yes | Y / Y / Y | no | tested (generic OIDC) | Stateless AEAD-sealed tokens carrying IdP tokens; refresh-reuse detection; key-rotation runbook; CIMD host allowlist; opt-in IdP token forwarding for OBO; refresh race grace 2 s (`REFRESH_RACE_GRACE_SEC`) | No stdio — **closest competitor**. DCR TTL 168 h, shorter than a 30-day refresh lifetime (docs/configuration.md:52); revocation only via global `REVOKE_BEFORE`, no `/revoke`; Redis required under `PROD_MODE`; custom-scheme redirects opt-in via `REDIRECT_URIS_EXTRA` (beyond MCP's "localhost or HTTPS" MUST) |
| [sigbit/mcp-auth-proxy](https://github.com/sigbit/mcp-auth-proxy) | Go / MIT | v2.10.2 (2026-05-08) | slowing | Y / ? / ? | shared process (`-- <cmd>`) | generic OIDC | Wrapper UX; client-quirk matrix; claim→header mapping | Frozen tool catalog; child exit kills proxy; opt-in token passthrough; DCR fields stored unvalidated, no TTL (idp.go:359-387); #191 unauthenticated DCR → code interception / account takeover (open) |
| [xnyzer/mcp-oauth-gateway](https://github.com/xnyzer/mcp-oauth-gateway) | Go / Apache-2.0 | v0.5.0 (2026-10-12) | yes | Y (toggle) / Y (CIMD-first) / Y | yes | no | `CIMD_ENABLED`/`DCR_ENABLED` toggles; JWT key rotation | Default login is an operator password; IdP optional |
| [lethek/mcp-oauth-proxy](https://github.com/lethek/mcp-oauth-proxy) | Go / **no license** | — | yes | Y / Y / Y | no | no | Per-target RFC 9728 docs; tokens bound to one target; "consent makes DCR safe" write-up; upstream credential modes `provider_token`/`static`/`per_user`; DCR `none` only, never-used clients deleted after 24 h (store.go:964-970); consent CSRF = browser-bound secret cookie + `Origin` check — a flow id in the form "is NOT the CSRF defence" (oauth.go:428-440) | Study only (no license) |
| [PrefectHQ/fastmcp](https://github.com/PrefectHQ/fastmcp) OAuthProxy | Python / Apache-2.0 | v4.1.6 (2026-11-03) | yes | Y / ? / Y | via proxy *[unverified]* | `AzureProvider`, OBO | Pluggable storage; Entra integration docs; CIMD "Verified domain" badge (oauth_proxy/ui.py:63-70) | Framework, not a binary; keys derived from the IdP client secret; DCR no TTL (#6036); upstream client synthesised with `allow_unregistered_redirect_uris=True` (proxy.py:1011-1028); consent remembered per browser for 365 d (consent.py:686) |
| [cloudflare/workers-oauth-provider](https://github.com/cloudflare/workers-oauth-provider) | TS / MIT | v1.2.4 (2026-10-22) | yes | Y / ? / app-supplied | no | no | Compact AS endpoint set; hashed tokens; per-grant encrypted props; documented KV atomicity limits; DCR 90 d KV TTL renewed at half-life (oauth-provider.ts:5437-5464) | Workers-only library; renewal race (#429); CIMD fetch follows redirects |
| [giantswarm/mcp-oauth](https://github.com/giantswarm/mcp-oauth) | Go library / Apache-2.0 | v1.10.2 (2026-11-05) | yes | ? / Y / ? | n/a | no | Provider plug-ins, lifecycle hooks, refresh-reuse detection, RFC 9068 JWTs | Library, not a binary |
| [stainless-api/mcp-front](https://github.com/stainless-api/mcp-front) | Go / Elastic-2.0 | — | no | ? | **process per user** | as IdP | Per-user stdio isolation; per-service `aud` | Not OSI; aggregator |
| [oauth2-proxy](https://github.com/oauth2-proxy/oauth2-proxy) | Go / MIT | v7.15.6 (2026-11-05) | yes | PR #3488 open | no | yes | Provider breadth; cookie vs Redis sessions | MCP support unmerged |

Also seen, not worth tracking: atrawog/mcp-oauth-gateway (dead), hyprmcp/mcp-gateway
(archived), mdspinali/mcp-entra-proxy (Entra relay with token passthrough and one shared
secret), nicknikolakakis/mcp-auth-gateway (per-user process, injects the IdP token — effectively
passthrough), AthenZ/mcp-oauth-proxy (Java, AWS-heavy), Shalimov04/mcp-airlock (JWT validation
only, no AS).

## 2. Gateways and platforms (overlap, not the wedge — ADR-0001)

| Project | Lang / license | Latest | MCP auth role | Entra | stdio | Learn from |
|---|---|---|---|---|---|---|
| [agentgateway](https://github.com/agentgateway/agentgateway) | Rust / Apache-2.0 | v1.7.0 (2026-10-27) | RS + IdP shims rewriting AS metadata; **no AS**: `/register` returns a mock carrying the shared IdP client_id (mcp/auth.rs:785-818); relays the IdP's `/token` (auth.rs:125, 720) | adapter: strips `resource` (AADSTS9010010), OIDC discovery instead of RFC 8414 | process per session; per request for 2026-07-28 | Entra quirk shims; stdio relay; no revision translation |
| [Pomerium](https://github.com/pomerium/pomerium) | Go / Apache-2.0 | v0.34.0 (2026-11-04) | full AS facade (PRM, DCR flag, CIMD, SSRF guard) | `pkg/identity/oidc/azure` | no | **Best AS-facade/CIMD reference** (`internal/mcp/DESIGN.md`); databroker storage. Gaps: `/token` only logs a `redirect_uri` mismatch (handler_token.go:212) and accepts PKCE plain/empty; loopback any-port for `localhost`/`127.0.0.1`, not `[::1]` (oauth21/validate_client.go:65-74, 102-104); no CIMD cache; no DCR TTL; default auth method `client_secret_basic`; CIMD allowlist required (empty = reject all) |
| [ToolHive](https://github.com/stacklok/toolhive) | Go / Apache-2.0 | v0.62.0 (2026-11-04) | embedded AS (fosite) — K8s operator | OBO CRD (enterprise build) | one shared container; id rewriting, init cache | Shared-stdio pitfalls (#5744); revision classifier; key rotation with fallback keys; DCR 24 h until first use, then 30 d renewed on exchange (storage/config.go:49-56); DCR rate limit + 10,000 cap → 503; consent shows name "(not verified)"; remembered consent re-checked against the user after the IdP callback (handlers/callback.go:248, 361-367) |
| [Obot](https://github.com/obot-platform/obot) | Go / MIT | v0.27.0 (2026-10-20) | full AS facade (DCR, CIMD, consent, `private_key_jwt`) | auth provider | containers | Redirect-URI validation; identity headers `X-Obot-User-*`; **only project shipping RFC 7592** client management (`GET/PUT/DELETE /oauth/register/{client}`, oauth/handler.go:79-81). Gap: `/token` does not re-check `redirect_uri` |
| [IBM ContextForge](https://github.com/IBM/mcp-context-forge) | Python / Apache-2.0 | v1.1.0 (2026-10-20) | RS per virtual server | SSO | shared bridge | Anti-patterns: opt-in passthrough, header→env on a shared process |
| [docker/mcp-gateway](https://github.com/docker/mcp-gateway) | Go / MIT | v0.44.3 (2026-10-26) | static bearer only | no | container per call / per session | Per-session isolation; per-client pool |
| [microsoft/mcp-gateway](https://github.com/microsoft/mcp-gateway) | C# / MIT | v1.0.0 | RS, Entra bearer | app roles `requiredRoles` | k8s *[unverified]* | Entra app-role gating |
| [theagentrouter/agent-router](https://github.com/theagentrouter/agent-router) (ex envoyproxy/ai-gateway) | Go / Apache-2.0 | v1.2.0 (2026-10-07) | RS (JWKS from RFC 8414) | generic JWT | no | Config shape |
| [Teleport](https://github.com/gravitational/teleport) | Go / AGPL-3.0 | v18.10.0 | `tsh mcp` certs, not OAuth | SSO | host agent | Glob tool allow-lists; audit events |
| Kong AI MCP OAuth2, Traefik Hub, Azure APIM, Cloudflare MCP portals, Solo Enterprise | commercial | — | RS | APIM native; Solo OBO paid | no | APIM/Kong: never forward `Authorization` by default; Traefik exempts `initialize` |

## 3. stdio bridges

| Project | Latest | Process model | Note |
|---|---|---|---|
| [supergateway](https://github.com/supercorp-ai/supergateway) | v4.2.1 (2026-10-24) | per request; `--stateful` per session | 4.1.0 moved off shared processes after cross-client leaks |
| [sparfenyuk/mcp-proxy](https://github.com/sparfenyuk/mcp-proxy) | v0.14.0 (2026-11-02) | shared, re-served | Routes progress per request; no sampling |
| [TBXark/mcp-proxy](https://github.com/TBXark/mcp-proxy) | v1.1.0 (2026-09-15) | shared, re-served | Drain stderr (pipe deadlock); respawn on ping |

## 4. Go building blocks

| Module | Latest | Use | Note |
|---|---|---|---|
| [modelcontextprotocol/go-sdk](https://github.com/modelcontextprotocol/go-sdk) | v1.8.0 (2026-09) | dependency | 2026-07-28 + older revisions; `CommandTransport`; RS-side auth helpers; `oauthex` metadata/DCR types; no stdio↔HTTP bridge, no AS |
| [coreos/go-oidc](https://github.com/coreos/go-oidc) v3 | v3.21.0 | dependency | IdP discovery + ID token verification |
| golang.org/x/oauth2 | v0.37.0 | dependency | IdP code exchange, PKCE helpers |
| [go-jose/go-jose](https://github.com/go-jose/go-jose) v4 | v4.1.9 | dependency | Sign proxy tokens, publish JWKS |
| [MSAL Go](https://github.com/AzureAD/microsoft-authentication-library-for-go) | v1.10.1 | dependency (F14 only) | `AcquireTokenOnBehalfOf` |
| [dex](https://github.com/dexidp/dex) | v2.46.1 | study | Connector interface; approval screen; storage + key rotation |
| [zitadel/oidc](https://github.com/zitadel/oidc) v3 | v3.51.17 | study | OP storage interface |
| [ory/fosite](https://github.com/ory/fosite) | v0.49.0 (2024-12) | study | Full AS toolkit; stale and heavy |
| modernc.org/sqlite / go.etcd.io/bbolt | v1.61.1 / v1.5.0 | candidate (F5) | Pure Go; bbolt is single-process |
| [code.dny.dev/ssrf](https://github.com/daenney/ssrf) | v0.3.0 | candidate (F17) | Dialer-hook SSRF guard; tiny, pin and review |

## 5. Test tooling

| Tool | Latest | Note |
|---|---|---|
| [modelcontextprotocol/conformance](https://github.com/modelcontextprotocol/conformance) | v0.1.16 | `server --requirements 2026-07-28`, `--suite auth`, `authorization` scenarios |
| [MCP Inspector](https://github.com/modelcontextprotocol/inspector) | 2.14.0 | Manual OAuth flow check |
| [oauth2-proxy/mockoidc](https://github.com/oauth2-proxy/mockoidc) | untagged | In-process fake IdP (no Entra `aud` profile) |
| [navikt/mock-oauth2-server](https://github.com/navikt/mock-oauth2-server) | 6.1.4 | Scriptable claims per issuer (Docker) |
| Keycloak 26.8.2 + testcontainers-go v0.45.0 | — | No official Keycloak module; community `stillya/testcontainers-keycloak` |
| [goreleaser](https://github.com/goreleaser/goreleaser) | v2.20.0 | Releases, SBOM, signing |

## 6. MCP clients — behaviour that constrains us

Details and sources: F6 client matrix (research notes, 2026-11-05).

| Client | Registration | Quirks |
|---|---|---|
| Claude.ai / Desktop | CIMD only if AS advertises the flag **and** `none`; else DCR | Registers a new client on every fresh connection (claude.com authentication.md:97); in chat, opens a new 2025-11-25 MCP session per tool call (claude-ai-mcp#583) |
| Claude Code | CIMD (port-less loopback `redirect_uris`), DCR, `--client-id` | Omits `resource` (claude-code#90497, closed not planned); re-registers on `invalid_client` (inferred from the minified Claude Code 2.1.318 binary) |
| VS Code | CIMD on the flag alone, DCR, prompt | 2025-11-25 only (ADR-0003); re-registers on `invalid_client` (extHostAuthentication.ts:872-875) |
| Cursor | DCR public client, static `CLIENT_ID` | CIMD *[unverified]*; refuses AS metadata without `code_challenge_methods_supported` |
| ChatGPT | CIMD preferred (`private_key_jwt` default), DCR | Requires RFC 9207 `iss` |
| MCP Inspector 2.14.0 | DCR `none`; CIMD only with a user-supplied URL | TS SDK 2.4.0: re-registers on `invalid_client` |
| Gemini CLI | DCR `none`, one loopback redirect | Sends `resource` plus a non-standard `audience` if configured; validates `iss`; no CIMD found |
| Windsurf / Devin | — | Insufficient docs ("OAuth for each" transport) |

## Where to look, per feature

| Feature | Study |
|---|---|
| F1 Upstream kinds ([ADR-0003](../../adr/0003-upstream-kinds.md)) | agentgateway `mcp/upstream/stdio.rs`; supergateway `--stateful`; ToolHive dispatcher (what sharing costs); docker clientpool |
| F2 Spec revisions ([ADR-0004](../../adr/0004-spec-revisions-pass-through.md)) | go-sdk `streamable.go`, `client.go` (discover → initialize fallback); ToolHive `pkg/mcp/revision.go`; agentgateway (no translation) |
| F3 Auth modes ([ADR-0005](../../adr/0005-auth-modes-broker-only.md)) / F4 Token model ([ADR-0006](../../adr/0006-token-model.md)) | babs (sealed tokens); Pomerium `internal/mcp/DESIGN.md`; workers-oauth-provider; giantswarm/mcp-oauth |
| F5 State & storage ([ADR-0007](../../adr/0007-state-and-storage.md)) | dex storage; Pomerium databroker; workers-oauth-provider storage schema; ToolHive key fallback files |
| F6 Client registration ([ADR-0008](../../adr/0008-client-registration.md)) / F8 Redirect URIs ([ADR-0009](../../adr/0009-redirect-uri-policy.md)) | Pomerium CIMD + SSRF; Obot redirect checks and RFC 7592; xnyzer toggles; ToolHive TTL + cap; babs optional CIMD host allowlist; workers-oauth-provider 90 d sliding TTL |
| F7 Consent | dex approval; Obot; lethek CSRF design; ToolHive post-callback user re-check; babs no-JS page |
| F9 IdP adapters | dex connectors; agentgateway `McpIDP` adapters |
| F10 Entra / F14 OBO | agentgateway Entra shim; FastMCP `AzureProvider`; MSAL Go; ToolHive OBO CRD |
| F11 Token validation / F12 Authz | go-sdk `auth`; agentgateway CEL rbac; Teleport globs; Microsoft app roles |
| F13 Identity propagation | Obot headers; Kong `claim_to_header`; APIM no-forward default |
| F17 Hardening | Pomerium SSRF guard; Kong 3.13 bypass fix; ContextForge/sigbit passthrough as anti-patterns |
| F19 Packaging | sigbit `-- <cmd>` wrapper; goreleaser |
| F21 Testing | conformance suite; mockoidc; mock-oauth2-server; Keycloak |
