# Reference projects (2026-11-05)

Competitors and projects to learn from while grilling F1–F22. Repo metadata checked via
GitHub GraphQL on the date above; behaviour notes come from reading shallow clones or official
docs. *[unverified]* = no primary source read. Re-check versions before relying on them.

## 1. Direct competitors — auth proxies with an AS facade

| Project | Lang / license | Latest | Maintained | DCR / CIMD / consent | stdio | Entra | Learn from | Weakness |
|---|---|---|---|---|---|---|---|---|
| [babs/mcp-auth-proxy](https://github.com/babs/mcp-auth-proxy) | Go / Apache-2.0 | v2.4.0 (2026-10-28) | yes | Y / Y / Y | no | tested (generic OIDC) | Stateless AEAD-sealed tokens carrying IdP tokens; refresh-reuse detection; key-rotation runbook; CIMD host allowlist; opt-in IdP token forwarding for OBO | No stdio — **closest competitor** |
| [sigbit/mcp-auth-proxy](https://github.com/sigbit/mcp-auth-proxy) | Go / MIT | v2.10.2 (2026-05-08) | slowing | Y / ? / ? | shared process (`-- <cmd>`) | generic OIDC | Wrapper UX; client-quirk matrix; claim→header mapping | Frozen tool catalog; child exit kills proxy; opt-in token passthrough |
| [xnyzer/mcp-oauth-gateway](https://github.com/xnyzer/mcp-oauth-gateway) | Go / Apache-2.0 | v0.5.0 (2026-10-12) | yes | Y (toggle) / Y (CIMD-first) / Y | yes | no | `CIMD_ENABLED`/`DCR_ENABLED` toggles; JWT key rotation | Default login is an operator password; IdP optional |
| [lethek/mcp-oauth-proxy](https://github.com/lethek/mcp-oauth-proxy) | Go / **no license** | — | yes | Y / Y / Y | no | no | Per-target RFC 9728 docs; tokens bound to one target; "consent makes DCR safe" write-up; upstream credential modes `provider_token`/`static`/`per_user` | Study only (no license) |
| [PrefectHQ/fastmcp](https://github.com/PrefectHQ/fastmcp) OAuthProxy | Python / Apache-2.0 | v4.1.6 (2026-11-03) | yes | Y / ? / Y | via proxy *[unverified]* | `AzureProvider`, OBO | Pluggable storage; Entra integration docs | Framework, not a binary; keys derived from the IdP client secret |
| [cloudflare/workers-oauth-provider](https://github.com/cloudflare/workers-oauth-provider) | TS / MIT | v1.2.4 (2026-10-22) | yes | Y / ? / app-supplied | no | no | Compact AS endpoint set; hashed tokens; per-grant encrypted props; documented KV atomicity limits | Workers-only library |
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
| [agentgateway](https://github.com/agentgateway/agentgateway) | Rust / Apache-2.0 | v1.7.0 (2026-10-27) | RS + IdP shims rewriting AS metadata | adapter: strips `resource` (AADSTS9010010), OIDC discovery instead of RFC 8414 | process per session; per request for 2026-07-28 | Entra quirk shims; stdio relay; no revision translation |
| [Pomerium](https://github.com/pomerium/pomerium) | Go / Apache-2.0 | v0.34.0 (2026-11-04) | full AS facade (PRM, DCR flag, CIMD, SSRF guard) | `pkg/identity/oidc/azure` | no | **Best AS-facade/CIMD reference** (`internal/mcp/DESIGN.md`); databroker storage |
| [ToolHive](https://github.com/stacklok/toolhive) | Go / Apache-2.0 | v0.62.0 (2026-11-04) | embedded AS (fosite) — K8s operator | OBO CRD (enterprise build) | one shared container; id rewriting, init cache | Shared-stdio pitfalls (#5744); revision classifier; key rotation with fallback keys |
| [Obot](https://github.com/obot-platform/obot) | Go / MIT | v0.27.0 (2026-10-20) | full AS facade (DCR, CIMD, consent, `private_key_jwt`) | auth provider | containers | Redirect-URI validation; identity headers `X-Obot-User-*` |
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

## Where to look, per feature

| Feature | Study |
|---|---|
| F1 Upstream kinds | agentgateway `mcp/upstream/stdio.rs`; supergateway `--stateful`; ToolHive dispatcher (what sharing costs); docker clientpool |
| F2 Spec revisions | go-sdk `streamable.go`, `client.go` (discover → initialize fallback); ToolHive `pkg/mcp/revision.go`; agentgateway (no translation) |
| F3 Auth modes / F4 Token model | babs (sealed tokens); Pomerium `internal/mcp/DESIGN.md`; workers-oauth-provider; giantswarm/mcp-oauth |
| F5 State & storage | dex storage; Pomerium databroker; workers-oauth-provider storage schema; ToolHive key fallback files |
| F6 Client registration / F8 Redirect URIs | Pomerium CIMD + SSRF; Obot redirect checks; xnyzer toggles; lethek consent write-up |
| F7 Consent | dex approval; Obot; lethek |
| F9 IdP adapters | dex connectors; agentgateway `McpIDP` adapters |
| F10 Entra / F14 OBO | agentgateway Entra shim; FastMCP `AzureProvider`; MSAL Go; ToolHive OBO CRD |
| F11 Token validation / F12 Authz | go-sdk `auth`; agentgateway CEL rbac; Teleport globs; Microsoft app roles |
| F13 Identity propagation | Obot headers; Kong `claim_to_header`; APIM no-forward default |
| F17 Hardening | Pomerium SSRF guard; Kong 3.13 bypass fix; ContextForge/sigbit passthrough as anti-patterns |
| F19 Packaging | sigbit `-- <cmd>` wrapper; goreleaser |
| F21 Testing | conformance suite; mockoidc; mock-oauth2-server; Keycloak |
