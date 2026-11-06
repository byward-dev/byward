# ADR-0001: Scope — auth-only proxy, public OSS, Entra as first-class

- Status: Accepted
- Date: 2026-11-05

## Context

MCP servers commonly hand-roll OAuth in
front of Entra ID, with different designs and different gaps (no consent step, no protected
resource metadata, tokens without expiry, single-replica state). Research (see
`docs/research.md`) found no maintained single-binary Go proxy that combines an MCP-compliant
authorization-server facade (DCR + CIMD + consent), Entra adaptation, stdio bridging, and
support for both the 2025-11-25 and 2026-07-28 spec revisions.

Existing options are either full gateways (agentgateway, Pomerium, ToolHive, Kong, Traefik
Hub), resource-server-only (Envoy Agent Router, Azure APIM, Kong), language-bound libraries
(FastMCP OAuthProxy), or stalled (sigbit/mcp-auth-proxy, last push 2026-05).

## Decision

1. **Audience: public open-source product** for third parties fronting arbitrary MCP servers
   with arbitrary IdPs — not just an internal tool.
2. **Wedge: the smallest auth-only proxy.** One Go binary, no external dependencies,
   env/flag configuration, one command to put any MCP server (stdio or HTTP) behind any OIDC
   IdP.
3. **Differentiator: best-in-class Microsoft Entra ID support**, including its quirks (GUID
   `aud`, v1/v2 issuers, no DCR/CIMD, exact App ID URI matching for `resource`) and
   On-Behalf-Of to downstream APIs.
4. **Permanent non-goals:** routing/aggregation of multiple upstreams, a policy language,
   rate limiting of MCP traffic, credential vaulting for arbitrary third-party SaaS. These belong
   to gateways.

## Consequences

- Every feature request is tested against "is this auth?" — if not, it is out of scope.
- Spec-correctness (MCP authorization, security best practices) is a feature, not a cost.
- Entra must have an integration test lane against a real tenant or a faithful mock.
- Acceptance is defined by spec conformance and the client compatibility matrix, not by any single consumer.

## Alternatives considered

- **Internal tool only** — rejected: the goal is a public product.
- **Full gateway (tool authz, audit, aggregation)** — rejected: crowded, unsustainable solo.
- **Per-user credential vaulting as the wedge** — rejected: Pomerium/ToolHive/Arcade/Composio
  already compete there.
- **Adopt agentgateway instead of building** — rejected for the wedge: it is a full gateway
  (YAML, CEL, multiplexing) in Rust; the gap is a minimal Go auth-only binary.

## Amendment 2026-11-06 (rate limiting)

The rate-limiting non-goal in Decision 4 means rate limiting of MCP traffic, which is a gateway
concern. The proxy's own OAuth endpoints (`/authorize`, `/consent`, `/callback/<idp>`, `/token`,
`/register`, `/revoke`) are rate-limited per client address as abuse protection
([ADR-0018](0018-hardening.md) §8). That protects the authorization server itself and is part of
the auth scope.
