# ADR-0005: Auth modes — broker only in v0.1

- Status: Accepted; amended by ADR-0027
- Date: 2026-11-05
- Issue: #4 (F3)

## Context

Comparable projects offer up to three modes: **off** (plain reverse proxy — ToolHive and FastMCP
default), **resource-server only** (validate IdP-issued tokens; protected resource metadata points
MCP clients at the IdP — agentgateway default, ToolHive CLI, FastMCP `RemoteAuthProvider`), and
**broker** (we are the authorization server facade — Pomerium, sigbit, FastMCP `OAuthProxy`).

Resource-server mode only works when the IdP lets MCP clients register themselves and honours
RFC 8707. Entra does not: "Microsoft Entra ID doesn't publish an RFC 7591 registration endpoint …
register the OAuth client statically instead" (Microsoft Learn, M365 Copilot DCR page, updated
2026-08-31); no Microsoft page documents CIMD support. Where the IdP does support it, today's
stack is fragile: Keycloak 26.8 marks its MCP, RFC 8707 and CIMD support Experimental; Auth0
needs a tenant toggle for `resource`; Claude Code does not send `resource`, so Keycloak issues
`aud=<client_id>` and strict resource servers reject it (anthropics/claude-code#90497, closed
not planned). Demand found (2026-11-05): no requests in sigbit or babs; the strongest signal,
oauth2-proxy #3167, asks for MCP auth in front of Keycloak — which a broker also meets.

## Decision

1. **v0.1 ships broker mode only.** It is the only mode that works for Entra with MCP clients
   that register themselves (ADR-0001's differentiator).
2. **No "off" mode.** An auth proxy with auth off is a foot-gun; tests use the fake IdP. _Amended by
   ADR-0027:_ a loopback-only `--insecure-no-auth` exists for trying the proxy out and for tests.
3. **Resource-server mode may be added later (v0.2+)**, kept additive by three v0.1 seams:
   inbound token validation behind one interface; `authorization_servers` in protected resource
   metadata is a parameter; 401 `scope=` and 403 `insufficient_scope` live in shared middleware.
4. **A missing `resource` parameter at our `/authorize` and `/token` means our own resource
   URL.** We front exactly one resource, and Claude Code omits it (#90497). This is a named
   client-quirk leniency with its own test.

## Considered options

- Broker + resource-server mode in v0.1 — rejected for now: no demand from our segment, Entra
  cannot use it, ~500–800 LOC plus a compatibility-matrix axis for a solo maintainer.
- off / resource-server / broker — rejected: "off" contradicts the product.
