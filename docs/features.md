# Feature backlog

> Index only. Each row becomes a GitHub Issue (milestone v0.1 / later); details and
> discussion live there, decisions in `docs/adr/` (ADR-0002).

Each feature gets its own grilling session; outcome lands in an ADR. Scope filter: ADR-0001
(auth-only, Entra first-class). Status: `open` = not grilled, `proposed` = recommendation made
but not accepted, `decided` = ADR exists.

Suggested grill order follows dependencies (earlier rows constrain later ones).

| # | Feature | Key questions | Depends on | Status |
|---|---|---|---|---|
| F1 | **Upstream kinds** | HTTP reverse proxy; stdio shared process; stdio per-user process; legacy SSE? | — | proposed: v1 = HTTP + shared stdio; per-user stdio → v2; no SSE |
| F2 | **Spec revision support** | 2025-11-25 (sessions) and 2026-07-28 (stateless, `Mcp-Method`/`Mcp-Name`) side by side? Translation between them when client and upstream differ? | F1 | open |
| F3 | **Auth modes** | off / resource-server only / broker AS — three-mode split? | — | open |
| F4 | **Token model** | Relay IdP tokens vs mint own (audience-bound, revocable, hides IdP refresh token); JWT format; lifetimes | F3 | open |
| F5 | **State & storage** | Stateless (signed/encrypted) vs embedded store (SQLite/Bolt) vs pluggable; key management & rotation; multi-replica | F4 | open |
| F6 | **Client registration** | DCR (deprecated but needed), CIMD with SSRF guards, static pre-registered clients; `none` + `private_key_jwt` auth | F3, F5 | open |
| F7 | **Consent screen** | Per-client consent (spec MUST); UI, CSRF, `__Host-` cookie, approval registry | F5, F6 | open |
| F8 | **Redirect URI policy** | Loopback any-port (RFC 8252), exact HTTPS match, known-client presets (Claude, VS Code, Cursor, ChatGPT) | F6 | open |
| F9 | **IdP adapters** | Generic OIDC + presets (Entra, Google, Keycloak, Okta, Auth0, GitHub?); non-OIDC GitHub in or out | F3 | open |
| F10 | **Entra specifics** | v1/v2 issuer, GUID `aud`, App ID URI `resource`, `.default` scopes, Graph-token trap, multi-tenant, CA claim challenges | F9 | open |
| F11 | **Token validation** | JWKS caching, `aud`/`iss`/`exp`, opaque token introspection (RFC 7662), clock skew | F4, F9 | open |
| F12 | **Authorization rules** | Claim/group/role requirements; scopes + 403 `insufficient_scope` step-up; simple tool allow/deny list (no policy language) | F11 | open |
| F13 | **Identity propagation** | Signed JWT assertion header vs `X-Forwarded-*`; what stdio upstreams get (nothing / env) | F1, F4 | open |
| F14 | **Delegation to downstream APIs** | Entra OBO, RFC 8693 token exchange with `act`; proxy-side vs upstream-side | F10, F13 | open |
| F15 | **Machine-to-machine** | Client credentials extension; Enterprise-Managed Authorization (ID-JAG) | F3, F11 | open |
| F16 | **Discovery & errors** | PRM (path-inserted + root), AS metadata (RFC 8414 + OIDC), RFC 9207 `iss`, `WWW-Authenticate` shapes | F3 | open |
| F17 | **Security hardening** | No token passthrough, SSRF guards, session binding `user:session`, mix-up, Origin check, response timeouts (Claude 10 s/30 s) | all | open |
| F18 | **Configuration UX** | Env vars vs flags vs file; presets; validation at startup; `doctor`/self-check command | F9 | open |
| F19 | **Packaging & deployment** | Binary releases (goreleaser), container image, sidecar vs wrapper (`-- <cmd>`), ACME/TLS or terminate upstream | F1 | open |
| F20 | **Observability** | Structured logs, audit events (login, consent, scope elevation), OTel tracing, health/readiness | — | open |
| F21 | **Testing strategy** | Keycloak testcontainer, fake OIDC, Entra lane, client conformance (Claude/VS Code/Inspector) | F9, F10 | open |
| F22 | **Project & governance** | License (Apache-2.0 vs MIT), versioning/stability promise, docs site, contribution policy | — | open |
