# Quality lenses for feature grilling

Checklist for every feature (F1–F22) during `/grill-with-docs`. Terms follow `CONTEXT.md`.
Sources checked 2026-11-05; `[unverified]` = no primary source.

## How to use it

Name the feature's **primary persona** and its job: "When I …, I want …, so I can …". Write
measurable answers as quality scenarios: context / trigger / acceptance criteria (arc42 §10).

### Research procedure (per feature question)

Look at every question from all of these angles before asking for a decision. Independent
angles can be researched in parallel (one helper or agent per angle).

1. **Standards.** Verify every claim the recommendation rests on against a primary source: MCP
   spec and security best practices, RFCs and drafts, OWASP ASVS, WCAG, browser specs. Quote it
   with a link or `file:line`. Note where sources conflict and which one you follow.
2. **Competitors.** Build a table from source at a named commit: what each comparable project
   (`docs/research/reference-projects.md`) does for this question, including their bugs and issues.
3. **What competitors missed.** Options none of them ship: other standards, designs, tools, and
   product/UX/operational ideas. Evaluate those too — the best answer may be one nobody ships yet.
4. **MCP clients.** How each client (Claude, Claude Code, VS Code, Cursor, ChatGPT, MCP Inspector,
   Gemini CLI, …) actually behaves for this question, from source, binaries or official docs —
   not from what the spec says they should do.
5. **IdPs.** How the IdPs behind us (Entra first, then Keycloak, Okta, Google, Auth0) behave, from
   their official docs — including what operators and users see there.
6. **Lenses and personas.** Walk every lens in this document (start with those the
   [feature × lens map](#feature--lens-map) marks) and every persona, **against the final design**,
   not the first draft. Answer each question or mark it `n/a` with a reason; list each gap and
   the change it requires.
7. **Confidence.** State high / medium / low, what remains unverified, and what evidence would
   raise it. Settle cheap unknowns before asking; if nothing more could change the decision, say so.
8. **Record.** Write the decision as an ADR. Lens answers, budgets and matrix cells go in
   **Consequences**; note deliberate deviations from a standard and why. Update `CONTEXT.md` for
   any resolved term.

## Personas

| ID | Persona | Success looks like |
|---|---|---|
| P1 | Solo **operator** on a VM or Docker host wrapping a stdio **upstream**; knows Go/Node, not OAuth | Working connector in < 15 min; errors name the fix |
| P2 | Platform **operator** in an Entra tenant, k8s behind ingress | Entra how-to matches the portal; startup check validates tenant, app ID, redirect URI; HA |
| P3 | Security reviewer | One-page security posture; secure defaults; insecure modes named and logged; signed releases + SBOM |
| P4 **User** at **consent**, non-technical | Knows who is asking within 3 s; one click; errors say what to tell the operator |
| P5 MCP-server author | Stable identity contract to the upstream, no token passthrough |
| P6 Contributor (human or agent) | `mise run check` passes locally; ADRs answer "why"; fakes in `internal/testutil` |

## Lenses

Q42 tags (detail: ISO/IEC 25010:2023), then project-specific groups.

### #secure

- ASVS 5.0.0: which `v5.0.0-x.y.z` requirements and level? (V6–V14, V16 apply.)
- RFC 9700: PKCE `S256` always; `iss` (RFC 9207); refresh rotation with reuse detection; `resource` audience (RFC 8707); no open redirector?
- RFC 8725: `alg` pinned per key; `typ` separates **IdP tokens** from **proxy tokens**; `kid` only from our JWKS, never `jku`/`x5u`?
- MCP: no token passthrough by construction; SSRF guard on client-supplied URLs; authorization URL from config only; scope minimization?
- MCP Top 10 / Agentic: can a token reach logs or the upstream, a grant widen silently, or an agent gain more than the user has?
- STRIDE on a data-flow diagram, one test per threat.

Sources: [ASVS 5.0.0 (2025-05-30)](https://owasp.org/www-project-application-security-verification-standard/) · [RFC 9700](https://www.rfc-editor.org/rfc/rfc9700) · [RFC 8725](https://www.rfc-editor.org/rfc/rfc8725) ([bis-10, 2026-08-31](https://datatracker.ietf.org/doc/draft-ietf-oauth-rfc8725bis/)) · [MCP security considerations](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization/security-considerations), [best practices](https://modelcontextprotocol.io/docs/2026-07-28/tutorials/security/security_best_practices) (2026-07-28) · [OWASP MCP Top 10 (2025, beta)](https://owasp.org/www-project-mcp-top-10/) · [Agentic Top 10 2026 [unverified date]](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/) · [Threat Modeling Manifesto](https://www.threatmodelingmanifesto.org/)

### #safe

- IdP, JWKS, store or upstream unreachable: do we deny? (Fail-open is the worst outcome.)
- Does hazardous config (HTTP issuer, wildcard redirect, empty audience) refuse to start or warn loudly?
- Is zero-config the secure path, with every relaxation a named flag logged at each startup?
- Can a partial config end up silently unauthenticated?

Sources: ISO/IEC 25010:2023 Safety [secondary] · [CISA Secure by Design [version unverified]](https://www.cisa.gov/securebydesign) · [Pit of success](https://blog.codinghorror.com/falling-into-the-pit-of-success/)

### #reliable

- What does the **MCP client** get when the IdP is slow, the upstream is down or a stdio child crashes (401 / 503 / JSON-RPC error)?
- Does every outbound call carry a deadline from the inbound one? Are retries bounded and jittered?
- Idempotent under client retries (double `/token`, refresh reuse)? Does state survive a restart?

Sources: [Google SRE book](https://sre.google/sre-book/)

### #efficient

- Cost per session/user: memory, FDs, goroutines, processes (stdio: 120–240 MB, ADR-0003)?
- Queue limits; what is shed first; ms added per MCP request?
- Works with N replicas, no sticky sessions?

Sources: [SRE overload](https://sre.google/sre-book/handling-overload/) · [RED](https://grafana.com/blog/2018/08/02/the-red-method-how-to-instrument-your-services/) / [USE](https://www.brendangregg.com/usemethod.html)

### #operable

- Env/flag config validated at startup; `*_FILE` for secrets; stdio child inherits no proxy secrets?
- SIGTERM: drain, stop children, close SSE explicitly, within budget? Readiness = can serve; liveness without IdP?
- Golden signals / RED per endpoint, USE per resource; OTel semconv pinned (MCP attributes are Development); `traceparent` forwarded in `_meta` (SEP-414)?
- Structured logs with a redaction test (tokens, codes, verifiers, URLs with `code`/`state`); admin tasks as subcommands?

Sources: [Twelve-Factor](https://12factor.net/) · [K8s probes v1.37](https://kubernetes.io/docs/concepts/configuration/liveness-readiness-startup-probes/) · [OTel semconv v1.45.0](https://opentelemetry.io/docs/specs/semconv/)

### #maintainable

- Fits AGENTS.md layout (`internal/`, one adapter package per interface)?
- Testable without Docker via `internal/testutil` fakes and an injected clock?
- New dependency: version, maintenance, Apache-2.0-compatible license, govulncheck clean? Builds on the last two Go releases?
- Concepts and code added versus a solo-maintainer budget?

Sources: [Go release policy](https://go.dev/doc/devel/release) · [govulncheck v1.9.0](https://go.dev/doc/security/vuln/) · ADR-0002

### #flexible

- Linux/macOS/Windows, container and bare metal (spawn, signals, paths)? Embedded store and Postgres?
- Reversibility: standard tokens and metadata only (RFC 9728/8414, JWT)? Can the operator swap the IdP or remove the proxy without re-registering clients or rewriting upstreams?

Sources: ISO/IEC 25010:2023 Flexibility · [Twelve-Factor X](https://12factor.net/dev-prod-parity)

### #usable

- Consent: who is asking (client name, redirect host), for what (upstream, scopes) in 3 s; Allow and Deny equally visible?
- Errors: near the cause, specific ("registered X, sent Y"), a remedy, a support code, a reference link?
- CLI: `--help` with examples; exit code per failure class; startup line shows effective config (redacted); ≤ 5 required settings?
- Docs per Diátaxis: tutorial, how-to (Entra, Keycloak, ingress), reference, explanation?
- WCAG 2.2 on consent/error pages: contrast, focus, 24 px targets, `lang`, real `<form>`, no proxy CAPTCHA/password (3.3.8)?

Sources: [Nielsen heuristics](https://www.nngroup.com/articles/ten-usability-heuristics/) · [NN/g error messages](https://www.nngroup.com/articles/error-message-guidelines/) · [clig.dev](https://clig.dev/) · [Diátaxis](https://diataxis.fr/) · [WCAG 2.2](https://www.w3.org/TR/WCAG22/) · Krug, *Don't Make Me Think*, 3rd ed.

### #suitable

- Is this auth (ADR-0001)? Does a gateway already do it, and does that matter for the wedge?
- Does "one command to protected" stay true, with no external dependency?
- Which spec MUST/SHOULD clauses does it implement, and which test proves each?

### Trust and user agency

- Any outbound call the operator did not configure (telemetry, update check)? Default: none.
- Does consent name client, redirect host, scopes and upstream in plain words, marking CIMD names unverified?
- Can a grant be revoked, cutting refresh tokens immediately?

Sources: ISO/IEC 25019:2023 [secondary]

### Upgrade and config-as-API stability

- New public surface (flags, env, metrics, log fields, paths, error codes)? Hyrum's Law: all of it gets depended on.
- Rename or removal: deprecation window and warning? Store schema migrates forward and rolls back one version?
- Strict parsing by default; each leniency tied to a named client quirk with a test (RFC 9413 §5.1)? Policy for dropping a spec revision?

Sources: [SemVer](https://semver.org/) · [Hyrum's Law](https://www.hyrumslaw.com/) · [RFC 9413](https://www.rfc-editor.org/rfc/rfc9413)

### Privacy, compliance and supply chain

- Which personal data (`sub`, email, IP) is stored or logged, and why? Pseudonymous `sub` by default? Retention and per-user deletion?
- Audit events for login, consent, deny, revoke, registration, key rotation, without secrets?
- Crypto only from Go stdlib / `x/crypto` (no EAR notification [secondary])? NOTICE and license check in CI?
- Release: SLSA provenance, cosign signature, SBOM, reproducible (`-trimpath`, pinned toolchain), Scorecard green?

Sources: [GDPR Art. 5, 25](https://eur-lex.europa.eu/eli/reg/2016/679/oj) · [SLSA v1.2](https://slsa.dev/spec/) · [Scorecard v5.6.0](https://scorecard.dev/) · [CycloneDX 1.7](https://cyclonedx.org/specification/overview/) / [SPDX 3.0](https://spdx.dev/use/specifications/) · cosign v3.1.4

### Sustainability and governance

- Surface only the maintainer understands? Covered by an ADR plus tests? Single-owner CI dependency (real Entra tenant)?
- On the roadmap or an explicit non-goal?

Sources: [OpenSSF Best Practices (Silver)](https://www.bestpractices.dev/en/criteria/1) · [CHAOSS Contributor Absence Factor](https://chaoss.community/kb/metric-contributor-absence-factor/)

### Time and clocks

- Skew leeway bounded (RFC 7519 §4.1.4: "usually no more than a few minutes")?
- Every TTL (code, access, refresh, consent, DCR client) explicit with a default? `time.Now` injected? Behaviour at key rollover and at the expiry edge?

### Abuse resistance of our endpoints

- What state does an anonymous request create (DCR, pending authorization), and when does it expire? Caps on clients, requests, sessions?
- Bounded bodies, CIMD size and hops, JWKS refresh rate; `http.Server` timeouts set (Go defaults are none)?
- Auth-server hygiene, not MCP traffic rate limiting (ADR-0001 non-goal). RFC 7591 §5 on DCR throttling: [unverified].

### Recoverability

- Signing key lost or rotated: what breaks, how do clients recover; verify-only keys kept?
- Store: hot backup, point-in-time restore (replay of revoked grants), empty-store restart, corruption detected at startup?

## Invariants

1. No token passthrough to the upstream.
2. Never log tokens, secrets, authorization codes or PKCE verifiers.
3. Named IdP endpoints come from config, never overridable.
4. Client-supplied URLs are fetched only through the SSRF guard.
5. Per-client consent before the IdP redirect.
6. Audience validated; authorization responses carry `iss`.
7. Proxy tokens carry `exp`, `aud` = our resource, `iss` = us, a `kid` in our JWKS; never IdP tokens.
8. The IdP refresh token never leaves the **broker** and is encrypted at rest.
9. Authorization codes are single-use and short-lived; `/token` re-checks `client_id`, `redirect_uri`, PKCE.
10. Exact redirect matching; only the loopback port may vary.
11. Keys come from the operator; never derived from the IdP client secret; never ephemeral across replicas; rotation keeps verify-only keys.
12. Every relaxation is an explicit flag, logged at startup.
13. Legacy MCP sessions are bound to the user (ADR-0004); an upstream process never serves more than one user (ADR-0003).
14. Size, time and count limits on registration, CIMD and the store.
15. Errors never echo secrets or upstream internals.
16. The reverse proxy uses `httputil.ReverseProxy.Rewrite`, never `Director`; identity, forwarding,
    authorization and downstream-token headers are stripped before ours are set (ADR-0016, ADR-0018).
17. The MCP endpoint checks `Origin` (403) and `Host` (421) before authentication; the default bind is
    `127.0.0.1` (ADR-0018).
18. Every `http.Server` timeout and `MaxHeaderBytes` is set; builds use the latest Go patch release;
    `govulncheck` is green (ADR-0018).
19. The proxy never sends its own IdP credential on a caller's behalf; app-only tokens are accepted
    only with a pinned issuer and audience, `idtyp=app` and a required app role (ADR-0022).

## Known pitfalls

- Mix-up: no `iss` in the authorization response.
- Confused deputy: static **IdP app** + DCR + consent cookie, no per-client consent.
- Open redirect: prefix matching, or redirecting on an error path.
- Keys derived from the IdP client secret.
- Random per-process keys (restarts break logins; replicas disagree).
- No `exp`; access = refresh; IdP refresh token wrapped in the client's token.
- One shared DCR `client_id`, no binding at `/token`.
- Upstream skipping `aud`; opt-in passthrough.
- Hard-coded email allowlists.
- CIMD SSRF: following redirects, DNS rebinding, unbounded body, caching errors.
- `localhost` vs `127.0.0.1` loopback mismatch.
- One stdio process shared across users.
- Refresh rotation without reuse detection.
- Logging full URLs (leaks `code`/`state`).

## Default budgets

Decided values cite their ADR; everything else is **proposed — decided per feature**.

| Budget | Default | Status |
|---|---|---|
| stdio idle timeout | 30 min | **Decided**, ADR-0003 |
| stdio process caps | per-upstream and per-user, LRU eviction of idle | **Decided** mechanism (ADR-0003); values proposed |
| stdio spawn / kill | 30 s spawn timeout; kill 5 s after SIGTERM | Proposed |
| Discovery, registration, token | < 10 s, p99 < 2 s | Proposed (Claude times out at 10 s) |
| Refresh | < 30 s, p99 < 5 s | Proposed (Claude: 30 s) |
| Outbound IdP / CIMD fetch | 5 s, 2 jittered retries; CIMD ≤ 5 KB, metadata ≤ 64 KB | Proposed (CIMD -03 §10.11: 5 KB) |
| `http.Server` | ReadHeaderTimeout 10 s, IdleTimeout 120 s, per-request write deadlines for SSE | Proposed |
| Request body | 4 MB MCP route, 64 KB OAuth endpoints | Proposed |
| Shutdown | ≤ 25 s (K8s grace 30 s) | Proposed |
| Authorization code / consent state | 60 s single-use / 10 min | Proposed |

## Compatibility matrix

Each feature names the cells it touches and adds a test per cell; untested cells are "best effort".

| Axis | Values |
|---|---|
| MCP client | Claude.ai/Desktop, Claude Code, VS Code, Cursor, ChatGPT, MCP Inspector, Gemini CLI |
| Client registration | static, CIMD, DCR |
| Spec revision | 2025-11-25, 2026-07-28 |
| IdP | Entra (single tenant, organizations), Keycloak, Okta, Auth0, Google |
| Upstream | HTTP, stdio |
| Platform | linux/amd64+arm64, darwin, windows |

CI runs the MCP conformance suite (`--suite auth`) on both revisions with the fake IdP's entra
and keycloak profiles; MCP clients get manual or recorded smoke tests.

## Feature × lens map

| # | Feature | Lenses |
|---|---|---|
| F1 | Upstream kinds | #efficient, #reliable, #secure, #suitable |
| F2 | Spec revision support | compatibility, upgrade, #suitable |
| F3 | Auth modes | #safe, #secure, #flexible, #suitable |
| F4 | Token model | #secure, time, recoverability, trust |
| F5 | State & storage | recoverability, #reliable, #efficient, abuse, upgrade |
| F6 | Client registration | #secure, abuse, trust, compatibility |
| F7 | Consent screen | #usable, trust, #secure, abuse |
| F8 | Redirect URI policy | #secure, compatibility, abuse |
| F9 | IdP adapters | #maintainable, #flexible, compatibility |
| F10 | Entra specifics | compatibility, recoverability, #usable |
| F11 | Token validation | #secure, time, #safe, #efficient |
| F12 | Authorization rules | #safe, #suitable, #secure |
| F13 | Identity propagation | #secure, #flexible, upgrade |
| F14 | Delegation to downstream APIs | #secure, time, #suitable |
| F15 | Machine-to-machine | #secure, time, #suitable |
| F16 | Discovery & errors | #usable, #suitable, trust, abuse |
| F17 | Security hardening | #safe, #secure, abuse |
| F18 | Configuration UX | #usable, #safe, upgrade |
| F19 | Packaging & deployment | #operable, #flexible, privacy & supply chain, recoverability |
| F20 | Observability | #operable, privacy & supply chain, trust |
| F21 | Testing strategy | #maintainable, time, compatibility, sustainability |
| F22 | Project & governance | sustainability, privacy & supply chain, upgrade |

## Out of scope

- MCP traffic rate limiting — ADR-0001 non-goal; our own endpoints are covered by "abuse resistance".
- Certification (SOC 2, ISO 27001) and data-residency guarantees — the operator's job; we emit evidence.
- Environmental sustainability — negligible for a small binary; covered by #efficient.
- Health/life risk (ISO/IEC 25019) — not a safety-critical domain.
- CNCF incubation — needs adopters and several maintainers; revisit later.
- Export-control notification — not needed with standard cryptography only.
- LLM content risks (prompt injection, tool poisoning) — the proxy never interprets MCP payloads.
- Internationalization — English-only pages unless F7/F16 decide otherwise.
