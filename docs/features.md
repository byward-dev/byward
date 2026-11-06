# Feature backlog

> Index only. Each row is a GitHub Issue in milestone
> [v0.1](https://github.com/corker/mcp-authproxy/milestone/1); key questions, dependencies and
> discussion live there, decisions in `docs/adr/` (ADR-0002).

Each feature gets its own grilling session; the outcome lands in an ADR, which is linked from
the issue and from the Status column below. Scope filter: ADR-0001 (auth-only, Entra
first-class). Status: `open` = not grilled, `proposed` = recommendation made but not accepted,
`decided` = ADR exists.

Suggested grill order follows dependencies (earlier rows constrain later ones).

| # | Issue | Feature | Area | Depends on | Status |
|---|---|---|---|---|---|
| F1 | [#2](https://github.com/corker/mcp-authproxy/issues/2) | Upstream kinds | `area:upstream` | — | decided: [ADR-0003](adr/0003-upstream-kinds.md) |
| F2 | [#3](https://github.com/corker/mcp-authproxy/issues/3) | Spec revision support | `area:upstream` | [F1](https://github.com/corker/mcp-authproxy/issues/2) | decided: [ADR-0004](adr/0004-spec-revisions-pass-through.md) |
| F3 | [#4](https://github.com/corker/mcp-authproxy/issues/4) | Auth modes | `area:broker` | — | decided: [ADR-0005](adr/0005-auth-modes-broker-only.md) |
| F4 | [#5](https://github.com/corker/mcp-authproxy/issues/5) | Token model | `area:broker` | [F3](https://github.com/corker/mcp-authproxy/issues/4) | decided: [ADR-0006](adr/0006-token-model.md) |
| F5 | [#6](https://github.com/corker/mcp-authproxy/issues/6) | State & storage | `area:storage` | [F4](https://github.com/corker/mcp-authproxy/issues/5) | decided: [ADR-0007](adr/0007-state-and-storage.md) |
| F6 | [#7](https://github.com/corker/mcp-authproxy/issues/7) | Client registration | `area:broker` | [F3](https://github.com/corker/mcp-authproxy/issues/4), [F5](https://github.com/corker/mcp-authproxy/issues/6) | decided: [ADR-0008](adr/0008-client-registration.md) |
| F7 | [#8](https://github.com/corker/mcp-authproxy/issues/8) | Consent screen | `area:broker` | [F5](https://github.com/corker/mcp-authproxy/issues/6), [F6](https://github.com/corker/mcp-authproxy/issues/7) | decided: [ADR-0010](adr/0010-consent-screen.md) |
| F8 | [#9](https://github.com/corker/mcp-authproxy/issues/9) | Redirect URI policy | `area:broker` | [F6](https://github.com/corker/mcp-authproxy/issues/7) | decided: [ADR-0009](adr/0009-redirect-uri-policy.md) |
| F9 | [#10](https://github.com/corker/mcp-authproxy/issues/10) | IdP adapters | `area:idp` | [F3](https://github.com/corker/mcp-authproxy/issues/4) | decided: [ADR-0011](adr/0011-idp-adapters.md), amended by [ADR-0026](adr/0026-idp-adapters-go-jose-only.md) |
| F10 | [#11](https://github.com/corker/mcp-authproxy/issues/11) | Entra specifics | `area:idp` | [F9](https://github.com/corker/mcp-authproxy/issues/10) | decided: [ADR-0012](adr/0012-entra-specifics.md) |
| F11 | [#12](https://github.com/corker/mcp-authproxy/issues/12) | Token validation | `area:authz` | [F4](https://github.com/corker/mcp-authproxy/issues/5), [F9](https://github.com/corker/mcp-authproxy/issues/10) | decided: [ADR-0014](adr/0014-token-validation.md) |
| F12 | [#13](https://github.com/corker/mcp-authproxy/issues/13) | Authorization rules | `area:authz` | [F11](https://github.com/corker/mcp-authproxy/issues/12) | decided: [ADR-0015](adr/0015-access-gate.md) |
| F13 | [#14](https://github.com/corker/mcp-authproxy/issues/14) | Identity propagation | `area:upstream` | [F1](https://github.com/corker/mcp-authproxy/issues/2), [F4](https://github.com/corker/mcp-authproxy/issues/5) | decided: [ADR-0016](adr/0016-identity-propagation.md) |
| F14 | [#15](https://github.com/corker/mcp-authproxy/issues/15) | Delegation to downstream APIs | `area:idp` | [F10](https://github.com/corker/mcp-authproxy/issues/11), [F13](https://github.com/corker/mcp-authproxy/issues/14) | decided: [ADR-0017](adr/0017-delegation-obo.md) |
| F15 | [#16](https://github.com/corker/mcp-authproxy/issues/16) | Machine-to-machine | `area:authz` | [F3](https://github.com/corker/mcp-authproxy/issues/4), [F11](https://github.com/corker/mcp-authproxy/issues/12) | decided: [ADR-0022](adr/0022-machine-to-machine.md) |
| F16 | [#17](https://github.com/corker/mcp-authproxy/issues/17) | Discovery & errors | `area:broker` | [F3](https://github.com/corker/mcp-authproxy/issues/4) | decided: [ADR-0013](adr/0013-discovery-and-errors.md) |
| F17 | [#18](https://github.com/corker/mcp-authproxy/issues/18) | Security hardening | `area:security` | all | decided: [ADR-0018](adr/0018-hardening.md) |
| F18 | [#19](https://github.com/corker/mcp-authproxy/issues/19) | Configuration UX | `area:ops` | [F9](https://github.com/corker/mcp-authproxy/issues/10) | decided: [ADR-0020](adr/0020-configuration.md) |
| F19 | [#20](https://github.com/corker/mcp-authproxy/issues/20) | Packaging & deployment | `area:ops` | [F1](https://github.com/corker/mcp-authproxy/issues/2) | decided: [ADR-0019](adr/0019-packaging.md) |
| F20 | [#21](https://github.com/corker/mcp-authproxy/issues/21) | Observability | `area:ops` | — | decided: [ADR-0021](adr/0021-observability.md) |
| F21 | [#22](https://github.com/corker/mcp-authproxy/issues/22) | Testing strategy | `area:project` | [F9](https://github.com/corker/mcp-authproxy/issues/10), [F10](https://github.com/corker/mcp-authproxy/issues/11) | decided: [ADR-0024](adr/0024-testing-strategy.md) |
| F22 | [#23](https://github.com/corker/mcp-authproxy/issues/23) | Project & governance | `area:project` | — | decided: [ADR-0023](adr/0023-project-governance.md) (license: ADR-0002) |
