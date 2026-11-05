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
| F3 | [#4](https://github.com/corker/mcp-authproxy/issues/4) | Auth modes | `area:broker` | — | open |
| F4 | [#5](https://github.com/corker/mcp-authproxy/issues/5) | Token model | `area:broker` | [F3](https://github.com/corker/mcp-authproxy/issues/4) | open |
| F5 | [#6](https://github.com/corker/mcp-authproxy/issues/6) | State & storage | `area:storage` | [F4](https://github.com/corker/mcp-authproxy/issues/5) | open |
| F6 | [#7](https://github.com/corker/mcp-authproxy/issues/7) | Client registration | `area:broker` | [F3](https://github.com/corker/mcp-authproxy/issues/4), [F5](https://github.com/corker/mcp-authproxy/issues/6) | open |
| F7 | [#8](https://github.com/corker/mcp-authproxy/issues/8) | Consent screen | `area:broker` | [F5](https://github.com/corker/mcp-authproxy/issues/6), [F6](https://github.com/corker/mcp-authproxy/issues/7) | open |
| F8 | [#9](https://github.com/corker/mcp-authproxy/issues/9) | Redirect URI policy | `area:broker` | [F6](https://github.com/corker/mcp-authproxy/issues/7) | open |
| F9 | [#10](https://github.com/corker/mcp-authproxy/issues/10) | IdP adapters | `area:idp` | [F3](https://github.com/corker/mcp-authproxy/issues/4) | open |
| F10 | [#11](https://github.com/corker/mcp-authproxy/issues/11) | Entra specifics | `area:idp` | [F9](https://github.com/corker/mcp-authproxy/issues/10) | open |
| F11 | [#12](https://github.com/corker/mcp-authproxy/issues/12) | Token validation | `area:authz` | [F4](https://github.com/corker/mcp-authproxy/issues/5), [F9](https://github.com/corker/mcp-authproxy/issues/10) | open |
| F12 | [#13](https://github.com/corker/mcp-authproxy/issues/13) | Authorization rules | `area:authz` | [F11](https://github.com/corker/mcp-authproxy/issues/12) | open |
| F13 | [#14](https://github.com/corker/mcp-authproxy/issues/14) | Identity propagation | `area:upstream` | [F1](https://github.com/corker/mcp-authproxy/issues/2), [F4](https://github.com/corker/mcp-authproxy/issues/5) | open |
| F14 | [#15](https://github.com/corker/mcp-authproxy/issues/15) | Delegation to downstream APIs | `area:idp` | [F10](https://github.com/corker/mcp-authproxy/issues/11), [F13](https://github.com/corker/mcp-authproxy/issues/14) | open |
| F15 | [#16](https://github.com/corker/mcp-authproxy/issues/16) | Machine-to-machine | `area:authz` | [F3](https://github.com/corker/mcp-authproxy/issues/4), [F11](https://github.com/corker/mcp-authproxy/issues/12) | open |
| F16 | [#17](https://github.com/corker/mcp-authproxy/issues/17) | Discovery & errors | `area:broker` | [F3](https://github.com/corker/mcp-authproxy/issues/4) | open |
| F17 | [#18](https://github.com/corker/mcp-authproxy/issues/18) | Security hardening | `area:security` | all | open |
| F18 | [#19](https://github.com/corker/mcp-authproxy/issues/19) | Configuration UX | `area:ops` | [F9](https://github.com/corker/mcp-authproxy/issues/10) | open |
| F19 | [#20](https://github.com/corker/mcp-authproxy/issues/20) | Packaging & deployment | `area:ops` | [F1](https://github.com/corker/mcp-authproxy/issues/2) | open |
| F20 | [#21](https://github.com/corker/mcp-authproxy/issues/21) | Observability | `area:ops` | — | open |
| F21 | [#22](https://github.com/corker/mcp-authproxy/issues/22) | Testing strategy | `area:project` | [F9](https://github.com/corker/mcp-authproxy/issues/10), [F10](https://github.com/corker/mcp-authproxy/issues/11) | open |
| F22 | [#23](https://github.com/corker/mcp-authproxy/issues/23) | Project & governance | `area:project` | — | partly decided (license: ADR-0002) |
