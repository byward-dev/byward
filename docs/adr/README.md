# Architecture decision records

Decisions for byward, one file each. ADRs 0003–0024 came from the v0.1 features (F1–F22 in
[`docs/archive/features.md`](../archive/features.md)), grilled with the procedure in
[`docs/quality-lenses.md`](../quality-lenses.md); later ADRs and amendments come from GitHub issues.
An ADR is changed only by an amendment: a later ADR (`ADR-NNNN`) or a dated section or note in the
ADR itself, with its issue. The last column lists both.

| ADR | Decision | Feature | Amendments |
|---|---|---|---|
| [0001](0001-scope-auth-only-proxy-entra-first-class.md) | Scope: auth-only proxy, public OSS, Entra first-class | — | 2026-11-06 (rate limiting) |
| [0002](0002-repo-structure-for-agents.md) | Repository structure optimised for coding agents | — | 2026-11-14 (§2, features.md archived; §8, skills) |
| [0003](0003-upstream-kinds.md) | Upstream kinds: HTTP relay; stdio processes never shared between users | F1 | ADR-0025 |
| [0004](0004-spec-revisions-pass-through.md) | Spec revisions: serve both eras, pass through, never translate | F2 | ADR-0007; 2026-11-06 (#61); 2026-11-07 (#168) |
| [0005](0005-auth-modes-broker-only.md) | Auth modes: broker only (a loopback no-auth mode added by ADR-0027) | F3 | ADR-0027 |
| [0006](0006-token-model.md) | Token model: minted, sealed proxy tokens with a revocation deny list | F4 | ADR-0007; 2026-11-14 (#287) |
| [0007](0007-state-and-storage.md) | State and storage: one store interface, embedded SQLite by default | F5 | 2026-11-07 (#150); 2026-11-13 (#227, PostgreSQL) |
| [0008](0008-client-registration.md) | Client registration: static, CIMD and DCR, strictly validated | F6 | — |
| [0009](0009-redirect-uri-policy.md) | Redirect URI policy: exact HTTPS, any-port loopback, re-checked at /token | F8 | ADR-0010; 2026-11-06 (DCR) |
| [0010](0010-consent-screen.md) | Consent screen: before the IdP, per client, remembered only for trusted clients | F7 | 2026-11-06 (#90, slices 1.4, 1.6, 2.1); 2026-11-07 (#126); 2026-11-14 (#287) |
| [0011](0011-idp-adapters.md) | IdP adapters: small interface, generic OIDC with presets, Entra on top | F9 | ADR-0026; ADR-0030; 2026-11-14 (#286, #306) |
| [0012](0012-entra-specifics.md) | Entra specifics: v2, tid+oid, own API scope at login, certificate credentials | F10 | — |
| [0013](0013-discovery-and-errors.md) | Discovery and errors: both well-known paths, one issuer, `iss` everywhere | F16 | — |
| [0014](0014-token-validation.md) | Token validation: header only, sealed checks, no store on the request path | F11 | ADR-0022; 2026-11-07 (#64) |
| [0015](0015-access-gate.md) | Authorization: an access gate at login and refresh, no per-request denials | F12 | 2026-11-06 (slice 1.5); 2026-11-07 (#126); ADR-0014 (#64); ADR-0011 (#286) |
| [0016](0016-identity-propagation.md) | Identity propagation: an RFC 9068 assertion for the upstream, strip then inject | F13 | 2026-11-07 (#151, #64); 2026-11-08 (#187, #207); 2026-11-14 (#330) |
| [0017](0017-delegation-obo.md) | Delegation: proxy-side Entra On-Behalf-Of (v0.2, amended) | F14 | ADR-0029; 2026-11-06 (release); 2026-11-07 (slice 4.2); 2026-11-08 (#195, #141) |
| [0018](0018-hardening.md) | Hardening: Origin and Host checks, bounded HTTP, Rewrite-only proxying | F17 | 2026-11-06 (OAuth rate limits; #102, #103, #105); 2026-11-07 (#167); 2026-11-14 (§13, invariants list moved) |
| [0019](0019-packaging.md) | Packaging: a signed container image and Linux binaries for servers | F19 | 2026-11-13 (#183, TLS) |
| [0020](0020-configuration.md) | Configuration: flags and env, secrets from files, one registry | F18 | — |
| [0021](0021-observability.md) | Observability: redacted logs, an audit stream, one request ID, telemetry off by default | F20 | 2026-11-06 |
| [0022](0022-machine-to-machine.md) | Machine-to-machine: accept Entra app-only tokens, opt-in (v0.2, amended) | F15 | 2026-11-06 (release); 2026-11-07 (#64) |
| [0023](0023-project-governance.md) | Project governance: 0.y.z with a stability contract, Apache-2.0 §5, disclosed AI help | F22 | — |
| [0024](0024-testing-strategy.md) | Testing strategy: a Docker-free check, a client simulator, conformance three ways | F21 | ADR-0027; 2026-11-06 (real clients); 2026-11-07 (#164); 2026-11-14 (§7) |
| [0025](0025-upstream-refusal.md) | Upstream refusals are answered as JSON-RPC responses | F1 | — |
| [0026](0026-idp-adapters-go-jose-only.md) | IdP adapters depend only on go-jose | F9 | — |
| [0027](0027-insecure-no-auth.md) | `--insecure-no-auth`, a loopback-only mode without authentication | F3 | — |
| [0028](0028-product-name-byward.md) | The product is named byward | — | — |
| [0029](0029-stdio-downstream-token-socket.md) | stdio upstreams get downstream tokens from a token socket | F14 | — |
| [0030](0030-oidc-roles-groups-claims.md) | Configurable roles and groups claims for OIDC IdPs | F9 | — |

## Writing a new ADR

- Next number: one above the highest in this table; file `NNNN-short-slug.md`.
- Header: title, `Status`, `Date`, `Issue`. Then Context, Decision, Consequences, and Considered
  options when the rejected alternatives are worth remembering.
- An ADR is not rewritten after acceptance. A later ADR that changes it adds an
  "_Amended by ADR-NNNN_" note at the affected line; a change recorded in the ADR itself is a dated
  "## Amendment" section or "_Amended <date> (#n)_" note. Either way, add it to the Status line and
  to the Amendments column here.
- Add the row to this table in the same PR.
