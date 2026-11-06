# Architecture decision records

Decisions for byward, one file each. The backlog index is [`docs/features.md`](../features.md);
each feature (F1–F22) is a GitHub issue and gets an ADR once grilled with the research procedure in
[`docs/quality-lenses.md`](../quality-lenses.md).

| ADR | Decision | Feature | Amended by |
|---|---|---|---|
| [0001](0001-scope-auth-only-proxy-entra-first-class.md) | Scope: auth-only proxy, public OSS, Entra first-class | — | — |
| [0002](0002-repo-structure-for-agents.md) | Repository structure optimised for coding agents | — | — |
| [0003](0003-upstream-kinds.md) | Upstream kinds: HTTP relay; stdio processes never shared between users | F1 | 0025 |
| [0004](0004-spec-revisions-pass-through.md) | Spec revisions: serve both eras, pass through, never translate | F2 | 0007 |
| [0005](0005-auth-modes-broker-only.md) | Auth modes: broker only in v0.1 | F3 | 0027 |
| [0006](0006-token-model.md) | Token model: minted, sealed proxy tokens with a revocation deny list | F4 | 0007 |
| [0007](0007-state-and-storage.md) | State and storage: one store interface, embedded SQLite by default | F5 | — |
| [0008](0008-client-registration.md) | Client registration: static, CIMD and DCR, strictly validated | F6 | — |
| [0009](0009-redirect-uri-policy.md) | Redirect URI policy: exact HTTPS, any-port loopback, re-checked at /token | F8 | 0010 |
| [0010](0010-consent-screen.md) | Consent screen: before the IdP, per client, remembered only for trusted clients | F7 | — |
| [0011](0011-idp-adapters.md) | IdP adapters: small interface, generic OIDC with presets, Entra on top | F9 | 0026 |
| [0012](0012-entra-specifics.md) | Entra specifics: v2, tid+oid, own API scope at login, certificate credentials | F10 | — |
| [0013](0013-discovery-and-errors.md) | Discovery and errors: both well-known paths, one issuer, `iss` everywhere | F16 | — |
| [0014](0014-token-validation.md) | Token validation: header only, sealed checks, no store on the request path | F11 | 0022 |
| [0015](0015-access-gate.md) | Authorization: an access gate at login and refresh, no per-request denials | F12 | — |
| [0016](0016-identity-propagation.md) | Identity propagation: an RFC 9068 assertion for the upstream, strip then inject | F13 | — |
| [0017](0017-delegation-obo.md) | Delegation: proxy-side Entra On-Behalf-Of in v0.1 | F14 | — |
| [0018](0018-hardening.md) | Hardening: Origin and Host checks, bounded HTTP, Rewrite-only proxying | F17 | — |
| [0019](0019-packaging.md) | Packaging: a signed container image and Linux binaries for servers | F19 | — |
| [0020](0020-configuration.md) | Configuration: flags and env, secrets from files, one registry | F18 | — |
| [0021](0021-observability.md) | Observability: redacted logs, an audit stream, one request ID, telemetry off by default | F20 | — |
| [0022](0022-machine-to-machine.md) | Machine-to-machine: accept Entra app-only tokens, opt-in (v0.2, amended) | F15 | — |
| [0023](0023-project-governance.md) | Project governance: 0.y.z with a stability contract, Apache-2.0 §5, disclosed AI help | F22 | — |
| [0024](0024-testing-strategy.md) | Testing strategy: a Docker-free check, a client simulator, conformance three ways | F21 | 0027 |
| [0025](0025-upstream-refusal.md) | Upstream refusals are answered as JSON-RPC responses | F1 | — |
| [0026](0026-idp-adapters-go-jose-only.md) | IdP adapters depend only on go-jose | F9 | — |
| [0027](0027-insecure-no-auth.md) | `--insecure-no-auth`, a loopback-only mode without authentication | F3 | — |
| [0028](0028-product-name-byward.md) | The product is named byward | — | — |

## Writing a new ADR

- Next number: one above the highest in this table; file `NNNN-short-slug.md`.
- Header: title, `Status`, `Date`, `Issue`. Then Context, Decision, Consequences, and Considered
  options when the rejected alternatives are worth remembering.
- An ADR is not rewritten after acceptance. A later ADR that changes it adds an
  "_Amended by ADR-NNNN_" note at the affected line and a row update here.
- Add the row to this table and link the ADR from `docs/features.md` in the same PR.
