# byward documentation

Find your role below. Each page appears once, under the reader who needs it first.

## Evaluating byward

- [README](../README.md): what byward does, and how to try it on your machine without an IdP.
- [Security posture](security-posture.md): guarantees, threat model, security invariants, known gaps.
- [Scope and non-goals](adr/0001-scope-auth-only-proxy-entra-first-class.md): what byward will not do.
- [Packaging](reference/packaging.md): images, archives, signatures and build provenance.

## Running byward: pick your IdP

| IdP | Guide |
|---|---|
| Microsoft Entra ID | [Quickstart: Entra and Claude Code](how-to/quickstart-entra.md) |
| Google | [Sign users in with Google](how-to/google.md) |
| Okta | [Sign users in with Okta](how-to/okta.md) |
| Keycloak | [Sign users in with Keycloak](how-to/keycloak.md) |
| Auth0 | [Sign users in with Auth0](how-to/auth0.md) |
| Any other OpenID Connect IdP | [Sign users in with an OpenID Connect IdP](how-to/oidc.md) |

Then, for every deployment:

- [Run byward](how-to/run-byward.md): the data directory, the keys, the settings, the container or
  the binary, and the first checks.
- [Deploy byward](how-to/deploy.md): one replica or several, TLS, the internal listener.
- [Restrict who can sign in](how-to/access-gate.md) (the access gate).
- [Harden a deployment](how-to/harden-a-deployment.md): the checklist before production.
- [Keep the proxy's state](how-to/state.md) on SQLite (one replica), or
  [run several replicas on PostgreSQL](how-to/postgres.md).
- [Create and rotate sealing keys](how-to/sealing-keys.md).
- [Revoke access](how-to/revoke-access.md) for a user, everyone, a client or a headless caller.
- [Respond to alerts](how-to/respond-to-alerts.md): what each IdP alert and upstream refusal means.
- [Serve TLS at the proxy](how-to/tls.md), and [trust a private CA](how-to/private-ca.md).

### Your MCP server (the upstream)

- [Put a stdio MCP server behind byward](how-to/stdio-upstream.md)
  ([example image](examples/stdio-node/Dockerfile)).
- [Tell the upstream who the user is](how-to/identity-assertion.md) (the identity assertion), or
  [plain identity headers](how-to/plain-identity-headers.md) for an upstream that cannot verify a JWT.
- [Give the upstream the proxy's own credential](how-to/upstream-credential.md).
- [Call a downstream API as the user](how-to/downstream-apis.md) (Entra On-Behalf-Of), and the worked
  example [Microsoft 365 data through Graph](how-to/microsoft-365.md).

### Your MCP clients

- [Client metadata documents (CIMD)](how-to/cimd.md), [dynamic registration (DCR)](how-to/dcr.md), and
  [static clients](reference/static-clients.md).
- [Headless callers with Entra app-only tokens](how-to/app-tokens.md).

### Reference

- [Settings](reference/settings.md), [commands](reference/commands.md) (including `check` and `doctor`),
  [observability](reference/observability.md) (logs, audit events, metrics),
  [identity assertion](reference/identity-assertion.md), [rate limits](reference/rate-limits.md).

## Administering the IdP

The IdP guides above start with what to register at the IdP; these pages go further.

- Entra: [register the app](how-to/quickstart-entra.md#1-register-the-entra-app),
  [a certificate instead of a client secret](how-to/entra-certificate.md),
  [a federated credential instead](how-to/entra-federated-credential.md),
  [app roles for headless callers](how-to/app-tokens.md#1-give-the-caller-a-role-on-the-proxys-app),
  [API permissions for On-Behalf-Of](how-to/downstream-apis.md#1-grant-the-api-permissions),
  [the recommended gate setup](how-to/access-gate.md#entra-recommended-setup).
- Auth0: [roles in the ID token](how-to/auth0.md#2-roles-in-the-id-token).
- Keycloak: [roles and groups in the token](how-to/keycloak.md#2-roles-and-groups-in-the-token).
- Okta: [the authorization server](how-to/okta.md#2-the-authorization-server),
  [a key instead of the secret](how-to/okta.md#5-a-key-instead-of-the-secret-private_key_jwt).
- Any OIDC IdP: [what to register](how-to/oidc.md#1-register-the-proxy-at-the-idp).

## Contributing

- [CONTRIBUTING.md](../CONTRIBUTING.md): setup, the definition of done, the test and AI-assistance policies.
- [CONTEXT.md](../CONTEXT.md): the domain words, used exactly in code and docs.
- [Decisions (ADRs)](adr/README.md), and the [quality lenses](quality-lenses.md) used to grill a feature.
- Coding agents: [AGENTS.md](../AGENTS.md), and [issue tracker](agents/issue-tracker.md),
  [triage labels](agents/triage-labels.md) and [domain docs](agents/domain.md) for their skills.
- Reporting a vulnerability: [SECURITY.md](../SECURITY.md).

## Maintaining byward

- [Cut a release](maintainers/release.md).
- [The scheduled real-Entra lane](maintainers/real-entra-lane.md).
- [Run and read the load test](maintainers/load-test.md).

## Archive

Kept as history, not updated: the [v0.1 feature map](archive/features.md) and the
[landscape research](archive/research.md) of 2026-11-05.
