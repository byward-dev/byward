# Security Audit Scope

This document defines the scope and boundaries for independent security reviews and code audits of `byward` (pre-1.0). It is designed for security auditors from programmes such as OSTIF and Sovereign Tech Resilience.

## 1. Overview

`byward` is an auth-only proxy sitting in front of an upstream MCP (Model Context Protocol) server. It acts as an OAuth 2.1 authorization server (the **broker**) and an RFC 9728 protected resource, authenticating users via Microsoft Entra ID or an OpenID Connect (OIDC) IdP.

## 2. Core Components in Scope

### A. Broker & OAuth 2.1 Authorization Server
- **Endpoints:** `/authorize`, `/consent`, `/callback/entra`, `/token`, `/revoke`, `/register`.
- **Mechanisms:** Authorization Code Flow with PKCE (`S256` required), static clients, Dynamic Client Registration (DCR), and Client Identity Metadata Documents (CIMD).
- **Consent:** Per-client consent screens with CSRF protections (`Origin`, `Sec-Fetch-Site`, `__Host-` cookies, 10-minute flow expiry).

### B. Token Handling & Cryptography
- **Sealed Tokens:** Access and refresh tokens are encrypted and authenticated using AES-256-GCM (`internal/token/token.go`). Associated data binds the resource URL and token type, and tokens carry strict expiration (`exp`).
- **Refresh & Revocation:** Access tokens last 1 hour. Refresh tokens rotate on every use, with a 30-second grace period for retries; reuse outside the grace revokes the grant. RFC 7009 revocation is fully supported.

### C. IdP Adapters
- **Microsoft Entra ID:** Single-tenant authentication with certificate-based client credentials (`PS256` with `x5t#S256`), federated token files, or client secrets.
- **OIDC Providers:** Generic OIDC discovery with issuer strict matching and SSL enforcement outside development mode (`--dev`).

### D. Stdio Sandbox, Upstream Relay, and Token Socket
- **Identity Propagation:** ES256 JSON Web Token (JWT) identity assertions signed by the proxy with a 60-second expiration (`aud` = upstream). Client identity headers are systematically stripped.
- **Stdio Isolation:** Each MCP session runs in its own process and temporary session directory with restricted permissions (`0700` directories, `0600` token socket files).
- **Downstream Token Socket (`BYWARD_DOWNSTREAM_TOKEN_SOCKET`):** Unix domain socket serving On-Behalf-Of (OBO) downstream API tokens exclusively to the upstream process and its authenticated descendants running under the same UID, verified via peer credential inspection (`SO_PEERCRED` / `LOCAL_PEERCRED`) and process ancestry walks.

### E. Logging & Redaction
- **Structured Logging:** `slog`-based logging with strict attribute allowlists and automatic Bearer/JWT-shaped token redaction (`internal/logging/logging.go`). Audit logs record security events without exposing credentials or secrets (`internal/audit`).

## 3. Related Documentation & References

- **Security Posture:** [docs/security-posture.md](../security-posture.md)
- **Threat Model & Architecture ADRs:** 
  - [ADR-0001: Scope, Auth-Only Proxy](../adr/0001-scope-auth-only-proxy-entra-first-class.md)
  - [ADR-0005: Auth Modes (Broker Only)](../adr/0005-auth-modes-broker-only.md)
  - [ADR-0006: Token Model](../adr/0006-token-model.md)
  - [ADR-0015: Access Gate](../adr/0015-access-gate.md)
  - [ADR-0016: Identity Propagation](../adr/0016-identity-propagation.md)
  - [ADR-0017: Delegation OBO](../adr/0017-delegation-obo.md)
- **Quality Lenses & Invariants:** [docs/quality-lenses.md](../quality-lenses.md)
