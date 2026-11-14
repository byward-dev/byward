# ADR-0014: Token validation — header only, sealed checks, no store on the request path

- Status: Accepted; amended by ADR-0022, and 2026-11-07 (#64)
- Date: 2026-11-05
- Issue: #12 (F11)

## Context

On every MCP request the proxy validates its own proxy token (ADR-0006). MCP 2026-07-28: clients
"MUST use the Authorization request header field … Access tokens MUST NOT be included in the URI query
string"; servers "MUST validate that access tokens were issued specifically for them as the intended
audience"; "Invalid or expired tokens MUST receive a HTTP 401". OAuth 2.1 draft-14 §5.1: "resource
servers MUST ignore access tokens in a URI query parameter". RFC 6750 §3: no credentials → a bare
challenge that "SHOULD NOT include an error code"; `invalid_token` → 401; `insufficient_scope` → 403.

Competitors (source, 2026-11-05): babs binds the token type as associated data, checks audience,
uses fixed error descriptions and strips `Authorization` before relaying — the model to follow.
go-sdk's `RequireBearerToken` (v1.8.0) never sends `error="invalid_token"` and answers in plain text.
ToolHive returns raw error text; agentgateway's audience check is optional, a bug class with a public
advisory for the TypeScript SDK (GHSA-rvq5-wwqv-78pq). VS Code and Claude Code treat any 401 as "sign
in again".

## Decision

1. **Tokens only from `Authorization: Bearer`.** Tokens in the query string or form body are ignored;
   `access_token` is stripped from the query before relaying; a token sent both ways gets 400
   `invalid_request`.
2. **Check order, no store read:** type prefix → AEAD open (key chosen by key ID; resource URL and
   token type as associated data) → format version → `exp`/`iat` with the 30 s leeway → in-memory deny
   list (grant ID, per-user cut-off; fail closed when more than 30 s stale, ADR-0006). The result is the
   request's identity (F13). _Amended by ADR-0022:_ a three-part JWT goes to the opt-in Entra app-only
   path instead; the validator is chosen by format, never by fallback.
3. **401 shapes:** no token → `WWW-Authenticate: Bearer resource_metadata="…", scope="…"` with no
   error code; a bad, expired or revoked token → `error="invalid_token"` with a fixed description that
   only distinguishes "expired" from "invalid", and a JSON body. Every cryptographic failure looks the
   same.
4. **Our own small middleware**, not go-sdk's `RequireBearerToken`; the inbound `Authorization` header
   is always removed before relaying (ADR-0003).
5. **Never log tokens;** metrics count result categories only. No cache of rejected tokens (it would
   be a memory-exhaustion target). DPoP is later; the token format version leaves room for `cnf`.

## Consequences

- Validation costs one AEAD open and an in-memory lookup per request.
- The 401 shapes are the ones in ADR-0013; F12 adds no 403s in v0.1.

## Amendment 2026-11-07 (#64): the first 403, app path only, v0.2

An app-only caller whose token is valid but whom the app gate refuses (no required app role, not
in the client-ID or tenant list) gets `403` with `WWW-Authenticate: Bearer
error="insufficient_scope"` and a fixed description, and no `scope` or `resource_metadata`: no
interactive step-up could help, only the operator's role assignment can (RFC 6750 §3.1). Headless
callers are not the interactive clients that loop on 403; Claude Code re-runs its `headersHelper` and
retries once when a tool call gets 401 or 403, and fails the connection when the credential is
refused at connect (code.claude.com/docs/en/mcp, 2026-11-07). Every other refusal keeps the 401 shapes of §3, and proxy
tokens never get a 403.
