# ADR-0016: Identity propagation — an RFC 9068 assertion for the upstream, strip then inject

- Status: Accepted
- Date: 2026-11-06
- Issue: #14 (F13)

## Context

ADR-0004 makes identity propagation a v1 requirement: in URL-mode elicitation "The MCP Server **MUST**
verify the identity of the user who opens the URL", and MRTR `requestState` SHOULD be bound to the
principal. The MCP spec defines no mechanism and reserves the `io.modelcontextprotocol/` `_meta` prefix.
RFC 9068 profiles JWT access tokens (`typ: at+jwt`; `iss`, `exp`, `aud`, `sub`, `client_id`, `iat`,
`jti` required); RFC 8725 §3.9 requires audience validation and §3.11 recommends explicit typing;
OWASP ASVS 5.0 4.1.3 requires that intermediary identity headers "cannot be overridden by the
end-user"; RFC 7239: forwarded headers "cannot be relied upon". `/proc/<pid>/cmdline` is readable by all
users by default (`hidepid=0`); `environ` needs ptrace-level access.

Competitors (source): Pomerium signs `X-Pomerium-Jwt-Assertion` (`aud` = host, 5 min, JWKS); Obot, babs
and Microsoft's gateway send plain headers; babs strips every identity, forwarding and authorization
header on every hop; Kong once failed to clear a header when the claim was absent (spoofing); sigbit
lets stdio children inherit the proxy's whole environment; ContextForge always forwards a passthrough
header. Consumers: go-sdk `auth.RequireBearerToken`, the TypeScript SDK's `requireBearerAuth` and
FastMCP's `JWTVerifier` all read `Authorization: Bearer`.

Runtime test (2026-11-06): an ES256 `at+jwt` assertion was accepted by go-sdk v1.8.0's stock middleware
with a ~15-line go-jose verifier and by FastMCP 4.1.6's stock `JWTVerifier`; both rejected wrong `aud`,
expired and wrong-key tokens; FastMCP accepts any `typ`.

## Decision

1. **The identity assertion is an RFC 9068 access token for the upstream:** `typ: at+jwt`, ES256
   pinned, signed with a dedicated key (ADR-0006); `iss` = our issuer, `aud` = that upstream's URL,
   `sub` = the user key (`tid:oid` for Entra), `client_id` = the MCP client, `iat`, `exp` = 60 s, `jti`;
   optional `roles`, `groups`, and opt-in `email`/`name`.
2. **Delivered as `Authorization: Bearer`** to HTTP upstreams, replacing the client's stripped token
   (ADR-0014). The header name is configurable.
3. **JWKS** at `/.well-known/jwks.json` (several keys, rotation with overlap, `Cache-Control:
   max-age=300`), also served on the internal listener the upstream talks to; a `jwks` command exports
   the public keys to a file for upstreams that load them statically.
4. **Strip, then inject, on every request:** remove case-insensitively `Authorization`, our identity
   header, configured plain identity headers, `X-Forwarded-*` (re-set only from trusted sources) and the
   downstream-token header (F14); then set ours and clear any header whose claim is absent.
5. **Plain identity headers** only behind a flag, documented as safe only when the upstream is reachable
   solely through the proxy.
6. **stdio:** identity in env at spawn (`MCP_AUTHPROXY_SUBJECT` opaque, `MCP_AUTHPROXY_ISSUER`, email
   opt-in); never in arguments; never tokens. Children do not inherit the proxy's environment — only an
   allowlist plus operator-configured env.
7. **Upstream credential set by the operator:** a static header name and value (secret via `*_FILE`,
   never logged, redacted in the startup config line). If it uses `Authorization`, the assertion moves to
   the configurable header; the two never share a header. Upstreams behind their own authorization
   server get tokens through F14, not here.
8. **Docs:** a claims-contract page and verification examples for go-sdk, the TypeScript SDK and
   FastMCP; examples, not a library. Verifiers should check `typ` where their library allows and use a
   30 s leeway.
9. **No replay cache** in the proxy; the 60 s lifetime and per-upstream `aud` bound replay.
10. **Missing signing key refuses to start.**

## Consequences

- The claims contract is public interface; RFC 9068 claims are fixed, ours are only ever added.
- Static JWKS copies must be refreshed at key rotation.
- Later: mTLS between proxy and upstream, binding the assertion to the request, identity over a file
  descriptor for stdio.
