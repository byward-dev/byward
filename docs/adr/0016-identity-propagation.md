# ADR-0016: Identity propagation — an RFC 9068 assertion for the upstream, strip then inject

- Status: Accepted; amended 2026-11-07 (#151, #64), 2026-11-08 (#187, #207), 2026-11-14 (#330)
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
6. **stdio:** identity in env at spawn (`BYWARD_SUBJECT` opaque, `BYWARD_ISSUER`); never in
   arguments; never tokens. _Amended 2026-11-14 (#330):_ no email. The `email` opt-in of §1 is the
   assertion's only; a stdio process gets no `BYWARD_EMAIL`, as item 6 of the 2026-11-07 amendment
   says. Children do not inherit the proxy's environment — only an
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

## Amendment 2026-11-07 (only verified emails, #151)

§1 asserted the opt-in `email` exactly as the IdP sent it. An upstream author may still trust it,
although nothing vouched for it. So now:

1. **An email is asserted only when the IdP vouches for it:** an OIDC ID token with
   `email_verified: true` (the boolean, or Google's string `"true"`). OIDC Core §5.1 defines it as
   "the OP took affirmative steps to ensure that this e-mail address was controlled by the End-User",
   and does not say what an absent claim means; byward reads absent as unverified, as the access gate
   already does for email domains.
2. **Entra never vouches for an email.** It sends no `email_verified`, and Microsoft says not to rely
   on the claim: "This value isn't guaranteed to be correct and is mutable over time. Never use it for
   authorization or to save data for a user" (ID token claims reference); "Never use `email` or `upn`
   claim values to store or determine whether the user in an access token should have access to data"
   (optional claims reference); "Applications should never use the email claim for authorization due
   to its mutability and non-uniqueness" (MSRC, 2023-06-20). `xms_edov` is not used: it is off by
   default, and it says the email's domain owner is verified, not that the user controls the mailbox.
   `removeUnverifiedEmailClaim` only removes the claim, and nothing in the token says it applied.
3. **`BYWARD_ASSERTION_UNVERIFIED_EMAIL=true`** (default `false`) also asserts an email the IdP does not
   vouch for, the same way for every IdP. It is how an Entra deployment asserts an email at all.
4. **`email_verified` is asserted with `email`, and only with it:** `true` when the IdP vouched for
   it, `false` when only the opt-in let it through. It is added to the claims contract (§ Consequences:
   ours are only ever added).
5. **One place decides:** the broker, when it picks the claims sealed into the access token. The
   assertion and every other copy of the email read them from there: the plain identity headers
   (§5) send `X-Byward-Email-Verified` exactly when they send `X-Byward-Email`.
6. **Every start logs** which emails are left out or carried unverified, naming the setting; a
   configuration with `email` opted in is never refused. A stdio upstream gets no email (§6), so it
   gets no such warning either.
7. **Tokens already issued keep their claims** until they expire: after the upgrade, or after the
   opt-in is turned off, an access token keeps its email, marked `email_verified: false`, for at most
   one access-token lifetime (one hour); a refresh token's next use decides again.

This is stricter than the products we checked (2026-11-07): oauth2-proxy v7.15.6 refuses only an
explicit `email_verified: false`, so with Entra its check never applies; Pomerium v0.34.0 asserts
`email` without checking it; sigbit/mcp-auth-proxy v2.10.2 and mcp-front never read it. (Cloudflare
Access calls its `email` "verified by the identity provider" but falls back to the UPN with Entra;
whether it checks `email_verified` is unverified.) Sources checked 2026-11-07; research notes kept
outside the repository. For a security product that is the right side to err on: an upstream that
reads `email` gets one that someone vouched for, or a claim that says nobody did.

## Amendment 2026-11-07 (#64): `principal_type`

Every assertion carries `principal_type`: `user`, or `client` for an Entra app-only caller
(ADR-0022 §5), whose `sub` is the service principal's `tid:oid` and `client_id` its application ID.
The minter refuses an identity without one rather than defaulting to `user`. stdio processes get
`BYWARD_PRINCIPAL_TYPE` and the plain identity headers (§5) `X-Byward-Principal-Type` with the same
values.

## Amendment 2026-11-08 (#187): the internal listener's JWKS

§3's JWKS on the internal listener is plain http, so over any network hop an on-path attacker can
substitute keys and forge assertions. The docs offer it only for an upstream on the same host or
behind a NetworkPolicy and mesh mTLS; otherwise the upstream uses the public https JWKS or a pinned
`byward jwks` export. TLS on the internal listener, reusing #183's pair, is possible later.

## Amendment 2026-11-08 (#207): `jwks_uri` in the authorization server metadata

This reverses #135's choice not to advertise the JWKS. Some verifiers find keys only through OIDC
discovery: MCP Toolbox's `generic` auth service (v1.16.0) has no JWKS setting and reads `jwks_uri`
from `<issuer>/.well-known/openid-configuration`, as OpenSearch's `openid` authenticator does. FastMCP's
`JWTVerifier`, OpenSearch's `jwt` authenticator and go-oidc take a JWKS URL directly.

1. **With an HTTP upstream, the metadata at both well-known paths lists `jwks_uri`**, the public
   `/.well-known/jwks.json`. With a stdio upstream there is no assertion and no `jwks_uri`. The
   assertion's `iss` stays byward's issuer, so the claims contract is unchanged. OpenID Connect
   Discovery 1.0 §3 makes `jwks_uri` REQUIRED; RFC 8414 §2 makes it OPTIONAL.
2. **Why it is safe:** #135 feared that clients would treat proxy tokens as JWTs. They cannot: proxy
   tokens are opaque `byw_` strings, not JWT-shaped. The keys verify only identity assertions, which
   are `typ: at+jwt` with the upstream URL as `aud`, so an MCP client holds nothing these keys verify.
3. **Rule:** every JWT byward signs carries a `typ` and an `aud` that only it uses, so no other kind
   can pass as an assertion under the same issuer and keys. A test lists every signer and its `typ`
   (`TestEveryJWTByWardSignsHasATypOfItsOwn`); a new one must be added there.
4. `byward doctor` follows discovery to the signing key ("identity assertion keys (discovery)").
   The internal listener serves no discovery document; a discovery-only verifier uses the public
   origin.
