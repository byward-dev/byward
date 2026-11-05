# ADR-0012: Entra specifics — v2, tid+oid, own API scope at login, certificate credentials

- Status: Accepted
- Date: 2026-11-05
- Issue: #11 (F10)

## Context

Entra is the differentiator (ADR-0001). Microsoft Learn (verbatim, 2026-11-05): v2 issuers end in
`/v2.0`; for multi-tenant apps "validate that the issuer … matches the iss claim … in addition to …
the tenant ID (tid)"; "use the immutable claim values `tid` and `oid` as a combined key"; `email`:
"Never use it for authorization"; requesting our own `.default` "returns an `id_token`, rather than an
access token"; one request may combine OIDC scopes with one resource; the `resource` parameter fails
with AADSTS901002 unless the app uses `requestedAccessTokenVersion: 2` and an HTTPS App ID URI; groups
overage at "200 for JWT tokens"; client secrets are "limited to two years"; certificate assertions use
the v2 token endpoint as `aud` and should be PS256 with `x5t#S256`. Entra's live discovery document
advertises no RFC 9207 `iss`, PAR, DPoP, back-channel logout or `code_challenge_methods_supported`.
Competitors (source): nobody implements the multi-tenant issuer check (oauth2-proxy's docs say to turn
issuer verification off), nobody ships certificate credentials, nobody maps AADSTS codes, and
oauth2-proxy keys users on email.

Real-tenant test (2026-11-05, four app registrations, all deleted; record in the research notes):
logging in with `openid profile email offline_access api://<app>/access_as_user` returned an access
token with `aud` = our app, `ver` 2.0, `scp` access_as_user, and that token worked as an OBO assertion
for Graph `User.Read` once Graph was consented (AADSTS65001 before). Requesting Graph scopes at login
instead returned a Graph token that failed OBO with AADSTS50013. With our own scope, Entra showed no
consent screen and recorded no grant, even with `prompt=consent`; with a Graph scope it showed
"Permissions requested … This application is not published by Microsoft." A client-credentials probe
worked with zero app permissions; a wrong secret gave 401 AADSTS7000215. `private_key_jwt` worked with
PS256 or RS256 and `x5t#S256` or `x5t`; no thumbprint gave AADSTS5002723, a wrong key AADSTS700027.
No `iss` parameter was returned in authorization responses.

## Decision

1. **v2 endpoints only.**
2. **Tenancy:** single tenant (a tenant GUID) by default; `organizations` only with a non-empty `tid`
   allowlist; `common` and `consumers` refused in v0.1. Issuer check: exact for a single tenant; for
   `organizations`, substitute `tid` into the `{tenantid}` template, require `iss` to equal it, and
   `tid` must be a GUID on the allowlist.
3. **User key `tid`+`oid`**, fixed; `name`, `preferred_username` and `email` are display only.
4. **Login request:** PKCE S256 (although not advertised), `nonce`, `response_mode=query`, never
   `resource`; scopes `openid profile email offline_access api://<app-id>/access_as_user`. The
   operator exposes that one scope with `requestedAccessTokenVersion: 2`. The resulting access token is
   stored encrypted for later On-Behalf-Of (F14).
5. **Credentials:** a certificate (`private_key_jwt`, PS256, `x5t#S256`, `aud` = v2 token endpoint) is
   recommended; a federated token file (`AZURE_FEDERATED_TOKEN_FILE`) re-read on every call; a client
   secret only via `*_FILE`, documented for development and small setups. Managed identity later.
   Previous credentials are accepted during rollover.
6. **Refresh errors:** AADSTS700082, 70043, 50076, 65001 and `invalid_grant` become `invalid_grant` to
   the MCP client; 5xx, 429 and timeouts become 503; `invalid_client` (7000222, 7000215, 700016,
   5002723, 700027) becomes 503 plus a loud operator alert, never a mass sign-out. A new refresh token
   is stored only if Entra returns one.
7. **Friendly pages** for 50020, 50105, 65001, 50011, 53003, 700016, 7000222 and 90072: a user message
   plus an operator hint in the logs; `error_description` is never shown raw.
8. **Roles and groups** (input to F12): app roles (`roles`) preferred; groups overage (`hasgroups`,
   `_claim_names`) means groups are unavailable, so a rule that needs groups denies. No Graph lookup in
   v0.1.
9. **No `cp1`** (claims challenges) in v0.1; Conditional Access blocks surface as page 53003.
10. **`doctor` (Entra part):** discovery, issuer and `{tenantid}` substitution, JWKS; a
    client-credentials probe that validates the credential without any app permission; optional
    `IDP_SECRET_EXPIRES_AT` warning at 30 days or less; a wrong redirect URI (50011) reported on the
    first real login.
11. **Hints:** pass-through for `domain_hint`, `login_hint` and `prompt=select_account`.
12. **Setup guide:** a single-tenant app registration; Expose an API with `requestedAccessTokenVersion:
    2`; redirect `https://<proxy>/callback/entra`; admin consent recommended (OBO and downstream APIs
    need it); notes on user assignment and publisher verification. With our login scopes, users may see
    only our consent page; if an operator adds another resource, Entra adds its own screen, worded per
    tenant ("not published by Microsoft" in the test).

## Consequences

- The fake IdP's `entra` profile must reproduce decisions 2–9: the `{tenantid}` issuer, a pairwise
  `sub`, the v2 `aud`, no `iss` parameter, AADSTS codes, groups overage, and both assertion forms.
- Not verified in a real tenant: `organizations` (needs a second tenant), tenants with user consent
  disabled, and the federated token file. None of them changes a decision.
