# ADR-0011: IdP adapters — small interface, generic OIDC with presets, Entra on top

- Status: Accepted; amended by ADR-0026 and ADR-0030, and 2026-11-14 (#286, #306)
- Date: 2026-11-05
- Issue: #10 (F9)

## Context

The broker (ADR-0005) is an OAuth client of one **IdP** and uses only the IdP's ID token for identity
at login (ADR-0006). Competitors (source, 2026-11-05): dex uses small capability interfaces with code
per IdP; oauth2-proxy, Pomerium (11 methods) and sigbit use one large interface; ToolHive is
config-driven (`subject_claim`); agentgateway an enum; babs and lethek generic OIDC only. None defends
against IdP mix-up on its IdP leg except dex's per-connector callback. GitHub (no OIDC, no ID token) is
supported by half of them.

OIDC Core §3.1.3.7: `iss` "MUST exactly match", `aud` contains our client ID and no untrusted extra
audiences, `azp`, `exp`, `nonce` checked if sent, signature algorithm agreed. IdP quirks (official
docs): Google's `iss` has two forms and `email_verified` may be a string; Okta's org authorization
server tokens "aren't intended for validation or use by your own apps"; Auth0's issuer ends in a slash
(observed on a live tenant); Keycloak's issuer is `/realms/{realm}`. Entra sends no RFC 9207 `iss`
(confirmed in a real tenant). go-oidc v3.21.0 de-duplicates parallel JWKS refetches but does not
rate-limit them (`oidc/jwks.go`).

## Decision

1. **A small interface** in `internal/idp`, split by capability: `Authenticator` (login URL with
   `state`, `nonce`, PKCE; callback returning an `Identity` — stable subject key, display claims, raw
   claims for authorization rules — plus the IdP tokens); optional `Refresher`, whose errors are
   classed as *sign in again*, *temporarily unavailable* (5xx, timeouts and `invalid_client`, so a
   broken credential never signs everyone out) or *fatal*; optional `Revoker` (best effort, ADR-0006).
2. **`internal/idp/oidc`, the generic adapter.** IdP presets (`google`, `okta`, `auth0`, `keycloak`)
   are data: issuer templates, accepted issuers, required scopes, claim quirks (`email_verified` as
   bool or string, optional `hd` check). `subject_claim` defaults to `sub`; setting it to a mutable
   claim (`email`, `preferred_username`, `upn`) logs a startup warning.
   _Amended 2026-11-14 (#286):_ the roles and groups claims are configurable too (below).
   _Amended by ADR-0030:_ the decision in full.
3. **`internal/idp/entra` builds on the generic adapter** (ADR-0012); its subject key is fixed.
4. **Client credentials are an injected service** shared by all adapters: client secret from
   `*_FILE`; `private_key_jwt` with a key file; a client assertion read from a file on every call
   (workload identity). No vendor SDK. _Amended 2026-11-14 (#306):_ the signing algorithm (below).
5. **ID token validation per OIDC Core §3.1.3.7:** exact `iss`; `aud` contains our client ID with no
   untrusted extra audiences; `azp`; `exp`; `iat` within the ADR-0006 skew leeway; `nonce` always sent
   and checked; an algorithm allowlist per IdP (never `HS*` or `none`); signatures always verified,
   including on the direct token-endpoint flow.
6. **Mix-up defence:** a callback path per IdP (`/callback/{idp}`, RFC 9700 §4.4.2.2), the expected
   issuer bound into the sealed `state`, and `iss` required whenever the IdP advertises it.
7. **Discovery and JWKS:** go-oidc's key set with a rate limit on refetching for an unknown `kid`;
   discovery is lazy with bounded retries and never caches errors; the last good discovery and JWKS
   stay in memory if a refresh fails; readiness is false until discovery succeeds. Presets compare
   issuers exactly as configured and startup checks them against the discovered `issuer`.
   _Amended by ADR-0026:_ the key set is our own (go-jose only).
8. **Not in v0.1:** GitHub and other non-OIDC providers; several IdPs per proxy (the per-IdP callback
   keeps it possible); PAR, DPoP and IdP logout toward the IdP; on-disk discovery or JWKS caches.
9. **Libraries:** `coreos/go-oidc` v3.21.0, `golang.org/x/oauth2` v0.37.0, `go-jose` v4.1.9.
   _Amended by ADR-0026:_ only `go-jose` v4.1.6.

## Consequences

- An IdP's `error_description` is never shown to users raw; user pages and operator hints are mapped.
- A preset's defaults are public interface: changing one is a breaking change.
- One adapter test suite runs against the fake IdP's profiles and Keycloak (F21); a real-tenant Entra
  lane is a scheduled extra, not the main gate.

## Amendment 2026-11-14 (#286, #306): claims and the client assertion's algorithm

Recorded after the fact. Neither change is in v0.2.0-rc.1: both are on `main`, #286 with #302 and
#306's algorithm setting, `BYWARD_OIDC_CLIENT_KEY_ALG`, with #321. Item 2 describes the signing on
`main`; v0.2.0-rc.1 signs as item 2 does with the setting unset.

1. **Roles and groups claims (#286):** for an OIDC IdP, the access gate and the identity assertion
   read roles and groups from the ID token claims `BYWARD_OIDC_ROLES_CLAIM` and
   `BYWARD_OIDC_GROUPS_CLAIM` name, `roles` and `groups` by default for every preset, so an IdP
   that sends them in a namespaced claim (`https://example.com/roles`) works. A blank or padded
   name, or a claim of the sign-in itself such as `aud`, is a configuration error: `aud` holds our
   client ID, so a gate on it would admit every user of the IdP.
2. **The client assertion's algorithm (#306):** `private_key_jwt` signs with
   `BYWARD_OIDC_CLIENT_KEY_ALG`: PS256 (the default) or RS256 for an RSA key, ES256 for an EC P-256
   key, and the IdP's client must accept that algorithm. RS256 is for an IdP that refuses PS256
   without advertising it (Okta, `Preset.RefusedAssertionAlgs`) (`internal/idp/clientauth.go`;
   [OIDC how-to](../how-to/oidc.md)).
