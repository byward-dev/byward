# ADR-0026: IdP adapters depend only on go-jose

- Status: Accepted
- Date: 2026-11-06
- Issue: #49 (F9; amends ADR-0011)

## Context

ADR-0011 §9 chose `coreos/go-oidc` v3.21.0, `golang.org/x/oauth2` v0.37.0 and `go-jose` v4.1.9.
Building the adapters (source read 2026-11-06):

- **x/oauth2 v0.37.0:** a refresh sends only `grant_type` and `refresh_token` (`oauth2.go:279-282`),
  so a `private_key_jwt` client — the credential ADR-0012 §5 recommends — cannot refresh. The library
  also exposes no Entra error fields (`error_codes`, `trace_id`, `correlation_id`) and reads up to
  1 MiB of a token response (`internal/token.go:263`), above our 64 KiB budget.
- **go-oidc v3.21.0:** its `RemoteKeySet` de-duplicates parallel refetches but has no refetch rate
  limit (ADR-0011 Context), so the rate-limited key set of ADR-0011 §7 has to be ours anyway; what
  remains of go-oidc is JWT parsing, which go-jose provides.
- **go-jose versions** (Go module proxy): v4.1.9 2026-11-05, v4.1.8 2026-11-02, v4.1.7 2026-10-30,
  v4.1.6 2026-10-14. Only v4.1.6 is at least two weeks old. ADR-0019 §5 sets that age rule for
  tools; the Dependabot `gomod` cooldown of 14 days in the open release-pipeline PR (#70) applies it
  to Go modules. OSV (2026-11-06): the newest fixed advisory, GHSA-mgcc-cww5-fp2q (DoS when parsing
  JWKs that contain RSA keys), is fixed in 4.1.6; no advisory affects 4.1.6. `govulncheck` v1.9.0:
  no vulnerabilities.

## Decision

1. **`internal/idp` holds a small OAuth/OIDC client** on the standard library: a token-endpoint client
   with bounded bodies, the client credentials of ADR-0011 §4, a JWKS cache with a refetch rate limit,
   and OIDC Core ID token validation.
2. **go-jose v4 is the only dependency,** pinned at **v4.1.6**; go-oidc and x/oauth2 are not used.
3. **Go module upgrades follow the two-week age rule** of ADR-0019 §5, extended here from tools to
   modules, and are checked with `govulncheck`.

## Consequences

- We own the client-authentication, refresh and JWKS code: its parsers (token responses, JWKS, JWTs,
  callbacks, AADSTS codes) have fuzz targets per ADR-0018, and the adapter suites run it against the
  fake IdP.
- ADR-0011 §7 and §9 are amended; the interface and presets of ADR-0011 are unchanged.

## Considered options

- x/oauth2 for the code exchange and our own refresh: rejected; two token clients with different
  bounds and error parsing.
- go-oidc's `RemoteKeySet` behind a rate-limiting wrapper: rejected; the wrapper cannot tell an
  unknown `kid` from a bad signature.
- go-jose v4.1.9: rejected under the age rule. Newer key types it parses (e.g. AKP) are skipped by
  our key set, which loads each JWKS entry on its own (RFC 7517 §5), so 4.1.6 suffices.
