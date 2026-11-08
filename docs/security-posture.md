# Security posture

For security reviewers. What byward guarantees, what it does not, and where each claim is
enforced and tested. This page describes `main` as of 2026-11-06 (pre-release, 0.y.z). Items marked
**planned** are not built yet. Terms follow [CONTEXT.md](../CONTEXT.md). To deploy it, see
[Harden a deployment](how-to/harden-a-deployment.md).

## What it is

An **auth-only** proxy in front of one **upstream** MCP server. To MCP clients it acts as a
protected resource (RFC 9728) and as an OAuth 2.1 authorization server (the **broker**). It signs
users in at an **IdP** and then relays MCP traffic to the upstream
([ADR-0001](adr/0001-scope-auth-only-proxy-entra-first-class.md),
[ADR-0005](adr/0005-auth-modes-broker-only.md)). Today the only IdP is Microsoft Entra ID, in single-tenant
mode, and the only upstream kind is HTTP.

**It guarantees:**

- Every MCP request carries a valid **proxy token** that the broker issued for this resource URL.
  Otherwise the request gets 401 and never reaches the upstream.
- Who may sign in at all is decided by the **access gate**. It runs at sign-in and at every
  refresh ([ADR-0015](adr/0015-access-gate.md)).
- The user approves each MCP client on a **consent** page before the IdP sign-in.
- No token the client sent is ever forwarded to the upstream.

**It does not:**

- **Authorize tools or resources.** It has no per-tool rules and no `tools/list` filtering. Every
  user who passes the gate can call everything the upstream offers
  ([ADR-0015](adr/0015-access-gate.md) §6).
- **Inspect content.** MCP bodies are relayed byte for byte and never parsed. Prompt injection and
  tool poisoning are out of scope.
- **Tell the upstream who the user is.** The identity assertion is **planned** (#62,
  [ADR-0016](adr/0016-identity-propagation.md)). Until then the upstream sees no user identity.
  It cannot tell users apart, so it must not hold per-user state or per-user permissions.
- **Rate-limit MCP traffic.** Only the OAuth endpoints are rate-limited. MCP requests are capped in
  flight: 64 requests and 256 streams, then 503.
- **Terminate TLS.** TLS ends at your ingress or reverse proxy ([ADR-0019](adr/0019-packaging.md) §9).

## Threat model

| Threat | Protection | Where |
|---|---|---|
| Unauthenticated caller reaches the upstream | Every request to the MCP route passes the token guard. Tokens are read from `Authorization: Bearer` only. Methods other than GET, POST and DELETE get 405, and other paths never reach the upstream. | `internal/resource/resource.go` (Guard), `internal/server/server.go` (Handler, mcpMethods) |
| Another user's token, or a forged or altered one | Sealed tokens are AES-256-GCM. The resource URL and the token type are bound as associated data, and the token carries `exp`. Every failure looks the same (`invalid_token`). | `internal/token/token.go`, `internal/token/validator.go` |
| A malicious MCP client or app, or a confused deputy | Each client sees a consent page before the IdP sign-in. Only static clients and trusted CIMD hosts are remembered, for 30 days per user, client, redirect URI and resource; domain CIMD hosts and DCR clients are asked every time (see **Remembered consent** under [Token model](#token-model)). Redirect URIs match exactly, except the port on loopback, and are checked again at `/token`. PKCE S256 is required. A code is single-use and bound to its client. | `internal/broker/consent.go`, `internal/registration/redirect.go`, `internal/broker/token.go` |
| Token theft | Access tokens last 1 h. Refresh tokens rotate on every use, and reuse after the 30 s grace revokes the grant. A refresh token works only for the client it was issued to. Clients can revoke with `/revoke` (RFC 7009). | `internal/broker/refresh.go`, `internal/broker/revoke.go` |
| CSRF or clickjacking on consent | The answer needs exactly one `Origin` equal to the public origin; a missing or `null` Origin is refused. `Sec-Fetch-Site` must be `same-origin` when the browser sends it. A `__Host-` binding cookie and a sealed flow that expires after 10 min are required. Allow is refused within 1 s of showing the page. Every page sends CSP `frame-ancestors 'none'`, `X-Frame-Options: DENY` and `script-src 'none'`. | `internal/broker/consent.go`, `internal/broker/page.go` |
| DNS rebinding and cross-site requests to the MCP endpoint | `Host` is checked against an allowlist on the public listener (421), and on the internal listener only IP addresses, `localhost` and listed names pass (421). `Origin` on the MCP endpoint is checked against an exact list (403). Both checks run before authentication. | `internal/origin/origin.go` |
| SSRF | Client-supplied URLs (CIMD documents, and the `jwks_uri` of CIMD and DCR clients) are fetched only through the SSRF guard: `https` on port 443, public addresses only, checked when the connection is dialled (after DNS resolution, so a rebinding name cannot slip through), no redirects, no environment proxy, 5 KB and 5 s ([ADR-0008](adr/0008-client-registration.md) §4). Static clients have no `jwks_uri`. Entra endpoints are built from the fixed `https://login.microsoftonline.com` authority and the configured tenant. The IdP fetcher follows no redirects, bounds bodies and times out after 5 s. | `internal/ssrfguard`, `internal/server/wire.go`, `internal/idp/fetch.go`, `internal/idp/entra/entra.go` |
| Abuse of OAuth endpoints | Per-address token buckets apply on `/authorize`, `/consent`, `/callback/entra`, `/token`, `/revoke` and `/register`, with IPv6 grouped by /64. Open registration has its own controls (**Dynamic client registration** under [Token model](#token-model)). Request bodies are bounded. Every `http.Server` timeout is set. | `internal/ratelimit`, `internal/broker/register.go`, `internal/server/run.go` |

**Out of scope:** a compromised upstream, which receives every MCP request and answer. Also out of
scope: a compromised host or container runtime, where the sealing keys, secret files and process
memory are readable. And a compromised IdP or IdP tenant admin.

## Security invariants

The invariants are listed in [quality-lenses.md](quality-lenses.md#invariants), and every change must
keep them (AGENTS.md). Status on `main`:

| # | Invariant | Enforced in | Tested by |
|---|---|---|---|
| 1 | No token passthrough to the upstream | `internal/upstream/relay/relay.go` (`strip` removes `Authorization`; `access_token` dropped from the query). A stdio upstream gets only the JSON-RPC body on stdin, and an environment of an allowlist, the operator's env file and the user's key (`internal/upstream/stdio/command.go`) | `TestRelayForwardsBodyVerbatimAndStripsProxyHeaders`, `TestValidTokenIsRelayedWithoutIt`, `TestEachStdioMCPSessionIsItsOwnUpstreamProcessBoundToItsUserWithNoTokenOrProxySetting`, `TestUpstreamGetsOnlyAllowlistOperatorEnvAndIdentity` |
| 2 | Never log tokens, secrets, codes or verifiers | `internal/logging/logging.go` (attribute allowlist, bearer/JWT-shaped redaction); `internal/audit` (no credential fields) | `TestRedaction`, `TestMiddlewareLogsRequestWithoutQueryOrHeaders`, `TestAuditRecordsMatchTheGoldenSchema` |
| 3 | Named IdP endpoints from config only | `internal/idp/entra/entra.go` (`endpoint`: the fixed authority `https://login.microsoftonline.com` plus the tenant GUID; discovery is read only to check the issuer) | `TestAuthCodeURLTargetsTenantAuthorizeWithAccessAsUserScope`, `TestIssuerMustMatchTokenTenantAndAllowlist` |
| 4 | Client-supplied URLs only through the SSRF guard | `internal/ssrfguard` (dial-time address check); `internal/server/wire.go` builds one guard and gives it to the CIMD registry (documents and `jwks_uri`) and the DCR registry (`jwks_uri`) | `TestNonPublicAddressesAreRefused`, `TestRedirectsAreNotFollowed`, `TestTheGuardedHTTPClientRefusesPrivateAddresses`, `TestCIMDClientsAreResolvedThroughTheGuardOnlyWhenOn`, `TestARegisteredClientsKeysAreFetchedThroughTheGuard` |
| 5 | Per-client consent before the IdP redirect | `internal/broker/authorize.go` → `showConsent`; the IdP redirect only after Allow, or for a remembered consent, which the callback checks again for the user who signed in before issuing a code (`internal/broker/remember.go`) | `TestAuthorizeShowsTheConsentPageBeforeTheIdP`, `TestADifferentUserBehindAStaleHintGetsThePageAndNoCode`, `TestAnUnverifiedClientIsAskedEveryTime` |
| 6 | Audience validated; `iss` on authorization responses | Resource URL as associated data (`internal/token/token.go`); `iss` on success and error redirects (`internal/broker/authorize.go`) | `TestTokenForOneResourceNeverOpensForAnother`, `TestStaticClientSignsInWithEntraAndGetsAProxyToken` |
| 7 | Proxy tokens sealed by us, carry `exp`, never IdP tokens | `internal/token/token.go`. The upstream assertion half is **planned** (#62) | `TestTypesNeverCross`, `TestAnyTamperedByteIsRejected` |
| 8 | IdP refresh token stays in the broker, encrypted at rest | Sealed with the `idp-tokens` box (`internal/server/wire.go`, `internal/broker/authorize.go`) | `TestUnusableStoredIdPTokensRevokeTheGrant` |
| 9 | Codes single-use and short-lived; `/token` re-checks client, redirect URI and PKCE | `internal/broker/token.go` (`redeemCode`); 60 s lifetime | `TestReusedCodeRevokesTheGrant`, `TestTokenEndpointRechecks`, `TestFailedBindingAfterConsumeRevokesTheGrant`, `TestExpiredCodeIsRejected` |
| 10 | Exact redirect matching, only the loopback port varies | `internal/registration/redirect.go` | `TestMatchRedirect`, `FuzzMatchRedirect` |
| 11 | Keys from the operator, never derived or ephemeral; rotation keeps verify-only keys | `internal/token/keyring.go` (directory of key files; startup fails without one) | `TestMissingOrEmptyKeyDirectoryRefusesToStart`, `TestRotationKeepsOldTokensUntilTheirKeyIsRemoved` |
| 12 | Every relaxation is an explicit flag, logged at startup | `internal/config/config.go` (`Relaxations`), `cmd/byward/main.go` | `TestDevModeLogsEachRelaxation`, `TestNoAuthLogsThatAuthIsOffAndTheNextStep` |
| 13 | Legacy MCP sessions bound to the user; one upstream process per user | **Met for HTTP upstreams with authentication:** the upstream's `Mcp-Session-Id` is replaced by a sealed value bound to the user and the upstream; another user's, tampered or expired IDs get 404 and a `session_rejected` audit record (`internal/mcpsession`). Without authentication there is no user to bind to. **Met for stdio upstreams in the legacy era:** one process per MCP session, keyed by a proxy-issued session ID that is sealed the same way, and the process manager refuses a key bound to another user (`internal/upstream/stdio`). The modern era's one process per user is planned (#61). It holds at the wire level too: the relay never lets the upstream switch protocols (a client's `Upgrade` is dropped, an upstream's 101 is answered 502) and drops every upstream response trailer, and an informational (1xx) response carries only `Link` and the sealed session, so the upstream's `Mcp-Session-Id` never reaches the MCP client past the binding (`internal/upstream/relay/relay.go`, #168, #176) | `TestALegacySessionIsBoundToTheUserWhoStartedIt`, `TestAnUpstreamSessionSentAsATrailerNeverReachesTheClient`, `TestAnUpstreamsEarlyHintsReachTheClientSealedAndClean`, `TestRelayDropsUpstreamTrailers`, `TestAClientsUpgradeRequestNeverReachesTheUpstream`, `TestAnUpstreamThatSwitchesProtocolsGetsTheClientA502`, `TestAnUpstreamsEarlyHintsCarryOnlyLink`, `TestASessionThatIsNotTheCallersGets404AndNeverReachesTheUpstream`, `TestEachStdioMCPSessionIsItsOwnUpstreamProcessBoundToItsUserWithNoTokenOrProxySetting`, `TestKeyIsBoundToOneUser` |
| 14 | Size, time and count limits | Static clients file (1000 clients, 1 MiB); body limits; token length 2 KiB; consent answer table 10,000 | `TestLoadStaticRejects`, `TestBodyOverLimitIs413AndAtLimitPasses` |
| 15 | Errors never echo secrets or upstream internals | Fixed error strings (`internal/broker/token.go`); upstream errors become 502 `upstream unavailable` (`relay.go`), and an upstream that sends no headers in time a fixed JSON-RPC timeout error (`timeout.go`); panics give a bare 500 | `TestRelayHidesUpstreamErrors`, `TestStalledUpstreamIsAnsweredAndDropped`, `TestRecovererHidesPanicDetails`, `TestErrorPageEscapesInputAndIsLockedDown` |
| 16 | `ReverseProxy.Rewrite` only; identity and forwarding headers stripped; request trailers dropped | `internal/upstream/relay/relay.go` (`Authorization`, `Forwarded`, `Origin`, `X-Forwarded-*`, `Sec-Fetch-*`, matching `_` as `-`; every request trailer) | `TestRelayForwardsBodyVerbatimAndStripsProxyHeaders`, `TestAClientsRequestTrailersNeverReachTheUpstream` |
| 17 | `Origin` (403) and `Host` (421) before authentication; default bind `127.0.0.1` | `internal/origin/origin.go`, wired outermost in `internal/server/server.go`; default `127.0.0.1:8080` | `TestChecksRunBeforeAuthentication`, `TestHostOutsideAllowlistGets421`, `TestInternalListenerAcceptsAddressesAndListedNamesOnly`, `TestOriginOutsideAllowlistGets403`, `TestNewConfiguresHardenedLimitsAndLoopbackBind` |
| 18 | `http.Server` timeouts and `MaxHeaderBytes` set; latest Go patch; `govulncheck` green | `internal/server/run.go` (`hardened`); Go pinned in `mise.toml`, with a weekly `go-version.yml` check; `govulncheck` (pinned) runs for linux and darwin in `mise run check`, so in CI, and weekly | `TestNewConfiguresHardenedLimitsAndLoopbackBind`, `mise run vuln` |
| 19 | No own IdP credential on a caller's behalf; app-only tokens pinned | Holds trivially: `/token` offers no `client_credentials` or jwt-bearer grant, and app-only tokens are not accepted. App-only access is **planned** (#64) | `TestTokenEndpointRechecks` ("client credentials never") |

## Secure defaults

- **Authentication is on.** Without the Entra settings, `BYWARD_KEYS_DIR` and
  `BYWARD_STATIC_CLIENTS_FILE`, the proxy refuses to start (exit 2). It never silently runs
  without auth.
- Both listeners bind to loopback: public on `127.0.0.1:8080`, internal (metrics and probes) on
  `127.0.0.1:9090`. The two must differ.
- The public URL must be `https`. `http` is allowed only for a loopback host, with `--dev` or
  `--insecure-no-auth`.
- Secrets are read only from files (`*_FILE`, `--*-file`). An inline secret refuses to start
  unless `--dev` is set, and so does a secret file its group or others can read, unless it is on a
  read-only mount.
- The `Origin` allowlist on the MCP endpoint is empty: only the proxy's own origin and clients that
  send no `Origin` pass. No `X-Forwarded-For` is trusted until you set
  `BYWARD_TRUSTED_PROXIES`.
- Cookies are `__Host-`, `Secure`, `HttpOnly` and `SameSite=Lax` whenever the public URL is https.
- Unknown `BYWARD_*` variables, positional arguments, and a gate list that is set but empty
  all refuse to start.
- There is no telemetry or update check. Traces are off unless `OTEL_TRACES_EXPORTER` is set.
- The image runs as uid 65532 on distroless `static-debian13:nonroot`, pinned by digest
  ([ADR-0019](adr/0019-packaging.md)).

## Insecure modes

Each one is a named setting and is logged at **warning** level at every start, as
`development mode relaxation` with a `relaxation` field. The startup log also lists every effective
setting, with secrets shown as `<redacted>`.

| Mode | What it relaxes | Fences |
|---|---|---|
| `--dev` (`BYWARD_DEV`) | Accepts an `http` public URL on a loopback host. Over http, cookies drop `__Host-` and `Secure`. Accepts inline secrets from the environment. | `http` only on a loopback host; each relaxation is logged by name |
| `--insecure-no-auth` (`BYWARD_INSECURE_NO_AUTH`) | No authentication at all: no token check, no metadata, no broker routes | Public URL must be loopback. Listen address must be loopback, or inside a container with its own network namespace (host networking is detected and refused). Allowed hosts and origins must be loopback. It refuses to start alongside any authentication setting. Host and Origin checks, header stripping and body limits stay on. Logs `AUTHENTICATION IS OFF` and the next step ([ADR-0027](adr/0027-insecure-no-auth.md)). With a stdio upstream, anyone who can reach the proxy starts processes, bounded only by `BYWARD_STDIO_MAX_PROCESSES`, all as one anonymous user; logged as a warning ([stdio how-to](how-to/stdio-upstream.md#without-authentication)). |
| `BYWARD_GATE_ALLOW_EMPTY` | Allows an empty gate for Google or generic OIDC. It has **no effect with Entra**, the only IdP today. | Logged as a warning at every start |

An empty access gate with single-tenant Entra is allowed: every user of the tenant can sign in. It
is logged as a warning at every start.

## Token model

| Artifact | Form | Lifetime | Notes |
|---|---|---|---|
| Access token (`byw_at_…`) | Sealed AES-256-GCM, random 96-bit nonce; claims: grant ID, subject, `iat`, `exp`; key ID and format version in the header | 1 h, capped at the grant's expiry; 30 s clock leeway | Validated without a store read: open → time → deny list |
| Authorization code (`byw_ac_…`) | Sealed as above, plus a single-use row in the store | 60 s | Reuse, or redemption with the wrong client, redirect URI or verifier, revokes the grant |
| Refresh token (`byw_rt_…`) | 32 random bytes; only the SHA-256 hash is stored | 30 days absolute, 14 days idle | Issued only with `offline_access`. Rotated on every use. The previous token is accepted again within 30 s; any other reuse revokes the grant. Every refresh also refreshes the IdP tokens and re-runs the gate. |
| IdP tokens | Sealed with the same key ring, purpose `idp-tokens` as associated data | Up to the grant's expiry | Deleted with the grant. Never sent to the client. |
| Login and consent state | Sealed cookie and sealed form field | 10 min | `state` goes to the IdP only after Allow |

Lifetimes are constants in `internal/broker/broker.go`. ADR-0006 §5 allows configuring them within
bounds, but there are no settings for that yet.

**Revocation:**

- A revoked grant goes into an in-memory deny list. The list resyncs from the store every 5 s.
- A list more than 30 s stale **refuses every access token** (fail closed), and so does a list that
  has not synced yet (`internal/denylist/denylist.go`).
- `/revoke` revokes the whole grant, whichever of its tokens was sent. A store failure gets 503,
  never a false 200.
- The operator commands `byward revoke-user <tid:oid>` and `byward revoke-all --yes` delete the
  grants and record a cut-off in the store, beside a running proxy. Every proxy using the store
  refuses those users' tokens at its next sync (`internal/server/revoke.go`). A cut-off for every
  user is an explicit marker (`scope = 'all'`, checked by the database); a revocation naming
  nothing revokes nobody.
- No revocation request is sent to Entra; the IdP tokens are deleted and expire there.

**Dynamic client registration** ([DCR how-to](how-to/dcr.md), [ADR-0008](adr/0008-client-registration.md) §2–3, §8–10):

- `/register` is open to anyone who can reach the proxy, so a registration grants nothing by
  itself. Every sign-in by a DCR client shows the consent page and labels the app "Not verified",
  and the access gate still applies.
- Rate limit: 30 registrations per minute per address, with a burst of 10.
- Cap: 10,000 live registrations; beyond it, 503 with `Retry-After`.
- A registration never used to redeem a code is deleted after 24 h; a used one expires 90 days
  after its last use.
- No client secret is ever issued; redirect URIs follow ADR-0009, and failing ones are dropped.
- The operator's denylist (`BYWARD_CLIENT_DENYLIST`) refuses CIMD client IDs and redirect hosts at
  registration, `/authorize`, consent and `/token`.
- Every outcome, refusals included (invalid, rate-limited, capped, store failure), is audited
  (`client_registered`, rate-limited per address) and counted (`byward_dcr_registrations_total`).

**Sign-ins in flight** when a client changes: the client and its redirect URI are checked again at
consent and at `/token`, but not at the IdP callback, which relies on the sealed login cookie. If
the operator removes a redirect URI, denies its host, or a DCR registration expires after the user
answered consent, that sign-in still completes for up to 10 min (the login lifetime): the user is
returned to the old redirect URI with a code. `/token` then refuses the code, because it checks
the client and redirect URI again. This is accepted behaviour, not a gap: no token is issued.

**Remembered consent** ([ADR-0010](adr/0010-consent-screen.md) §2–3):

- Only clients whose identity is assured are remembered: static clients and CIMD hosts on
  `BYWARD_CIMD_TRUSTED_HOSTS`. Trust is read at every sign-in, so removing a host from that list
  makes its users answer again. Domain CIMD hosts and DCR clients are asked every time (ASVS 5.0.0
  10.7.1).
- The registry is in the store, per IdP user, client, redirect URI and resource, for 30 days from
  the Allow (not extended by use). A later request whose scopes are all approved counts as
  remembered; `prompt=consent` forces the page.
- Before the sign-in the user is unknown, so a sealed `__Host-` cookie (purpose `consent-hint`)
  names the user the browser last signed in as. It only lets `/authorize` skip the page. The
  callback checks the registry again for the user who actually signed in; on a different user, or
  consent forgotten in between, it issues nothing, clears the cookie and shows the page.
- Every revocation forgets: `/revoke`, refresh-token reuse, and `byward revoke-user` and
  `revoke-all` remove the matching rows in the same transaction as the grants.
- **Accepted: a local process can reuse a remembered loopback client.** A loopback redirect URI is
  remembered whatever its port, because ADR-0009 §2 lets the port vary (Claude Code picks a new one
  every run). So, for a remembered loopback client, a process on the user's machine that opens
  `/authorize` with that client ID and its own loopback port gets a code without a consent page;
  PKCE does not help, because that process chooses the verifier. Without remembered consent the
  page would at least show "Claude Code wants…" to a user who did not start it. This is accepted:
  local malware is outside the threat model, and it could read the client's own token store anyway.
  Operators who want the page every time for such clients can leave their CIMD host off
  `BYWARD_CIMD_TRUSTED_HOSTS`; a static client is always remembered.

**Keys:**

- Keys come from `BYWARD_KEYS_DIR`. The file that sorts last seals; every file opens.
  World-writable files are refused.
- One key ring seals access tokens, codes, IdP tokens, login cookies and consent flows. The purpose
  or token type is bound as associated data. ADR-0006 §8 asks for a separate key per purpose; that
  is a follow-up.
- Rotation is covered in [sealing keys](how-to/sealing-keys.md).

## Known gaps

| Gap | Effect | Tracking |
|---|---|---|
| ASVS 5.0.0 10.7.3 (user review and revocation of granted access) | Not met for users. The design leaves it to the operator (`byward revoke-user`, `byward revoke-all`) until a v0.2 "connected apps" page. | ADR-0010 §11; v0.2 |
| Consent answer table is per replica, in memory, capped at 10,000 | Double-submit protection holds within one process. A full table forgets the newest flow. It matters only with several replicas, which need v0.2's PostgreSQL. | No issue (`internal/broker/answers.go`) |
| Refresh drops the IdP's new tokens when sealing them fails | Kept when the gate cannot decide or the store fails to rotate (#92); a sealing failure leaves nothing safe to store. Fails closed: an unneeded sign-in with IdPs that revoke rotated refresh tokens. Entra is not affected. | `internal/broker/refresh.go` |
| Entra certificate credential | `private_key_jwt` exists in `internal/idp`, but no setting selects it; only a client secret is configurable | ADR-0012 §5 |

## Dependencies and supply chain

Direct modules (`go.mod`):

| Module | Version | Purpose |
|---|---|---|
| `github.com/go-jose/go-jose/v4` | v4.1.6 | Verifying IdP ID tokens, client assertions and the JWKS. The only JOSE/OIDC library: no go-oidc, no x/oauth2 ([ADR-0026](adr/0026-idp-adapters-go-jose-only.md)). |
| `golang.org/x/net` | v0.62.0 | `idna`: shows punycode on the consent page |
| `modernc.org/sqlite` | v1.61.0 | The pure-Go SQLite store (the default store). |
| `github.com/prometheus/client_golang` | v1.25.0 | `/metrics` |
| `go.opentelemetry.io/otel`, `…/sdk`, `…/trace`, `contrib/exporters/autoexport` | v1.47.0 / v0.72.0 | Traces, used only when `OTEL_TRACES_EXPORTER` is set |

Proxy-token cryptography is the Go standard library only: `crypto/aes`, `crypto/cipher` GCM,
`crypto/sha256` and `crypto/rand`.

**Build and release** (`.goreleaser.yaml`, `.github/workflows/release.yml`):

- Releases are built only from a `v*` tag.
- Signing is cosign keyless: the image by digest, and a bundle for `checksums.txt`.
- Each archive gets a syft SBOM. The image gets a buildx SBOM and provenance (`mode=max`).
- GitHub build-provenance attestations (`actions/attest`) cover the archives and the image.
- Builds use `-trimpath -buildvcs=true` and the commit timestamp. CI checks reproducibility with a
  rebuild (`reproducible.yml`).
- Actions are pinned by SHA and linted with actionlint and zizmor.
- Licence check: Apache-2.0, BSD, MIT and ISC only.
- OpenSSF Scorecard (`scorecard.yml`). Dependabot for Go modules, Actions and the base-image
  digest, with a 14-day cooldown.
- golangci-lint includes `gosec`.

Verification commands are in [packaging](reference/packaging.md#verifying-a-release). No release
has been published yet (#67).

## Reporting a vulnerability

Report privately through GitHub's
[Report a vulnerability](https://github.com/byward-dev/byward/security/advisories/new). Never
open a public issue. The first response comes within 14 days. Details, scope and supported versions
are in [SECURITY.md](../SECURITY.md).
