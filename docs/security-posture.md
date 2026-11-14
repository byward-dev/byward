# Security posture

For security reviewers. What byward guarantees, what it does not, and where each claim is
enforced and tested. This page describes `main` as of 2026-11-14: the v0.2 line (v0.2.0-rc.1 is
the latest release) plus the PostgreSQL store, which is not released yet. Items marked
**planned** are not built yet. Terms follow [CONTEXT.md](../CONTEXT.md). To deploy it, see
[Harden a deployment](how-to/harden-a-deployment.md).

## What it is

An **auth-only** proxy in front of one **upstream** MCP server. To MCP clients it acts as a
protected resource (RFC 9728) and as an OAuth 2.1 authorization server (the **broker**). It signs
users in at an **IdP** and then relays MCP traffic to the upstream
([ADR-0001](adr/0001-scope-auth-only-proxy-entra-first-class.md),
[ADR-0005](adr/0005-auth-modes-broker-only.md)). The IdP is Microsoft Entra ID (single-tenant) or any
OpenID Connect IdP ([OIDC how-to](how-to/oidc.md)), one per proxy.

**It guarantees:**

- Every MCP request carries a valid **proxy token** that the broker issued for this resource URL.
  Otherwise the request gets 401 and never reaches the upstream.
- Who may sign in at all is decided by the **access gate**. It runs at sign-in and at every
  refresh ([ADR-0015](adr/0015-access-gate.md)).
- The user approves each MCP client on a **consent** page before the IdP sign-in.
- No token the client sent is ever forwarded to the upstream.
- An HTTP upstream learns who the user is only from the **identity assertion**: a 60-second ES256
  JWT that the proxy signs, with `aud` = that upstream, on every request. A client cannot supply
  one; every copy of its header is removed first ([ADR-0016](adr/0016-identity-propagation.md),
  [reference](reference/identity-assertion.md)). A stdio upstream gets the user in its process
  environment instead. Its roles and groups are as of the last sign-in or refresh: at most one
  hour old.
- Plain identity headers (`X-Byward-*`) are off by default. When an operator turns them on, they
  carry the same values as the assertion, and a client's copies are always removed, also while
  they are off. They are safe only when the upstream is reachable through the proxy alone; the
  proxy cannot enforce that, and `doctor` only hints at it
  ([plain identity headers](how-to/plain-identity-headers.md)).
- The proxy's own Entra credential is exactly one of a certificate (recommended, ADR-0012 §5: an
  RSA key of 2048 bits or more that never leaves the proxy, `PS256` with `x5t#S256`), a federated
  token file or a client secret, each from a file the secret-file check guards; a certificate's end
  date is checked at startup and by `doctor` ([certificate how-to](how-to/entra-certificate.md)).
- An HTTP upstream that needs the proxy's own credential, such as an API key, gets the operator's
  value from a secret file, in a header the assertion does not use. A client cannot supply it, byward
  never sends it to a client, and it is never logged ([upstream credential](how-to/upstream-credential.md)).
- With On-Behalf-Of on, an HTTP upstream also gets a token for one configured downstream API, such
  as Microsoft Graph, exchanged for the user's stored Entra token. It travels in its own header,
  which a client can never supply, and is never stored or logged
  ([ADR-0017](adr/0017-delegation-obo.md), [how-to](how-to/downstream-apis.md)). A stdio process
  asks its own token socket for it instead: the socket answers only that process and its
  descendants, for the user it serves, and the token is never in its environment or any file. On a
  host whose ptrace restriction is off, another user's process could still read it from memory
  (see the stdio row under [Threat model](#threat-model)).

**It does not:**

- **Authorize tools or resources.** It has no per-tool rules and no `tools/list` filtering. Every
  user who passes the gate can call everything the upstream offers
  ([ADR-0015](adr/0015-access-gate.md) §6).
- **Inspect content.** MCP bodies are relayed byte for byte and never parsed. Prompt injection and
  tool poisoning are out of scope.
- **Verify the assertion for the upstream.** The upstream must check the signature, `aud` and `exp`
  itself. An upstream reachable other than through the proxy, that skips this, trusts whoever
  calls it.
- **Rate-limit MCP traffic.** Only the OAuth endpoints are rate-limited. MCP requests are only
  [capped in flight](reference/rate-limits.md#mcp-in-flight-caps).
- **Choose where TLS ends.** At your ingress or reverse proxy, or at byward with your certificate
  (`BYWARD_TLS_CERT_FILE`, see the threat model below; [ADR-0019](adr/0019-packaging.md) §9 as
  amended). byward never obtains a certificate itself.

## Threat model

| Threat | Protection | Where |
|---|---|---|
| Unauthenticated caller reaches the upstream | Every request to the MCP route passes the token guard. Tokens are read from `Authorization: Bearer` only. Methods other than GET, POST and DELETE get 405, and other paths never reach the upstream. | `internal/resource/resource.go` (Guard), `internal/server/server.go` (Handler, mcpMethods) |
| Another user's token, or a forged or altered one | Sealed tokens are AES-256-GCM. The resource URL and the token type are bound as associated data, and the token carries `exp`. Every failure looks the same (`invalid_token`). | `internal/token/token.go`, `internal/token/validator.go` |
| A malicious MCP client or app, or a confused deputy | Each client sees a consent page before the IdP sign-in. Only static clients and trusted CIMD hosts are remembered, for 30 days per user, client, redirect URI and resource; domain CIMD hosts and DCR clients are asked every time (see **Remembered consent** under [Token model](#token-model)). Redirect URIs match exactly, except the port on loopback, and are checked again at `/token`. PKCE S256 is required. A code is single-use and bound to its client. | `internal/broker/consent.go`, `internal/registration/redirect.go`, `internal/broker/token.go` |
| Token theft | Access tokens last 1 h. Refresh tokens rotate on every use, and reuse after the 30 s grace revokes the grant. A refresh token works only for the client it was issued to. Clients can revoke with `/revoke` (RFC 7009). | `internal/broker/refresh.go`, `internal/broker/revoke.go` |
| CSRF or clickjacking on consent | The answer needs exactly one `Origin` equal to the public origin; a missing or `null` Origin is refused. `Sec-Fetch-Site` must be `same-origin` when the browser sends it. A `__Host-` binding cookie and a sealed flow that expires after 10 min are required. Allow is refused within 1 s of showing the page. Every page sends CSP `frame-ancestors 'none'`, `X-Frame-Options: DENY` and `script-src 'none'`. | `internal/broker/consent.go`, `internal/broker/page.go` |
| A browser downgraded to http on the sign-in and consent pages (SSL stripping) | With an `https` public URL, every answer of the public listener carries `Strict-Transport-Security: max-age=31536000`, whether TLS ends at byward or at an ingress. It is decided from `BYWARD_PUBLIC_URL` alone, never from the request (`r.TLS`, `X-Forwarded-Proto`). There is no `includeSubDomains` or `preload`, since byward does not own the parent domain. An upstream's own `Strict-Transport-Security` is dropped, so the proxy's is the one browsers keep (RFC 6797 §8.1). None over an `http` public URL (`--dev`), and none on the internal listener. | `internal/server/hsts.go`, `internal/upstream/relay/relay.go` |
| Eavesdropping on the hop from the ingress to the proxy | That hop carries bearer tokens. Either keep it private, or have byward terminate TLS with the operator's certificate (`BYWARD_TLS_CERT_FILE`, `BYWARD_TLS_KEY_FILE`). TLS 1.2 or later. The key file passes the secret-file permission check. A replaced pair is served from the next handshake, never one that does not load, match or validate, and no certificate in the chain may be expired or not yet valid. Startup refuses a pair it cannot serve, and an `http` public URL with TLS on. It warns 30 days before the chain's first expiry and when the certificate covers none of the proxy's hosts; `doctor` reports the files on disk. The issuer, cookies and HSTS still come from `BYWARD_PUBLIC_URL` alone. No ACME. An ingress that does not verify the certificate gets encryption without authentication ([Serve TLS at the proxy](how-to/tls.md)). | `internal/servingcert`, `internal/server/wire_tls.go`, `internal/config/config_tls.go` |
| DNS rebinding and cross-site requests to the MCP endpoint | `Host` is checked against an allowlist on the public listener (421), and on the internal listener only IP addresses, `localhost` and listed names pass (421). `Origin` on the MCP endpoint is checked against an exact list (403). Both checks run before authentication. | `internal/origin/origin.go` |
| SSRF | Client-supplied URLs (CIMD documents, and the `jwks_uri` of CIMD and DCR clients) are fetched only through the SSRF guard: `https` on port 443, public addresses only, checked when the connection is dialled (after DNS resolution, so a rebinding name cannot slip through), no redirects, no environment proxy, 5 KB and 5 s ([ADR-0008](adr/0008-client-registration.md) §4). Static clients have no `jwks_uri`. Entra endpoints are built from the fixed `https://login.microsoftonline.com` authority and the configured tenant. An OIDC IdP's endpoints come from the discovery document of the configured issuer, whose `issuer` must match exactly; the issuer and every endpoint must be `https` outside `--dev`. The IdP is the operator's, so it is reached directly, not through the SSRF guard: a self-hosted IdP on a private address works. The IdP fetcher follows no redirects, bounds bodies and times out after 5 s. Every outbound TLS connection, the guard's included, trusts Go's system roots, which take any CA the operator adds through `SSL_CERT_FILE` or `SSL_CERT_DIR` ([private CA](how-to/private-ca.md)). | `internal/ssrfguard`, `internal/server/wire.go`, `internal/idp/fetch.go`, `internal/idp/entra/entra.go` |
| Abuse of OAuth endpoints | Per-address token buckets apply on `/authorize`, `/consent`, `/callback/{idp}`, `/token`, `/revoke` and `/register`, with IPv6 grouped by /64. Open registration has its own controls (**Dynamic client registration** under [Token model](#token-model)). Request bodies are bounded. Every `http.Server` timeout is set. | `internal/ratelimit`, `internal/broker/register.go`, `internal/server/run.go` |
| Eavesdropping on the hop to an HTTP upstream | The proxy accepts an `http` upstream, so a deployment on a private network needs no certificate. Startup and `byward doctor` warn when the upstream is `http` at a public address (`check --offline` when it is given as one), and name the secrets that would travel in clear (the identity assertion, the upstream credential, an On-Behalf-Of token). A private address is not checked further: the operator keeps the hop private ([Harden a deployment](how-to/harden-a-deployment.md#protect-the-upstream-hop)). An upstream redirect is answered with 502, never passed to the MCP client, so a client is not sent to the upstream's own address. `doctor` names an environment HTTP proxy the hop goes through. | `internal/server/upstreamhop.go`, `internal/upstream/relay/relay.go` |
| Eavesdropping on, or impersonation of, the PostgreSQL store; a restored copy of it | With `BYWARD_STORE_POSTGRES_DSN_FILE`, the connection must be `sslmode=verify-full` for every host: the server's name and chain are checked, and plaintext, a Unix socket and the weaker modes are refused at startup, judged after pgx has read its `PG*` environment and files (only `--dev` relaxes this). The DSN is a secret file, never logged or quoted in an error. A database restored from an older copy is found while the replicas run, and a new store epoch refuses the refresh tokens it brought back ([ADR-0007](adr/0007-state-and-storage.md), #227 amendment). | `internal/store/postgres/dsn.go`, `internal/store/postgres/restore.go` |
| One user's stdio upstream process reads another user's data | Each legacy MCP session, or each user in the 2026-07-28 era, gets its own process, and `{session_dir}` gives each process its own directory (invariant 13). **This is a separation, not a sandbox:** every process runs as byward's own uid. Any upstream process can read another's files and its environment (`/proc/<pid>/environ` needs only the same uid), and, on a host that allows ptrace between processes of one uid (`kernel.yama.ptrace_scope` 0), its memory. The operator closes the memory path with `ptrace_scope` 1 or higher and runs untrusted upstream servers in their own container or VM ([Harden a deployment](how-to/harden-a-deployment.md#isolate-stdio-upstream-processes)). | `internal/upstream/stdio` |

**Out of scope:** a compromised upstream, which receives every MCP request and answer. Also out of
scope: a compromised host or container runtime, where the sealing keys, secret files and process
memory are readable. And a compromised IdP or IdP tenant admin.

## Security invariants

Every change must keep these invariants (AGENTS.md, CONTRIBUTING.md); this table is their only full
list. Status on `main`:

| # | Invariant | Enforced in | Tested by |
|---|---|---|---|
| 1 | No token passthrough to the upstream. | `internal/upstream/relay/relay.go` (`strip` removes `Authorization` and `DPoP`, the proof bound to the client's token; `access_token` dropped from the query). A stdio upstream gets only the JSON-RPC body on stdin, and an environment of an allowlist, the operator's env file and the user's key (`internal/upstream/stdio/command.go`) | `TestRelayForwardsBodyVerbatimAndStripsProxyHeaders`, `TestValidTokenIsRelayedWithoutIt`, `TestEachStdioMCPSessionIsItsOwnUpstreamProcessBoundToItsUserWithNoTokenOrProxySetting`, `TestUpstreamGetsOnlyAllowlistOperatorEnvAndIdentity`, `TestAClientCannotSupplyTheAssertionHeader`, `TestWithoutAuthenticationTheUpstreamGetsOnlyTheOperatorCredential`, `TestWithPlainIdentityHeadersOffAClientsCopiesAreStillRemoved` |
| 2 | Never log tokens, secrets, authorization codes or PKCE verifiers. | `internal/logging/logging.go` (attribute allowlist, bearer/JWT-shaped redaction); `internal/audit` (no credential fields); OpenTelemetry's own logger logs its message only, never the `OTEL_*` value it rejected, and an SDK setting OTel rejects is logged by name only (`internal/tracing`; one known gap below) | `TestRedaction`, `TestMiddlewareLogsRequestWithoutQueryOrHeaders`, `TestAuditRecordsMatchTheGoldenSchema`, `TestAnOTELSettingTheExporterRejectsIsLoggedWithoutItsValue`, `TestAnSDKSettingOTELRejectsIsLoggedByNameWithoutItsValue` |
| 3 | Named IdP endpoints come from config, never overridable. | `internal/idp/entra/entra.go` (`endpoint`: the fixed authority `https://login.microsoftonline.com` plus the tenant GUID; discovery is read only to check the issuer); `internal/idp/oidc/oidc.go` (`discover`: the endpoints of the configured issuer's discovery document, whose `issuer` must match exactly, `https` outside `--dev`); the IdP is chosen only by `BYWARD_IDP` | `TestAuthCodeURLTargetsTenantAuthorizeWithAccessAsUserScope`, `TestIssuerMustMatchTokenTenantAndAllowlist`, `TestDiscoveryIssuerMustMatchExactly`, `TestDiscoveredEndpointsMustBeHTTPSUnlessALoopbackIssuerRunsInDevelopment`, `TestAnHTTPIssuerNeedsDevelopmentMode` |
| 4 | Client-supplied URLs are fetched only through the SSRF guard. | `internal/ssrfguard` (dial-time address check); `internal/server/wire.go` builds one guard and `wire_clients.go` gives it to the CIMD registry (documents and `jwks_uri`) and the DCR registry (`jwks_uri`) | `TestNonPublicAddressesAreRefused`, `TestRedirectsAreNotFollowed`, `TestTheGuardedHTTPClientRefusesPrivateAddresses`, `TestCIMDClientsAreResolvedThroughTheGuardOnlyWhenOn`, `TestARegisteredClientsKeysAreFetchedThroughTheGuard` |
| 5 | Per-client consent before the IdP redirect. | `internal/broker/authorize.go` → `showConsent`; the IdP redirect only after Allow, or for a remembered consent, which the callback checks again for the user who signed in before issuing a code (`internal/broker/remember.go`) | `TestAuthorizeShowsTheConsentPageBeforeTheIdP`, `TestADifferentUserBehindAStaleHintGetsThePageAndNoCode`, `TestAnUnverifiedClientIsAskedEveryTime` |
| 6 | Audience validated; authorization responses carry `iss`. | Resource URL as associated data (`internal/token/token.go`); `iss` on success and error redirects (`internal/broker/authorize.go`) | `TestTokenForOneResourceNeverOpensForAnother`, `TestStaticClientSignsInWithEntraAndGetsAProxyToken` |
| 7 | Proxy tokens are sealed by us (AEAD; key ID from our key ring; resource URL and token type as associated data), carry `exp`, and are never IdP tokens; assertions to the upstream are JWTs with `aud` = that upstream and a `kid` in our JWKS (ADR-0016). | `internal/token/token.go`; assertions: `internal/assertion` (ES256, `aud` = the upstream, `kid` in our JWKS) | `TestTypesNeverCross`, `TestAnyTamperedByteIsRejected`, `TestTheUpstreamGetsAnAssertionItCanVerifyInsteadOfTheClientsToken`, `TestGoSDKBearerMiddlewareAcceptsTheAssertion` |
| 8 | The IdP refresh token never leaves the **broker** and is encrypted at rest. | Sealed with the `idp-tokens` box (`internal/server/wire_parts.go`, `internal/broker/authorize.go`) | `TestUnusableStoredIdPTokensRevokeTheGrant` |
| 9 | Authorization codes are single-use and short-lived; `/token` re-checks `client_id`, `redirect_uri`, PKCE. | `internal/broker/token.go` (`redeemCode`); 60 s lifetime | `TestReusedCodeRevokesTheGrant`, `TestTokenEndpointRechecks`, `TestFailedBindingAfterConsumeRevokesTheGrant`, `TestExpiredCodeIsRejected` |
| 10 | Exact redirect matching; only the loopback port may vary. | `internal/registration/redirect.go` | `TestMatchRedirect`, `FuzzMatchRedirect` |
| 11 | Keys come from the operator; never derived from the IdP client secret; never ephemeral across replicas; rotation keeps verify-only keys. | `internal/token/keyring.go` (directory of key files; startup fails without one) | `TestMissingOrEmptyKeyDirectoryRefusesToStart`, `TestRotationKeepsOldTokensUntilTheirKeyIsRemoved` |
| 12 | Every relaxation is an explicit flag, logged at startup. | `internal/config/config.go` (`Relaxations`), `cmd/byward/main.go` (startup), `cmd/byward/operate.go` (`check --offline`) | `TestDevModeLogsEachRelaxation`, `TestDevModeLogsAnHTTPIdPIssuerOnLoopback`, `TestNoAuthLogsThatAuthIsOffAndTheNextStep`, `TestCheckOfflinePrintsEachRelaxationFirst` |
| 13 | Legacy MCP sessions are bound to the user (ADR-0004); an upstream process never serves more than one user (ADR-0003). | **Met for HTTP upstreams with authentication:** the upstream's `Mcp-Session-Id` is replaced by a sealed value bound to the user and the upstream; another user's, tampered or expired IDs get 404 and a `session_rejected` audit record (`internal/mcpsession`). It holds at the wire level too: the relay never lets the upstream switch protocols (a client's `Upgrade` is dropped; an upstream's 101 is answered 502, and an HTTP/2 upstream's interim 101 is dropped) and drops every upstream response trailer, so the upstream's `Mcp-Session-Id` never reaches the MCP client past the binding; an informational (1xx) response carries only `Link` and the sealed `Mcp-Session-Id`, and the proxy's own headers (CORS, `X-Request-Id`) still reach the final response after one (`internal/upstream/relay/relay.go`, #168, #176). Without authentication there is no user to bind to. **Met for stdio upstreams in the legacy era:** one process per MCP session, keyed by a proxy-issued session ID that is sealed the same way, and the process manager refuses a key bound to another user (`internal/upstream/stdio`). **Met for stdio in the modern era:** one process per user (keyed by issuer and subject); requests of the user's several clients share it under proxy-assigned ids and progress tokens, so answers reach only their own stream, and ambiguous JSON is refused (`internal/upstream/stdio/modern.go`, `rewrite.go`) | `TestALegacySessionIsBoundToTheUserWhoStartedIt`, `TestAnUpstreamSessionSentAsATrailerNeverReachesTheClient`, `TestRelayDropsUpstreamTrailers`, `TestAClientsUpgradeRequestNeverReachesTheUpstream`, `TestAnUpstreamThatSwitchesProtocolsGetsTheClientA502`, `TestAnUpstreamsInformationalResponsesCarryOnlyLinkAndTheSession`, `TestTheProxysOwnHeadersSurviveAnUpstreamsInformationalResponse`, `TestTheProxysOwnHeadersSurviveATimeoutAfterAnInformationalResponse`, `TestAnInterimSwitchingProtocolsIsNeverForwarded`, `TestAnUpstreamsEarlyHintsReachTheClientSealedAndClean`, `TestASessionThatIsNotTheCallersGets404AndNeverReachesTheUpstream`, `TestEachStdioMCPSessionIsItsOwnUpstreamProcessBoundToItsUserWithNoTokenOrProxySetting`, `TestKeyIsBoundToOneUser`, `TestModernEraRequestsRunInTheUsersOwnUpstreamProcessWithNoToken`, `TestConcurrentClientsOfOneUserGetOnlyTheirOwnResponsesAndProgress`, `FuzzLocateAndReplace` |
| 14 | Size, time and count limits on registration, CIMD and the store. | Static clients file (1000 clients, 1 MiB); body limits; token length 16 KiB; consent answer table 10,000 | `TestLoadStaticRejects`, `TestBodyOverLimitIs413AndAtLimitPasses` |
| 15 | Errors never echo secrets or upstream internals. | Fixed error strings (`internal/broker/token.go`); upstream errors and redirects become 502 `upstream unavailable` (`relay.go`), and an error through an environment proxy whose setting Go misread is reported by its cause, never quoting the address Go dialled from the credentials: the relay's logs, every IdP call (`internal/idp`, through `envproxy.Redact`), doctor's self-probe and trace export errors (`internal/tracing`), and an upstream that sends no headers in time a fixed JSON-RPC timeout error (`timeout.go`); panics give a bare 500 | `TestRelayHidesUpstreamErrors`, `TestAMisreadProxySettingNeverReachesTheUpstreamErrorLogAndAWellFormedProxysErrorStillDoes`, `TestATransportErrorThroughAMisreadProxySettingNeverQuotesItsAddress`, `TestTheIdPClientNeverQuotesAMisreadEnvironmentProxy`, `TestDoctorsSelfProbeNeverQuotesAMisreadEnvironmentProxyAndTheUpstreamLineWarnsOfIt`, `TestAFailedTraceExportNeverQuotesAMisreadEnvironmentProxy`, `TestAnUpstreamRedirectGetsTheClientA502AndTheLogWhereItPointed`, `TestStalledUpstreamIsAnsweredAndDropped`, `TestRecovererHidesPanicDetails`, `TestErrorPageEscapesInputAndIsLockedDown` |
| 16 | The reverse proxy uses `httputil.ReverseProxy.Rewrite`, never `Director`; identity, forwarding, authorization (with `DPoP`), downstream-token and operator-listed headers are stripped before ours are set, and an MCP client's request trailers never reach the upstream (ADR-0016, ADR-0018). | `internal/upstream/relay/relay.go` (`Authorization`, `DPoP`, `Forwarded`, `Origin`, `X-Forwarded-*`, `Sec-Fetch-*`, and the operator's `BYWARD_UPSTREAM_STRIP_HEADERS`, matching `_` as `-`; every request trailer). The operator's list may not name a header MCP needs (`internal/config/config_upstream.go`) | `TestRelayForwardsBodyVerbatimAndStripsProxyHeaders`, `TestAClientsRequestTrailersNeverReachTheUpstream`, `TestATrailerNamedLikeAProxySetHeaderNeverReachesTheUpstream`, `TestAnOperatorListedHeaderNeverReachesTheUpstreamInAnySpellingAndEveryOtherHeaderStillDoes`, `TestAListedHeaderNeverReachesTheUpstreamButTheProxysCredentialStillDoes`, `TestTheUpstreamStripListRefusesWhatCannotBeStripped` |
| 17 | The MCP endpoint checks `Origin` (403) and `Host` (421) before authentication; the default bind is `127.0.0.1` (ADR-0018). | `internal/origin/origin.go`, wired outermost in `internal/server/server.go`; default `127.0.0.1:8080` | `TestChecksRunBeforeAuthentication`, `TestHostOutsideAllowlistGets421`, `TestInternalListenerAcceptsAddressesAndListedNamesOnly`, `TestOriginOutsideAllowlistGets403`, `TestNewConfiguresHardenedLimitsAndLoopbackBind` |
| 18 | Every `http.Server` timeout and `MaxHeaderBytes` is set; builds use the latest Go patch release; `govulncheck` is green (ADR-0018). | `internal/server/run.go` (`hardened`); Go pinned in `mise.toml`, with a weekly `go-version.yml` check; `govulncheck` (pinned) runs for linux and darwin in `mise run check`, so in CI, and weekly | `TestNewConfiguresHardenedLimitsAndLoopbackBind`, `mise run vuln` |
| 19 | The proxy never sends its own IdP credential on a caller's behalf; app-only tokens are accepted only with a pinned issuer and audience, `idtyp=app` and a required app role (ADR-0022). | `/token` offers no `client_credentials`, jwt-bearer or token-exchange grant (`internal/broker/token.go`). App-only tokens, opt-in (`BYWARD_APP_TOKENS=entra`), are chosen by format, never by fallback (`resource.Dispatch`), and checked with a pinned issuer, audience, `RS256`, `typ: JWT`, `idtyp=app`, no `scp` and a required app role on every request (`internal/idp/entra/app.go`, `internal/gate/app.go`, `internal/apptoken`) | `TestTokenEndpointRechecks`, `TestAnAppTokenIsRefusedAtEveryOAuthEndpoint`, `TestTheValidatorIsChosenByFormatAndNeverFallsBack`, `FuzzTheValidatorIsChosenByFormatAndNeverFallsBack`, `TestAnAppOnlyTokenFailingAnyCheckIsRefused`, `TestAUsersEntraTokenIsRefusedAtTheMCPEndpoint`, `TestAnAppWithoutTheRoleIsForbiddenAndNeverReachesTheUpstream` |

## Secure defaults

- **Authentication is on.** Without an IdP configured (Entra or an `oidc` IdP) and a sealing key, the
  proxy refuses to start (exit 2). It never silently runs without auth; only the explicit
  `BYWARD_INSECURE_NO_AUTH` turns it off, on loopback.
- Both listeners bind to loopback: public on `127.0.0.1:8080`, internal (metrics and probes) on
  `127.0.0.1:9090`. The two must differ.
- The public URL must be `https`. `http` is allowed only for a loopback host, with `--dev` or
  `--insecure-no-auth`.
- Secrets are read only from files (`*_FILE`, `--*-file`). An inline secret refuses to start
  unless `--dev` is set, and so does a secret file (a setting's `*_FILE`, or the TLS key; not a sealing
  key) its group or others can read, unless it is on a read-only mount.
- The `Origin` allowlist on the MCP endpoint is empty: only the proxy's own origin and clients that
  send no `Origin` pass. No `X-Forwarded-For` is trusted until you set
  `BYWARD_TRUSTED_PROXIES`.
- Cookies are `__Host-`, `Secure`, `HttpOnly` and `SameSite=Lax` whenever the public URL is https.
- Unknown `BYWARD_*` variables, positional arguments, and a gate list that is set but empty
  all refuse to start.
- The identity assertion carries an opted-in `email` only when the IdP verified it
  (`email_verified: true`), with `email_verified` beside it; Entra never verifies one, so by default
  no Entra email is asserted ([ADR-0016](adr/0016-identity-propagation.md), 2026-11-07 amendment).
- There is no telemetry or update check. Traces are off unless `OTEL_TRACES_EXPORTER` is set.
- The image runs as uid 65532 on distroless `static-debian13:nonroot`, pinned by digest
  ([ADR-0019](adr/0019-packaging.md)).

## Insecure modes

Each one is a named setting and is logged at **warning** level at every start: `--dev` and
`--insecure-no-auth` as `development mode relaxation` with a `relaxation` field (also printed by
`byward check --offline`), the other two as their own warnings. The startup log also lists every effective
setting, with secrets shown as `<redacted>`.

| Mode | What it relaxes | Fences |
|---|---|---|
| `--dev` (`BYWARD_DEV`) | Accepts an `http` public URL on a loopback host; over http, cookies drop `__Host-` and `Secure`. Accepts an `http` OIDC issuer on a loopback host, and the endpoints it lists over `http` on loopback, the IdP's sign-in page included. Accepts inline secrets from the environment. Skips the secret file permission check. Lets the PostgreSQL store connect without `verify-full` TLS. | `http` (the public URL, the IdP issuer and its endpoints) only on a loopback host; inline secrets, file permissions and PostgreSQL TLS are not fenced. Each relaxation is logged by name at every start and printed by `byward check --offline` |
| `--insecure-no-auth` (`BYWARD_INSECURE_NO_AUTH`) | No authentication at all: no token check, no metadata, no broker routes | Public URL must be loopback. Listen address must be loopback, or inside a container with its own network namespace (host networking is detected and refused). Allowed hosts and origins must be loopback. It refuses to start alongside any authentication setting. Host and Origin checks, header stripping and body limits stay on. Logs `AUTHENTICATION IS OFF` and the next step ([ADR-0027](adr/0027-insecure-no-auth.md)). With a stdio upstream, anyone who can reach the proxy starts processes, bounded only by `BYWARD_STDIO_MAX_PROCESSES`, all as one anonymous user; logged as a warning ([stdio how-to](how-to/stdio-upstream.md#without-authentication)). |
| `BYWARD_ASSERTION_UNVERIFIED_EMAIL` | With `email` in `BYWARD_ASSERTION_CLAIMS`, asserts an email the IdP has not verified (every Entra email), marked `email_verified: false` | Logged as a warning at every start; the upstream must never authorize on `email` |
| `BYWARD_GATE_ALLOW_EMPTY` | Allows an empty gate for an OIDC IdP, where anyone with an account could sign in. It has **no effect with Entra**. | Logged as a warning at every start |

An empty access gate with single-tenant Entra is allowed: every user of the tenant can sign in. It
is logged as a warning at every start.

## Token model

| Artifact | Form | Lifetime | Notes |
|---|---|---|---|
| Access token (`byw_at_…`) | Sealed AES-256-GCM, random 96-bit nonce; claims: grant ID, subject, `iat`, `exp`, and the client ID and the asserted roles, groups, email (with whether it is verified) and name when there are any; key ID and format version in the header. The client holds it but cannot read it | 1 h, capped at the grant's expiry; 30 s clock leeway | Validated without a store read: open → time → deny list |
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
- The operator commands `byward revoke-user <user key>` and `byward revoke-all --yes` delete the
  grants and record a cut-off in the store, beside a running proxy. Every proxy using the store
  refuses those users' tokens at its next sync (`internal/server/revoke.go`). A cut-off for every
  user is an explicit marker (`scope = 'all'`, checked by the database); a revocation naming
  nothing revokes nobody.
- No revocation request is sent to Entra; the IdP tokens are deleted and expire there.

**Dynamic client registration** ([DCR how-to](how-to/dcr.md), [ADR-0008](adr/0008-client-registration.md) §2–3, §8–10):

- `/register` is open to anyone who can reach the proxy, so a registration grants nothing by
  itself. Every sign-in by a DCR client shows the consent page and labels the app "Not verified",
  and the access gate still applies.
- Rate limit: per address, with a burst ([budgets](reference/rate-limits.md#budgets)).
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
- **Silent sign-in (`prompt=none`, OIDC Core §3.1.2.1) never shows the page.** It proceeds only on
  a remembered consent for the user the hint names, and then asks the IdP with its own
  `prompt=none`. Anything else is an OAuth error at the validated redirect URI, with `state` and
  `iss`: `consent_required` for a client asked every time or with no consent covering the request;
  `login_required` without a hint, because nothing goes to the IdP before consent is established
  (ADR-0010 §1); the IdP's own `login_required`, `interaction_required`, `consent_required` or
  `account_selection_required` as it sent them; and `consent_required` when someone else signs in
  behind the hint (nothing issued, the hint cleared). Every refusal is audited (`consent_silent`).
  - The different answers for "no hint" and "a hint but no consent" are not an oracle: the
    request runs in the user's own browser with the user's own hint cookie (`SameSite=Lax`, so a
    cross-site frame never carries it), and the answer goes only to a redirect URI the client
    registered. Only the client learns it, or, for a loopback client, any local process (see the
    accepted local-process item below), and only that this browser's user has not approved it,
    which a page would have shown it too. A third-party site
    can start the request but cannot read where it ends. A client asked every time always gets
    `consent_required`, whatever is remembered. `/authorize`'s rate limit applies before any of
    this.
  - After the IdP, a silent sign-in never ends on a page either: an access-gate denial is
    `access_denied` naming no rule (still audited as `access_denied`), any other IdP failure is
    `server_error` or `temporarily_unavailable`, and a store failure while re-checking the consent
    is `temporarily_unavailable` and keeps the hint.
  - A silent IdP round trip without a hint (for browsers that lost the cookie) is not built; it
    would send the user to the IdP before consent is known. Later, if a real client needs it.
  - **A login is single use on the server too (#150).** The sealed login cookie holds the sign-in
    in progress; every callback that opens it records a hash of its IdP state in the store
    (`spent_logins`, kept for the login lifetime, 10 minutes) before calling the IdP, and refuses
    a second use with "This sign-in has expired." So a kept copy of the cookie cannot finish a
    sign-in twice, including after a rate-limited silent callback that answered
    `temporarily_unavailable`. If the store cannot record the login, the callback stops: a page,
    or `temporarily_unavailable` for a silent sign-in. Accepted: during such a store outage the
    login stays unrecorded, so a client that kept the HttpOnly `__Host-` cookie after being told to
    delete it could finish that sign-in once the store is back; it needs both the outage and that
    client.
- **Accepted: a local process can reuse a remembered loopback client.** A loopback redirect URI is
  remembered whatever its port, because ADR-0009 §2 lets the port vary (Claude Code picks a new one
  every run). So, for a remembered loopback client, a process on the user's machine that opens
  `/authorize` with that client ID and its own loopback port gets a code without a consent page;
  PKCE does not help, because that process chooses the verifier. Without remembered consent the
  page would at least show "Claude Code wants…" to a user who did not start it. This is accepted:
  local malware is outside the threat model, and it could read the client's own token store anyway.
  With `prompt=none` such a process also learns, without any page, whether the user has a
  remembered consent for that client (a page used to show when they had not).
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
| Consent answer table is per replica, in memory, capped at 10,000 | Double-submit protection holds within one process. A full table forgets the newest flow. It matters only with several replicas, on the PostgreSQL store. | No issue (`internal/broker/answers.go`) |
| Refresh drops the IdP's new tokens when sealing them fails | Kept when the gate cannot decide or the store fails to rotate (#92); a sealing failure leaves nothing safe to store. Fails closed: an unneeded sign-in with IdPs that revoke rotated refresh tokens. Entra is not affected. | `internal/broker/refresh.go` |
| A span limit setting that is not a number is printed with its value | `go.opentelemetry.io/auto/sdk` v1.2.1 (`limit.go`), linked in through `go.opentelemetry.io/otel`, reads `OTEL_ATTRIBUTE_COUNT_LIMIT`, `OTEL_ATTRIBUTE_VALUE_LENGTH_LIMIT` and the `OTEL_SPAN_*`, `OTEL_EVENT_*` and `OTEL_LINK_*` limits when the process starts, even with tracing off. It warns about a non-integer value, value included, through Go's default logger to stderr, before byward can install its own logger. These settings hold numbers; a credential lands there only if pasted into the wrong one. | Upstream: [open-telemetry/opentelemetry-go-instrumentation#3952](https://github.com/open-telemetry/opentelemetry-go-instrumentation/issues/3952); found in #274 |
| One key ring for every purpose | Access tokens, codes, IdP tokens, login cookies and consent flows are sealed with the same keys, each purpose bound as associated data. ADR-0006 §8 asks for a separate key per purpose. | ADR-0006 §8 (Keys, above) |
| Token lifetimes are fixed | Access token 1 h, refresh token 30 days absolute and 14 days idle, codes 60 s: constants, with no setting, although ADR-0006 §5 allows configuring them within bounds. | ADR-0006 §5; `internal/broker/broker.go` |
| Failed client authentication is not throttled per client | The `/token` limit is per address only; a client secret or client assertion guessed from many addresses is limited by the address budgets alone. | [Rate limits](reference/rate-limits.md) |
| stdio upstream processes share byward's uid | One user's process can read another user's files and environment, and on a `ptrace_scope` 0 host their memory. byward offers no per-user uid or sandbox for them; the operator isolates by host settings and separate containers or VMs. | #182 |

## Dependencies and supply chain

Direct modules (`go.mod`):

| Module | Version | Purpose |
|---|---|---|
| `code.dny.dev/ssrf` | v0.3.0 | The SSRF guard's dial-time address check for client-supplied URLs (`internal/ssrfguard`) |
| `github.com/go-jose/go-jose/v4` | v4.1.6 | Verifying IdP ID tokens, client assertions and the JWKS. The only JOSE/OIDC library: no go-oidc, no x/oauth2 ([ADR-0026](adr/0026-idp-adapters-go-jose-only.md)). |
| `golang.org/x/net` | v0.62.0 | `idna`: shows punycode on the consent page |
| `modernc.org/sqlite` | v1.61.0 | The pure-Go SQLite store (the default store). |
| `github.com/jackc/pgx/v5` | v5.12.0 | The PostgreSQL store, for several replicas (`internal/store/postgres`) |
| `golang.org/x/sys` | v0.49.0 | The peer credentials of a stdio process asking the token socket (`internal/upstream/stdio`) |
| `github.com/go-logr/logr` | v1.4.4 | Routes the tracing SDK's own errors into byward's log (`internal/tracing`) |
| `github.com/modelcontextprotocol/go-sdk` | v1.8.0 | Tests only: the real-client and assertion-contract tests |
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

Verification commands are in [packaging](reference/packaging.md#verifying-a-release); releases
are on [GitHub](https://github.com/byward-dev/byward/releases).

## Reporting a vulnerability

Report privately through GitHub's
[Report a vulnerability](https://github.com/byward-dev/byward/security/advisories/new). Never
open a public issue. The first response comes within 14 days. Details, scope and supported versions
are in [SECURITY.md](../SECURITY.md).
