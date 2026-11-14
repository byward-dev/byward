# ADR-0017: Delegation — proxy-side Entra On-Behalf-Of in v0.1

- Status: Accepted; amended 2026-11-06 (release), 2026-11-07, 2026-11-08 (#195, #141)
- Date: 2026-11-06
- Issue: #15 (F14)

## Context

ADR-0001 names On-Behalf-Of to downstream APIs as part of the Entra differentiator. Microsoft Learn
(OBO flow, updated 2026-06-15): the assertion "must have an audience (`aud`) claim of the app making
this OBO request"; OBO "only works for user principals"; a refresh token is returned only with
`offline_access`; Conditional Access challenges come back as `interaction_required` (AADSTS50079) with a
`claims` value. ADR-0012 already stores, encrypted, the access token for our own `access_as_user` scope.
The real-tenant test (2026-11-05) showed that token works as an OBO assertion for Graph `User.Read` once
Graph is consented (AADSTS65001 before), while a Graph token fails (AADSTS50013).

Competitors (source): agentgateway exchanges proxy-side (RFC 8693 / jwt-bearer) with a cache of 8192
entries capped at the subject token's expiry; FastMCP does OBO inside the MCP server; babs forwards the
raw IdP token to the upstream (its docs warn the audience is not checked); ToolHive's Entra OBO is an
enterprise stub. No project turns AADSTS65001 or Conditional Access into an actionable result.

Clients (source): only 401 and 403 trigger re-authentication — VS Code `isAuthStatusCode` is `401 || 403`;
the TypeScript SDK special-cases 401, 403 and 405 and throws on other statuses. Admin consent (Learn,
v2-admin-consent): `https://login.microsoftonline.com/{tenant}/v2.0/adminconsent?client_id&scope&
redirect_uri&state`, all required except `state`; `redirect_uri` must be registered; success returns
`admin_consent=True`. The test tenant has no Entra ID P1/P2 licence, so Conditional Access could not be
tested.

## Decision

1. **Proxy-side OBO, Entra only (`entra-obo`), in v0.1.** Only our IdP app holds the credential the
   exchange needs. A generic RFC 8693 adapter (Keycloak, Okta) comes later.
2. **Downstream scopes are configured per upstream;** the assertion is the stored `access_as_user`
   token.
3. **The downstream token goes in a dedicated header,** stripped from inbound requests (ADR-0016), never
   in `Authorization`. _Amended 2026-11-08 (#195):_ `Authorization` is allowed (see below); with a
   stdio upstream (#141) the token goes through the token socket instead.
4. **Cache** keyed by `tid`, `oid` and downstream scopes; in-memory LRU, bounded; TTL = the token's
   `exp` − 60 s, never beyond the stored assertion's `exp`. Downstream tokens are not refreshed — OBO
   runs again. They are never stored or logged.
5. **Errors:** AADSTS65001 returns HTTP 503 with a JSON body (`downstream_consent_required`) and an
   operator alert containing the admin-consent URL (tenant GUID, our client ID, the configured scopes,
   our registered `/callback/entra`); the callback recognises an `admin_consent=True` response and shows
   a confirmation page. `interaction_required` returns 503 plus an operator hint in v0.1. No 401 or 403
   (they make clients loop). Other errors follow ADR-0012.
6. **Setup guide:** grant admin consent for every downstream API.

## Consequences

- Passing Conditional Access `claims` through to the next login is v0.2 and needs a tenant with Entra
  ID P1 for testing.
- Upstream authors read the downstream token from one header; MCP clients see a plain error on
  consent problems, never a re-login loop.

## Amendment 2026-11-06 (release)

On-Behalf-Of ships in v0.2, not v0.1 (slice 4.2, #63). The first release is gated on the clients
connecting without manual setup: CIMD, dynamic registration and stdio upstreams. On-Behalf-Of builds
on a working v0.1 and is not needed for that. The design in this ADR is unchanged; read "v0.1" in
Decisions 1 and 5 as "v0.2".

## Amendment 2026-11-07 (design for slice 4.2)

- **§2–§3 settings:** `BYWARD_OBO_SCOPES` (space-separated scopes of one downstream API; empty turns
  On-Behalf-Of off) and `BYWARD_OBO_HEADER` (default `X-Byward-Downstream-Token`; stripped from inbound
  requests, sent as `Bearer <token>`). HTTP upstreams with Entra only: a stdio upstream gets its
  environment once per user and cannot receive a per-request token, so startup refuses the setting
  with stdio, with `--insecure-no-auth` and with any `BYWARD_IDP` but `entra`. The header is never the
  assertion's, `Authorization` or the operator credential's (ADR-0016 §7).
- **Every request to the upstream** carries the header, from the cache first, except an app-only
  caller's (ADR-0022): it acts for no user, so it is relayed without one, and the assertion's
  `principal_type` tells the upstream.
- **Assertion expiry:** while On-Behalf-Of is on, a proxy access token never outlives the stored
  `access_as_user` token: its `exp` is capped at that token's expiry − 60 s, so the client's normal
  refresh renews both, and byward never refreshes IdP tokens in the request path. (Entra access
  tokens live a random 60–90 minutes; CAE sessions longer, where the cap does not bind.) An IdP
  token that ends within those 60 s (or leaves under 30 s after them) is not a cap: the code or refresh token is already spent, so
  the token is issued uncapped (with a warning) and On-Behalf-Of refuses instead.
- **One exchange per user at a time:** concurrent requests share it, and it runs to completion
  (at most 30 s) even when the request that started it gives up, so the others still get the token.
- **§5 answers follow ADR-0025, not a plain 503.** ADR-0025 later showed that every non-2xx status
  breaks some client (VS Code puts the server into an error state). AADSTS65001 and
  `interaction_required` are answered like an upstream refusal:
  - a `tools/call` gets a tool result with `isError`, naming the missing administrator consent or
    the access policy;
  - other requests get JSON-RPC `-32603` with `data.downstream` = `consent_required` or
    `interaction_required`;
  - a notification gets 202, anything but `POST` 405, and a request whose `id` is unknown 503.

  The operator alert (an error log with the admin-consent URL, an audit record and a metric) is
  unchanged. Other errors follow ADR-0012.
- **Admin-consent callback:** `/callback/entra` with `admin_consent` and no `code` shows a
  confirmation page, or an error page when `error` is present (Entra's error redirect also carries
  `admin_consent=True`).
  - The callback is unauthenticated and unverifiable. It changes nothing and writes no audit event
    of its own: it logs "admin consent redirect received (unverified)" at info, through the
    rate-limited unauthenticated path.
  - It does not clear the cache: errors are never cached, so the next request simply retries, and an
    unauthenticated flush would let anyone force exchanges for every user.
  - The `tenant` it returns is never used.
  - The `/callback/entra` rate limit covers it.

## Amendment 2026-11-08 (#195: the downstream token in `Authorization`)

§3 and the 2026-11-07 settings note said the downstream token is never in `Authorization`. Most
Entra-protected MCP servers read the user's token from `Authorization: Bearer` and call their API
with it, so `BYWARD_OBO_HEADER=Authorization` is now allowed while `BYWARD_ASSERTION_HEADER` and
`BYWARD_UPSTREAM_CREDENTIAL_HEADER` use other headers; the identity assertion then travels in its own
header. The rule's purpose holds: the client's own `Authorization` is always removed before byward
sets its headers (invariant 1), so the upstream sees only the downstream token, and an app-only
caller, which gets none, sends no `Authorization` at all.

## Amendment 2026-11-08 (#141: stdio upstreams)

The 2026-11-07 settings note refused On-Behalf-Of with a stdio upstream: a process gets its
environment once and cannot receive a token that expires within the hour. A stdio process now asks
for it.

- **A token socket per process.** Each process gets a Unix socket in its own session directory (0700;
  the socket 0600), named in `BYWARD_DOWNSTREAM_TOKEN_SOCKET`. The process writes one JSON object on
  one line (`{}`) and reads one line back: `{"access_token","expires_at"}` (RFC 3339), or `{"error"}`
  with `consent_required`, `interaction_required`, `sign_in_expired`, `no_user`, `unavailable`,
  `failed`, `refused` or `bad_request`.
- **Which user, which grant.** A process serves one user (ADR-0003). The token is for that user,
  exchanged for the stored IdP token of the grant whose request the process served last, from the
  same cache as an HTTP upstream's. An app-only caller acts for no user: `no_user`. Once the stored
  IdP token or the grant itself has expired, or the grant was revoked or signed out, `sign_in_expired`: byward never
  refreshes IdP tokens outside a request, and the client's next request renews it.
- **The same check before every request.** Before a request reaches the process, byward gets the
  token as it does for an HTTP upstream. A refusal is answered in the proxy's name (the ADR-0025
  shapes above) and never starts or reaches a process, and a granted token is cached for the
  process to ask for. An ask the IdP refuses on the socket (`consent_required`, `interaction_required`,
  `unavailable`, `failed`) is recorded the same way: `downstream_token_refused`, the metric, the
  error log with the admin-consent URL. `no_user` and `sign_in_expired` are routine and only
  counted; `refused` is a warning log; `bad_request` is the asker's own mistake.
- **Who may ask.** Every upstream process, whatever its user, runs as byward's uid, so file
  permissions cannot keep one user's process from another's socket. byward accepts a connection
  only from the spawned process or one of its descendants: the peer's uid must be byward's
  (`SO_PEERCRED`; `LOCAL_PEERCRED` on macOS), and its parent chain must reach the spawned process
  (`/proc/<pid>/stat`; `kern.proc` on macOS). On Linux 6.5 and later the peer is pinned with
  `SO_PEERPIDFD`, and its pidfd's `fdinfo` is read again after the walk: a peer that has exited by
  then shows `Pid: -1` and is refused, as is any error from the option other than `ENOPROTOOPT`
  (a kernel without it, which goes unpinned). Older kernels and macOS leave a narrow race: a
  peer that hands its connection to another process and exits, with its PID reused inside the
  upstream's tree before the check, would pass. On macOS, `LOCAL_PEERPID` names the last process to
  use the peer's socket rather than the one that connected, so a connection handed on is checked
  against its new holder; macOS is for development only. Other peers get `refused`, and
  the refusal is logged with the peer's process ID.
- **Rejected alternatives**, all tested on 2026-11-07:
  - An inherited file descriptor (fd 3) does not survive `npx`: npm's child process gets only the
    standard streams. `uvx` and `sh -c` keep it, but npx servers are the common case.
  - A token file would be readable by every process of byward's uid, and would store the token,
    against §4.
  - The token in each request's `_meta` would reach byward's own logs whenever a server logs its
    requests to stderr.
- **What the host must give.** With `kernel.yama.ptrace_scope` 0 (Debian's kernel default), or no
  Yama, one process can read another of the same uid's memory, and with it the token it holds.
  byward warns at startup and in `doctor`, and does not refuse: the operator may isolate processes
  by other means. Optional per-user isolation is #182.
- **Upstream authors** change one thing: read the token from the socket when calling the
  downstream API, and ask again before `expires_at`. A server that only reads a static environment
  variable cannot get a token that expires within the hour without a restart.
- `BYWARD_OBO_HEADER` has no effect for a stdio upstream; setting it there is refused.
