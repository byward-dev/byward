# Observability reference

Decisions: [ADR-0021](../adr/0021-observability.md). The audit schema, the metric names and the log fields are public
interface; they change only through deprecation ([ADR-0023](../adr/0023-project-governance.md)).

## Where things go

| What | Where | Setting |
|---|---|---|
| Logs and the audit stream | standard error, JSON (`text` for development), UTC; standard output carries only command output such as `--print-config` | `BYWARD_LOG_FORMAT` |
| `/metrics`, `/livez`, `/readyz` | the **internal listener**, never the public one | `BYWARD_INTERNAL_LISTEN` (default `127.0.0.1:9090`; empty turns it off) |
| Traces | an OTLP collector you name; **off** unless `OTEL_TRACES_EXPORTER` is set | `OTEL_*` |

In Kubernetes set `BYWARD_INTERNAL_LISTEN=:9090` so the kubelet and Prometheus can reach it, and keep the port
out of the Service that fronts the proxy. Ship the audit stream to a separate system (OWASP ASVS 16.4.3); retention is
yours.

## Audit stream

Every audit record is a log line with `log.type=audit` and `schema_version=1`, so a log pipeline can split it out. It
carries `time`, `level` (`INFO` for success, `WARN` for failure), `msg` (`audit <event>`), `event`, `outcome`
(`success` or `failure`), and the fields below where they apply. No record ever carries a token, secret, code, verifier
or the IdP's `error_description`.

| Field | Meaning |
|---|---|
| `request_id` | The request ID: on error pages, in `/token` error descriptions, in `X-Request-Id`, and sent to Entra as `client-request-id` (Entra's `correlation_id`) |
| `remote_ip` | The client address: the TCP peer, or, when the peer is in `BYWARD_TRUSTED_PROXIES`, the rightmost `X-Forwarded-For` entry that is not a trusted proxy. The request log and the rate limits use the same address |
| `client_id` | The MCP client |
| `client_trust` | The client's trust level on the consent page: `verified`, `domain` or `not-verified` (ADR-0008 §8) |
| `user_key` | The IdP user key: `tid:oid` for Entra; for an `oidc` IdP, the value of its subject claim (`BYWARD_OIDC_SUBJECT_CLAIM`, `sub` by default). Personal data (GDPR Recital 26) |
| `grant_id` | The grant (one user's authorization of one client) |
| `idp` | The IdP, the `BYWARD_IDP` value: `entra`, `oidc`, `google`, `okta`, `auth0` or `keycloak` |
| `key_id` | A sealing key ID |
| `host`, `origin` | The rejected `Host` or `Origin` value |
| `reason` | A fixed reason; for `token_rejected` the OAuth error code |
| `epoch` | The store epoch; `store_restored` only |
| `open_streams` | How many open streams the stopped process had; `process_evicted` only, omitted when none |
| `suppressed` | How many records of the same event from the same `remote_ip` were dropped by the rate limit since the previous one |

Events from requests whose sender is not authenticated (marked *limited* below) are rate-limited per source address,
event and outcome: 10 per minute for each, then counted and reported as `suppressed=N` on the next record with the same
event and outcome from that source. A sender can therefore only crowd out its own records of the same event and
outcome: consent page views never hide consent decisions, and successful registrations never hide refused ones.
Metrics count every event, logged or not.

### Events and OCSF mapping

For SIEMs that use [OCSF](https://schema.ocsf.io) 1.9.0. Fields map as follows: `time` → `time`; `request_id` →
`metadata.correlation_uid`; `user_key` → `user.uid`; `client_id` → `actor.app_uid`; `idp` → `actor.idp.name`;
`remote_ip` → `src_endpoint.ip`; `grant_id` → `session.uid`; `reason` → `status_detail`; `outcome` → `status_id`
(1 Success, 2 Failure); `epoch` (the store epoch, `store_restored` only) → `unmapped.epoch`; `open_streams` (`process_evicted` only) → `unmapped.open_streams`. Rows marked *approximate* have no exact OCSF counterpart.

| Event | When | Outcomes | Limited | OCSF class / activity |
|---|---|---|---|---|
| `login` | sign-in through the IdP finished, was declined, failed at the IdP, or arrived with a missing, invalid or expired sign-in state | success, failure | only the state failures | 3002 Authentication / 1 Logon; `auth_protocol_id` 6 (OAuth 2.0) |
| `access_denied` | the access gate refused a signed-in user, at sign-in or on a refresh (`reason` = the rule: `tenant`, `role`, `group`, `groups_unavailable`, `email_domain` or `hosted_domain`) | failure | no | 3003 Authorize Session / 99 Other |
| `token_issued` | `/token` issued an access token, from an authorization code or a refresh token | success | no | 3002 Authentication / 4 Service Ticket Request |
| `token_rejected` | `/token` or `/revoke` refused a request (`reason` = OAuth error code) | failure | yes | 3002 Authentication / 4 Service Ticket Request |
| `access_token_rejected` | an MCP request carried an invalid or expired access token (`reason` = `invalid` or `expired`); a missing token is the normal start of sign-in and is not an event | failure | yes | 3002 Authentication / 99 Other (*approximate*) |
| `grant_revoked` | a grant was revoked: its authorization code or refresh token was reused, a code was redeemed with the wrong binding, the client revoked a token (`/revoke`), a refresh found the IdP session ended or the user no longer allowed, a refresh came from a client whose metadata document is now refused, or the operator ran `revoke-user` (`user_key` set) or `revoke-all`; `reason` is one of the [values below](#grant_revoked-reasons) | success | no | 3002 Authentication / 2 Logoff; `disposition_id` 24 Access Revoked |
| `client_registered` | a static client was loaded at startup (`reason` = `static`), or `/register` answered: success with `reason` = `dcr` and the new `client_id`, or failure with `reason` = `invalid_redirect_uri`, `invalid_client_metadata`, `full`, `unavailable` or `rate_limited` ([DCR](../how-to/dcr.md)) | success, failure | only `/register` | 3001 Account Change / 1 Create (*approximate*) |
| `key_loaded` | a sealing key was loaded at startup (`reason` = `signing` or `verification`) | success | no | 6002 Application Lifecycle / 3 Start (*approximate*) |
| `host_rejected` | a request named a `Host` outside the allowlist (421) | failure | yes | 4002 HTTP Activity; `disposition_id` 2 Blocked |
| `origin_rejected` | a request sent an `Origin` outside the allowlist (403) | failure | yes | 4002 HTTP Activity; `disposition_id` 2 Blocked |
| `consent_shown` | the consent page was shown, before the IdP sign-in (the user is not known yet) | success | yes | 3003 Authorize Session / 99 Other (*approximate*) |
| `consent_granted` | the user allowed the client on the consent page | success | yes | 3003 Authorize Session / 99 Other (*approximate*) |
| `consent_denied` | the user denied the client on the consent page (`reason` fixed) | failure | yes | 3003 Authorize Session / 99 Other (*approximate*) |
| `consent_remembered` | a sign-in skipped the consent page on a remembered consent (ADR-0010 §3): success after the callback confirmed it for the user who signed in (`user_key`, `grant_id`, `client_trust`); failure when it did not hold and the page was shown instead (`reason` = `user_mismatch`: someone else signed in than the hint cookie named; `not_remembered`: the consent was forgotten, expired or the client is no longer trusted) | success, failure | no | 3003 Authorize Session / 99 Other (*approximate*) |
| `consent_silent` | a `prompt=none` request could not finish without the user, so the client got an OAuth error at its redirect URI instead of a page (`reason` = the error sent: `consent_required`, `login_required`, `temporarily_unavailable`, `server_error`, or the IdP's own `login_required`, `interaction_required`, `consent_required`, `account_selection_required`; `client_trust` when refused by `/authorize`'s own checks). An access-gate denial is audited as `access_denied`, not here | failure | no | 3003 Authorize Session / 99 Other (*approximate*) |
| `rate_limited` | an OAuth endpoint refused a request over the client address's budget (`reason` = the endpoint; [rate limits](rate-limits.md)) | failure | yes | 4002 HTTP Activity; `disposition_id` 2 Blocked |
| `store_restored` | the store was found restored from an older copy, so a new `epoch` began and refresh tokens issued before it are refused: those users sign in again (ADR-0007 §9). SQLite finds it at startup (`reason` `restored from an older copy`); with PostgreSQL, one replica finds it while running (`restored from an older copy, found while running`); `byward store new-epoch` records `operator new-epoch` | success | no | 6002 Application Lifecycle / 99 Other (*approximate*) |
| `session_rejected` | a signed-in user presented an `Mcp-Session-Id` that is not theirs: sealed for another user or upstream, not issued by this proxy, tampered with, or expired (`reason` fixed); the client gets 404 and starts a new session | failure | no | 3003 Authorize Session / 99 Other (*approximate*) |
| `process_evicted` | an idle stdio upstream process, or one held only by quiet streams, was stopped so another could start under `BYWARD_STDIO_MAX_PROCESSES_PER_USER` (`reason` `user_cap`, the user's own process) or `BYWARD_STDIO_MAX_PROCESSES` (`reason` `upstream_cap`, any user's); `user_key` is the evicted process's user, whose session ends and whose client starts a new one; `open_streams`, present when it is above 0, is how many streams the stop ended (the process had seen no traffic for `BYWARD_STDIO_STREAM_IDLE_TIMEOUT`) | success | no | 6002 Application Lifecycle / 4 Stop (*approximate*) |
| `app_token_accepted` | an app-only caller's Entra token was first used at the MCP endpoint ([app-only callers](../how-to/app-tokens.md)): once per token (its `uti`), with the service principal as `user_key` (`tid:oid`) and its application ID as `client_id`; while 10,000 tokens are tracked, each request with an untracked token is recorded | success | no | 3002 Authentication / 1 Logon (*approximate*) |
| `app_token_rejected` | an MCP request carried an app-only token that was refused (`reason` = `expired`, `invalid`, `delegated` (a user's token), `keys_unavailable` (the tenant's keys could not be fetched), `revoked` (`revoke-user`), `deny_list_stale`, or `denied_role`, `denied_client`, `denied_tenant` (the app gate, answered with 403)); `user_key` and `client_id` only once the token passed every check of its own (the `denied_*`, `revoked` and `deny_list_stale` reasons) | failure | yes | 3002 Authentication / 1 Logon (*approximate*) |
| `downstream_token_refused` | Entra refused the On-Behalf-Of exchange for a signed-in user's MCP request, or for a stdio process's ask on its token socket, which has no request and so no `request_id` or `remote_ip` (`reason` `consent_required`, `interaction_required`, `unavailable` or `failed`); the client gets an answer it can show, never a 401 or 403, and with `consent_required` the error log carries `admin_consent_url` (ADR-0017 §5) | failure | no | 3003 Authorize Session / 99 Other (*approximate*) |

Not emitted: a key rotation as such. Keys are read at startup, and each one loaded is a `key_loaded` record.

### `grant_revoked` reasons

| `reason` | Why |
|---|---|
| `authorization code reused; grant revoked` | an authorization code was presented a second time |
| `authorization code redeemed with the wrong binding; grant revoked` | a code was redeemed with another client, redirect URI or PKCE verifier |
| `refresh token reused; grant revoked` | a rotated refresh token was presented after its grace period |
| `the client revoked a token (RFC 7009)` | the client called `/revoke` |
| `client metadata no longer valid` | a refresh came from a CIMD client whose metadata document is now refused |
| `the grant holds no usable IdP refresh token; grant revoked` | a refresh found no IdP refresh token to use |
| `the IdP ended the session; grant revoked` | the IdP refused the refresh: the user's session there is over |
| `the IdP returned no ID token on refresh; grant revoked` | the IdP's refresh answer had no ID token, so the user could not be checked again |
| `the IdP returned another user on refresh; grant revoked` | the refreshed ID token named another subject or issuer |
| `the access gate refused the user on refresh; grant revoked` | the user no longer passes the access gate |
| `operator revoke-user` | `byward revoke-user`; `user_key` names the user |
| `operator revoke-all` | `byward revoke-all` |

## Metrics

Prometheus text format at `/metrics` on the internal listener. Histogram buckets are fixed: 0.05, 0.1, 0.25, 0.5, 1,
2.5, 5 and 10 seconds. Label values come from fixed sets: never a user, client, tool or raw path.

| Metric | Type | Labels |
|---|---|---|
| `byward_http_request_duration_seconds` | histogram | `route`: the matched route pattern (`/mcp` or your public path, `/authorize`, `/consent`, `/assets/page.css`, `/callback/{idp}`, `/token`, `/revoke`, `/register`, the `/.well-known/…` metadata paths, `GET /.well-known/jwks.json`) or `other`; `status_class` (`2xx` …) |
| `byward_idp_request_duration_seconds` | histogram | `idp`, `operation` (`authorize`, `callback`, `refresh`), `outcome` (`success`, `rejected`, `unavailable`) |
| `byward_upstream_in_flight` | gauge | `kind` (`request`, `stream`) |
| `byward_upstream_busy_total` | counter | `kind`: requests refused with 503 because an admission cap was full |
| `byward_audit_events_total` | counter | `event`, `outcome`: every audit event, including rate-limited ones |
| `byward_rate_limited_total` | counter | `endpoint`: OAuth requests refused with 429 (or a `temporarily_unavailable` redirect) over a client address's budget |
| `byward_cimd_fetches_total` | counter | `outcome`: Client ID Metadata Document fetches: `ok`, `invalid`, `refused` (non-public address, a 4xx other than 408 and 429, redirect, too large), `unavailable` (network, timeout, 5xx, 408, 429), `rate_limited`, `busy` |
| `byward_dcr_registrations_total` | counter | `outcome`: `/register` answers: `registered`, `invalid_redirect_uri`, `invalid_client_metadata`, `full` (the cap), `unavailable` (store failure), `rate_limited` |
| `byward_consent_total` | counter | `trust` (`verified`, `domain`, `not-verified`), `outcome`: `shown` (the page), `granted`, `denied`, `remembered` (a sign-in that skipped the page, confirmed after the callback), `silent_refused` (a `prompt=none` request answered with an error; trust empty when refused after the IdP) |
| `byward_app_tokens_total` | counter | `outcome`: every app-only token at the MCP endpoint: `accepted`, or the `app_token_rejected` reasons |
| `byward_downstream_tokens_total` | counter | `outcome`: On-Behalf-Of downstream tokens for upstream requests and stdio processes' asks: `cached`, `issued`, `consent_required`, `interaction_required`, `unavailable`, `failed`; for a stdio process also `no_user` (an app-only caller) and `sign_in_expired` (ADR-0017) |
| `byward_idp_alerts_total` | counter | `idp`, `operation` (`authorize`, `callback`, `refresh`, `on_behalf_of`), `reason`: IdP errors that will not clear without the operator: `credential_rejected` (the IdP refuses the proxy's client credential or client ID: `invalid_client` or `unauthorized_client` from the token endpoint, an expired secret, an unregistered app), `credential_unusable` (the proxy could not build its credential: an unreadable certificate, key or federated token file), `protocol` (the IdP answered against the protocol, such as a success without tokens). Every series is exported at 0 from the start (`on_behalf_of` only with On-Behalf-Of on), so `increase()` sees the first one. Alert on any increase |
| `byward_build_info` | gauge | `version`, `go_version`; always 1 |
| `byward_stdio_processes` | gauge | none; live stdio upstream processes, starting and stopping ones included (only with a stdio upstream) |

Plus the standard `go_*` and `process_*` collectors. There is no metric for the deny list's sync age
or for store errors: a store that fails turns `/readyz` to 503 (below) and is logged.

Example alert rules (what to do when each fires: [respond to alerts](../how-to/respond-to-alerts.md)):

```yaml
groups:
  - name: byward
    rules:
      - alert: BywardIdPUnavailable
        expr: sum(rate(byward_idp_request_duration_seconds_count{outcome="unavailable"}[5m])) > 0
        for: 10m
      - alert: BywardIdPNeedsTheOperator
        expr: sum by (idp, reason) (increase(byward_idp_alerts_total[5m])) > 0
      - alert: BywardRejectedTokenSpike
        expr: sum(rate(byward_audit_events_total{event="access_token_rejected"}[5m])) > 1
        for: 10m
      - alert: BywardUpstreamBusy
        expr: sum(rate(byward_upstream_busy_total[5m])) > 0
        for: 5m
```

## Health

| Probe | Meaning | 503 when |
|---|---|---|
| `GET /livez` | the process is serving | never (if it does not answer, restart it) |
| `GET /readyz` | ready for traffic: configuration loaded, a signing key present, the store reachable | a check fails, or the proxy is shutting down (`"draining":"fail"`) |

The body is JSON, e.g. `{"status":"ok","checks":{"keys":"ok","store":"ok"}}`. Check errors go to the log, not the body.

| Check | Fails when | Fix |
|---|---|---|
| `keys` | no sealing key signs | add a key to `BYWARD_KEYS_DIR` ([sealing keys](../how-to/sealing-keys.md)) |
| `store` | the store does not answer a ping | the SQLite state directory or the PostgreSQL database; the log names the error |
| `draining` | the proxy is shutting down | none: it is stopping |
**The IdP is not part of readiness:** MCP requests are validated locally, so an IdP outage must not take every replica
out of service. Watch IdP health in `byward_idp_request_duration_seconds{outcome="unavailable"}`.

## Traces

Off unless `OTEL_TRACES_EXPORTER` is set (`none` also means off). The proxy never connects anywhere for telemetry by
default; the OpenTelemetry SDK would otherwise send to `localhost:4318`. When on, configure the exporter with the
standard variables, e.g. `OTEL_TRACES_EXPORTER=otlp`, `OTEL_EXPORTER_OTLP_ENDPOINT=https://collector:4318`,
`OTEL_EXPORTER_OTLP_PROTOCOL=http/protobuf`.

- OpenTelemetry's own errors, such as a failed export, are logged at warn level as `tracing error`, not printed to
  stderr. Through an [environment proxy](../how-to/harden-a-deployment.md#protect-the-upstream-hop) whose setting Go misread, the error is a
  fixed cause that never quotes the address Go dialled. An `OTEL_*` setting the exporter rejects is logged the same
  way, by what was being parsed (e.g. `parse headers`, `parse url`), never by its value: a header can be a
  credential and an endpoint can carry userinfo. An SDK setting it rejects is logged by its name (e.g.
  `invalid OTEL_RESOURCE_ATTRIBUTES`, `invalid OTEL_TRACES_SAMPLER or OTEL_TRACES_SAMPLER_ARG`), never by its
  value. One exception, a [known gap](../security-posture.md#known-gaps): a span limit setting such as
  `OTEL_ATTRIBUTE_COUNT_LIMIT` that is not a number is printed to stderr with its value at start, even with tracing
  off.
- One server span per request, named `<METHOD> <route pattern>` (e.g. `POST /mcp`), continuing an inbound
  `traceparent` header.
- `traceparent` toward the upstream is our span's; with tracing off an inbound `traceparent` passes through unchanged.
- The MCP body, including `params._meta`, is never read or changed. A client that puts trace context only in `_meta`
  joins the upstream's trace, not ours.
- `baggage` is not propagated (it can carry user data). No MCP span attributes while those conventions are
  Development.

| Client (2026-11-06) | Sends trace context |
|---|---|
| Claude Code | `traceparent` header, when its beta tracing is on |
| Python SDK, VS Code with Copilot (opt-in) | in `params._meta` |
| TypeScript SDK, go-sdk, MCP Inspector, Gemini CLI | none |

## Logs

One JSON line per request: `request_id`, `method`, `path` (never the query string), `status`, `duration_ms`,
`remote_ip`, and the `Mcp-Method` header value as `mcp_method`. Attribute keys are allowlisted; whole header maps,
bodies, tokens and secrets are never logged, and bearer-shaped values are redacted.

IdP sign-in failures log the IdP's error code (`idp_error_code`, the AADSTS number for Entra), `trace_id` and
`correlation_id`; with Entra, `correlation_id` equals our `request_id`, so a user's reference finds both logs.

An IdP error counted in `byward_idp_alerts_total` is also logged once, at error level, as its own line
`IdP alert: the operator must act` with `idp`, `operation`, `alert` (the reason, as in the metric) and the fix in `reason`
(so `reason` here holds the fix, not a reason code), for example
`{"level":"ERROR","msg":"IdP alert: the operator must act","idp":"entra","operation":"refresh","alert":"credential_rejected","reason":"<the fix>"}`. For
On-Behalf-Of that is once per exchange with the IdP, however many requests were waiting on it; each refused request's
line, and each refused token-socket ask's line, also carries `alert`. A log-based alert can match on that message or on `alert` being present. An error in the
IdP's callback query never counts: a browser can forge it, so only the token endpoint's answer can say the proxy's
credential was refused.

Personal data in logs: `user_key` and `remote_ip`. Email and name are never logged.
