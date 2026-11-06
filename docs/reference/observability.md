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
| `user_key` | The IdP user key (`tid:oid` for Entra). Personal data (GDPR Recital 26) |
| `grant_id` | The grant (one user's authorization of one client) |
| `idp` | The IdP adapter, e.g. `entra` |
| `key_id` | A sealing key ID |
| `host`, `origin` | The rejected `Host` or `Origin` value |
| `reason` | A fixed reason; for `token_rejected` the OAuth error code |
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
(1 Success, 2 Failure); `epoch` (the store epoch, `store_restored` only) → `unmapped.epoch`. Rows marked *approximate* have no exact OCSF counterpart.

| Event | When | Outcomes | Limited | OCSF class / activity |
|---|---|---|---|---|
| `login` | sign-in through the IdP finished, was declined, failed at the IdP, or arrived with a missing, invalid or expired sign-in state | success, failure | only the state failures | 3002 Authentication / 1 Logon; `auth_protocol_id` 6 (OAuth 2.0) |
| `access_denied` | the access gate refused a signed-in user, at sign-in or on a refresh (`reason` = the rule: `tenant`, `role`, `group`, `groups_unavailable`, `email_domain` or `hosted_domain`) | failure | no | 3003 Authorize Session / 99 Other |
| `token_issued` | `/token` issued an access token, from an authorization code or a refresh token | success | no | 3002 Authentication / 4 Service Ticket Request |
| `token_rejected` | `/token` or `/revoke` refused a request (`reason` = OAuth error code) | failure | yes | 3002 Authentication / 4 Service Ticket Request |
| `access_token_rejected` | an MCP request carried an invalid or expired access token (`reason` = `invalid` or `expired`); a missing token is the normal start of sign-in and is not an event | failure | yes | 3002 Authentication / 99 Other (*approximate*) |
| `grant_revoked` | a grant was revoked: its authorization code or refresh token was reused, a code was redeemed with the wrong binding, the client revoked a token (`/revoke`), a refresh found the IdP session ended or the user no longer allowed, a refresh came from a client whose metadata document is now refused (`reason` = `client metadata no longer valid`), or the operator ran `revoke-user` (`user_key` set) or `revoke-all` (`reason` = `operator revoke-user` or `operator revoke-all`) | success | no | 3002 Authentication / 2 Logoff; `disposition_id` 24 Access Revoked |
| `client_registered` | a static client was loaded at startup (`reason` = `static`), or `/register` answered: success with `reason` = `dcr` and the new `client_id`, or failure with `reason` = `invalid_redirect_uri`, `invalid_client_metadata`, `full`, `unavailable` or `rate_limited` ([DCR](../how-to/dcr.md)) | success, failure | only `/register` | 3001 Account Change / 1 Create (*approximate*) |
| `key_loaded` | a sealing key was loaded at startup (`reason` = `signing` or `verification`) | success | no | 6002 Application Lifecycle / 3 Start (*approximate*) |
| `host_rejected` | a request named a `Host` outside the allowlist (421) | failure | yes | 4002 HTTP Activity; `disposition_id` 2 Blocked |
| `origin_rejected` | a request sent an `Origin` outside the allowlist (403) | failure | yes | 4002 HTTP Activity; `disposition_id` 2 Blocked |
| `consent_shown` | the consent page was shown, before the IdP sign-in (the user is not known yet) | success | yes | 3003 Authorize Session / 99 Other (*approximate*) |
| `consent_granted` | the user allowed the client on the consent page | success | yes | 3003 Authorize Session / 99 Other (*approximate*) |
| `consent_denied` | the user denied the client on the consent page (`reason` fixed) | failure | yes | 3003 Authorize Session / 99 Other (*approximate*) |
| `consent_silent` | a `prompt=none` request could not finish without the user, so the client got an OAuth error at its redirect URI instead of a page (`reason` = the error sent: `consent_required`, `login_required`, `temporarily_unavailable`, `server_error`, or the IdP's own `login_required`, `interaction_required`, `consent_required`, `account_selection_required`; `client_trust` when known before the IdP). An access-gate denial is audited as `access_denied`, not here | failure | no | 3003 Authorize Session / 99 Other (*approximate*) |
| `consent_remembered` | a sign-in skipped the consent page on a remembered consent (ADR-0010 §3): success after the callback confirmed it for the user who signed in (`user_key`, `grant_id`, `client_trust`); failure when it did not hold and the page was shown instead (`reason` = `user_mismatch`: someone else signed in than the hint cookie named; `not_remembered`: the consent was forgotten, expired or the client is no longer trusted) | success, failure | no | 3003 Authorize Session / 99 Other (*approximate*) |
| `rate_limited` | an OAuth endpoint refused a request over the client address's budget (`reason` = the endpoint; [rate limits](rate-limits.md)) | failure | yes | 4002 HTTP Activity; `disposition_id` 2 Blocked |
| `store_restored` | at startup, the store was found restored from an older copy: a new `epoch` began and refresh tokens issued before it are refused, so those users sign in again (ADR-0007 §9) | success | no | 6002 Application Lifecycle / 99 Other (*approximate*) |
| `session_rejected` | a signed-in user presented an `Mcp-Session-Id` that is not theirs: sealed for another user or upstream, not issued by this proxy, tampered with, or expired (`reason` fixed); the client gets 404 and starts a new session | failure | no | 3003 Authorize Session / 99 Other (*approximate*) |
| `process_evicted` | an idle stdio upstream process was stopped so another could start under `BYWARD_STDIO_MAX_PROCESSES_PER_USER` (`reason` `user_cap`, the user's own process) or `BYWARD_STDIO_MAX_PROCESSES` (`reason` `upstream_cap`, any user's); `user_key` is the evicted process's user, whose session ends and whose client starts a new one | success | no | 6002 Application Lifecycle / 4 Stop (*approximate*) |

Not emitted yet; these arrive with their slices:
dynamic registration (slice 2.2) and key rotation
(later).

## Metrics

Prometheus text format at `/metrics` on the internal listener. Histogram buckets are fixed: 0.05, 0.1, 0.25, 0.5, 1,
2.5, 5 and 10 seconds. Label values come from fixed sets: never a user, client, tool or raw path.

| Metric | Type | Labels |
|---|---|---|
| `byward_http_request_duration_seconds` | histogram | `route`: the matched route pattern (`/mcp` or your public path, `/authorize`, `/consent`, `/assets/page.css`, `/callback/entra`, `/token`, `/revoke`, the `/.well-known/…` metadata paths) or `other`; `status_class` (`2xx` …) |
| `byward_idp_request_duration_seconds` | histogram | `idp`, `operation` (`authorize`, `callback`, `refresh`), `outcome` (`success`, `rejected`, `unavailable`) |
| `byward_upstream_in_flight` | gauge | `kind` (`request`, `stream`) |
| `byward_stdio_processes` | gauge | none; live stdio upstream processes, starting and stopping ones included (only with a stdio upstream) |
| `byward_upstream_busy_total` | counter | `kind`: requests refused with 503 because an admission cap was full |
| `byward_audit_events_total` | counter | `event`, `outcome`: every audit event, including rate-limited ones |
| `byward_rate_limited_total` | counter | `endpoint`: OAuth requests refused with 429 (or a `temporarily_unavailable` redirect) over a client address's budget |
| `byward_cimd_fetches_total` | counter | `outcome`: Client ID Metadata Document fetches: `ok`, `invalid`, `refused` (non-public address, a 4xx other than 408 and 429, redirect, too large), `unavailable` (network, timeout, 5xx, 408, 429), `rate_limited`, `busy` |
| `byward_dcr_registrations_total` | counter | `outcome`: `/register` answers: `registered`, `invalid_redirect_uri`, `invalid_client_metadata`, `full` (the cap), `unavailable` (store failure), `rate_limited` |
| `byward_consent_total` | counter | `trust` (`verified`, `domain`, `not-verified`), `outcome`: `shown` (the page), `granted`, `denied`, `remembered` (a sign-in that skipped the page, confirmed after the callback), `silent_refused` (a `prompt=none` request answered with an error; trust empty when refused after the IdP) |
| `byward_build_info` | gauge | `version`, `go_version`; always 1 |

Plus the standard `go_*` and `process_*` collectors. Deny-list sync age and store errors arrive
with their slices.

Example alert rules:

```yaml
groups:
  - name: byward
    rules:
      - alert: BywardIdPUnavailable
        expr: sum(rate(byward_idp_request_duration_seconds_count{outcome="unavailable"}[5m])) > 0
        for: 10m
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
**The IdP is not part of readiness:** MCP requests are validated locally, so an IdP outage must not take every replica
out of service. Watch IdP health in `byward_idp_request_duration_seconds{outcome="unavailable"}`.

## Traces

Off unless `OTEL_TRACES_EXPORTER` is set (`none` also means off). The proxy never connects anywhere for telemetry by
default; the OpenTelemetry SDK would otherwise send to `localhost:4318`. When on, configure the exporter with the
standard variables, e.g. `OTEL_TRACES_EXPORTER=otlp`, `OTEL_EXPORTER_OTLP_ENDPOINT=https://collector:4318`,
`OTEL_EXPORTER_OTLP_PROTOCOL=http/protobuf`.

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

Personal data in logs: `user_key` and `remote_ip`. Email and name are never logged.
