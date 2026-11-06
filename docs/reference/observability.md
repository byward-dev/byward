# Observability reference

Decisions: [ADR-0021](../adr/0021-observability.md). The audit schema, the metric names and the log fields are public
interface; they change only through deprecation ([ADR-0023](../adr/0023-project-governance.md)).

## Where things go

| What | Where | Setting |
|---|---|---|
| Logs and the audit stream | stdout, JSON (`text` for development), UTC | `MCP_AUTHPROXY_LOG_FORMAT` |
| `/metrics`, `/livez`, `/readyz` | the **internal listener**, never the public one | `MCP_AUTHPROXY_INTERNAL_LISTEN` (default `127.0.0.1:9090`; empty turns it off) |
| Traces | an OTLP collector you name; **off** unless `OTEL_TRACES_EXPORTER` is set | `OTEL_*` |

In Kubernetes set `MCP_AUTHPROXY_INTERNAL_LISTEN=:9090` so the kubelet and Prometheus can reach it, and keep the port
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
| `remote_ip` | The TCP peer (forwarded headers are not trusted) |
| `client_id` | The MCP client |
| `user_key` | The IdP user key (`tid:oid` for Entra). Personal data (GDPR Recital 26) |
| `grant_id` | The grant (one user's authorization of one client) |
| `idp` | The IdP adapter, e.g. `entra` |
| `key_id` | A sealing key ID |
| `host`, `origin` | The rejected `Host` or `Origin` value |
| `reason` | A fixed reason; for `token_rejected` the OAuth error code |
| `suppressed` | How many records from the same `remote_ip` were dropped by the rate limit since the previous one |

Events from requests whose sender is not authenticated (marked *limited* below) are rate-limited per source address,
across all such events together: 10 per minute, then counted and reported as `suppressed=N` on the next limited record
from that source. A sender can therefore only crowd out its own records. Metrics count every event, logged or not.

### Events and OCSF mapping

For SIEMs that use [OCSF](https://schema.ocsf.io) 1.9.0. Fields map as follows: `time` → `time`; `request_id` →
`metadata.correlation_uid`; `user_key` → `user.uid`; `client_id` → `actor.app_uid`; `idp` → `actor.idp.name`;
`remote_ip` → `src_endpoint.ip`; `grant_id` → `session.uid`; `reason` → `status_detail`; `outcome` → `status_id`
(1 Success, 2 Failure). Rows marked *approximate* have no exact OCSF counterpart.

| Event | When | Outcomes | Limited | OCSF class / activity |
|---|---|---|---|---|
| `login` | sign-in through the IdP finished, was declined, failed at the IdP, or arrived with a missing, invalid or expired sign-in state | success, failure | only the state failures | 3002 Authentication / 1 Logon; `auth_protocol_id` 6 (OAuth 2.0) |
| `access_denied` | the access gate refused a signed-in user | failure | no | 3003 Authorize Session / 99 Other |
| `token_issued` | `/token` issued an access token | success | no | 3002 Authentication / 4 Service Ticket Request |
| `token_rejected` | `/token` refused a request (`reason` = OAuth error code) | failure | yes | 3002 Authentication / 4 Service Ticket Request |
| `access_token_rejected` | an MCP request carried an invalid or expired access token (`reason` = `invalid` or `expired`); a missing token is the normal start of sign-in and is not an event | failure | yes | 3002 Authentication / 99 Other (*approximate*) |
| `grant_revoked` | a grant was revoked because its authorization code was reused or redeemed with the wrong binding | success | no | 3002 Authentication / 2 Logoff; `disposition_id` 24 Access Revoked |
| `client_registered` | a static client was loaded at startup (`reason` = `static`) | success | no | 3001 Account Change / 1 Create (*approximate*) |
| `key_loaded` | a sealing key was loaded at startup (`reason` = `signing` or `verification`) | success | no | 6002 Application Lifecycle / 3 Start (*approximate*) |
| `host_rejected` | a request named a `Host` outside the allowlist (421) | failure | yes | 4002 HTTP Activity; `disposition_id` 2 Blocked |
| `origin_rejected` | a request sent an `Origin` outside the allowlist (403) | failure | yes | 4002 HTTP Activity; `disposition_id` 2 Blocked |

Not emitted yet; these arrive with their slices: consent granted or denied (slice 1.4), access-gate rules (slice 1.5),
refresh, revocation and store restore detection (slice 1.6), dynamic registration (slice 2.2), and key rotation
(later).

## Metrics

Prometheus text format at `/metrics` on the internal listener. Histogram buckets are fixed: 0.05, 0.1, 0.25, 0.5, 1,
2.5, 5 and 10 seconds. Label values come from fixed sets: never a user, client, tool or raw path.

| Metric | Type | Labels |
|---|---|---|
| `mcp_authproxy_http_request_duration_seconds` | histogram | `route`: the matched route pattern (`/mcp` or your public path, `/authorize`, `/callback/entra`, `/token`, the `/.well-known/…` metadata paths) or `other`; `status_class` (`2xx` …) |
| `mcp_authproxy_idp_request_duration_seconds` | histogram | `idp`, `operation` (`authorize`, `callback`), `outcome` (`success`, `rejected`, `unavailable`) |
| `mcp_authproxy_upstream_in_flight` | gauge | `kind` (`request`, `stream`) |
| `mcp_authproxy_upstream_busy_total` | counter | `kind`: requests refused with 503 because an admission cap was full |
| `mcp_authproxy_audit_events_total` | counter | `event`, `outcome`: every audit event, including rate-limited ones |
| `mcp_authproxy_build_info` | gauge | `version`, `go_version`; always 1 |

Plus the standard `go_*` and `process_*` collectors. Live stdio processes, deny-list sync age and store errors arrive
with their slices.

Example alert rules:

```yaml
groups:
  - name: mcp-authproxy
    rules:
      - alert: MCPAuthproxyIdPUnavailable
        expr: sum(rate(mcp_authproxy_idp_request_duration_seconds_count{outcome="unavailable"}[5m])) > 0
        for: 10m
      - alert: MCPAuthproxyRejectedTokenSpike
        expr: sum(rate(mcp_authproxy_audit_events_total{event="access_token_rejected"}[5m])) > 1
        for: 10m
      - alert: MCPAuthproxyUpstreamBusy
        expr: sum(rate(mcp_authproxy_upstream_busy_total[5m])) > 0
        for: 5m
```

## Health

| Probe | Meaning | 503 when |
|---|---|---|
| `GET /livez` | the process is serving | never (if it does not answer, restart it) |
| `GET /readyz` | ready for traffic: configuration loaded, a signing key present, the store reachable | a check fails, or the proxy is shutting down (`"draining":"fail"`) |

The body is JSON, e.g. `{"status":"ok","checks":{"keys":"ok","store":"ok"}}`. Check errors go to the log, not the body.
**The IdP is not part of readiness:** MCP requests are validated locally, so an IdP outage must not take every replica
out of service. Watch IdP health in `mcp_authproxy_idp_request_duration_seconds{outcome="unavailable"}`.

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
