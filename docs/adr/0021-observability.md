# ADR-0021: Observability — redacted logs, an audit stream, one request ID, telemetry off by default

- Status: Accepted
- Date: 2026-11-06
- Issue: #21 (F20)

## Context

OWASP ASVS 5.0.0 V16 asks for a log inventory (16.1.1), "when, where, who, what" (16.2.1), UTC or an
explicit offset (16.2.2), no credentials and session tokens only "hashed or masked" (16.2.5), every
authentication operation and failed authorization (16.3.1–16.3.2), and logs shipped to "a logically
separate system" (16.4.3). GDPR Recital 26: pseudonymised data "should be considered to be information
on an identifiable natural person". OpenTelemetry semconv 1.45.0: HTTP server spans and
`http.server.request.duration` are Stable; the MCP conventions are "Development" and say
instrumentations "SHOULD propagate context … by injecting it into the MCP request `params._meta`". MCP:
`traceparent`, `tracestate` and `baggage` in `_meta` "MUST follow W3C Trace Context". Kubernetes:
"Readiness probes determine when a container is ready to accept traffic"; misconfigured probes cause
cascading failures.

Competitors (source): babs exposes Prometheus metrics; ToolHive has an audit package and injects
`traceparent` into `_meta` (a body rewrite); dex and agentgateway serve health on a separate port and
expose pprof; Obot keeps an audit log.

Clients (source, 2026-11-06): none sends trace context by default. Claude Code sends a `traceparent`
header on HTTP MCP requests when its beta tracing is on; the Python SDK and VS Code with Copilot (opt-in)
put it in `params._meta`; the TypeScript SDK, go-sdk, Inspector and Gemini CLI send none.
`error_description` reaches the user unreliably: VS Code only logs `/token` errors, the TypeScript SDK
drops redirect descriptions without `iss`; every client shows the page we render in the browser.

Runtime (2026-11-06):
- Entra echoed a sent `client-request-id` and returned it as `correlation_id` in the error body
  (`trace_id` = `x-ms-request-id`).
- A Go spike (otel v1.47.0, autoexport v0.72.0, client_golang v1.25.0):
  - `ReverseProxy.Rewrite` forwards the client's `traceparent` unchanged unless we inject;
  - `_meta` arrives byte-identical;
  - **autoexport with no `OTEL_*` variables exports OTLP to `https://localhost:4318`**;
  - an slog `ReplaceAttr` allowlist redacts as intended, except for whole-`http.Header` values;
  - Prometheus names come out as registered.

## Decision

1. **Logs:** `slog` JSON on stdout (`BYWARD_LOG_FORMAT=text|json`, default `json`), UTC. A
   `ReplaceAttr` allowlist plus a redaction test; whole header maps are never logged. Request lines
   carry method, status, duration and the `Mcp-Method` header value; bodies are never parsed for logs.
2. **Request ID** per request: on every HTML error page we render (the one place every client shows
   the user), in `error_description` of `/token` errors, in logs and audit events, and sent to the IdP
   as `client-request-id`, so it matches Entra's `correlation_id`.
3. **Audit stream:** JSON events with `log.type=audit` and `schema_version` on stdout, optional file
   sink. Events: login success and failure, consent granted and denied, access-gate denial, token
   revoked, client registered, key loaded or rotated, store restore (epoch bump), `Origin`/`Host`
   rejection. The docs map fields to OCSF 3002/3003 and tell operators to ship the stream off the host.
4. **Personal data:** logs carry the user key (`tid:oid`) and client IP; email and name only by opt-in;
   no HMAC pseudonyms. The docs hold the log inventory; retention is the operator's.
5. **Abuse:** events from unauthenticated requests are rate-limited per source and summarised with
   `suppressed=N`.
6. **stdio stderr:** each line becomes a log record tagged with the upstream, the process and the user
   key; lines over 8 KiB are truncated; rate-limited.
7. **IdP errors** log the error code (AADSTS for Entra), `trace_id` and `correlation_id`.
8. **Metrics:** Prometheus text format at `/metrics` on the internal listener (ADR-0018). Request
   duration, IdP call latency and errors, upstream in-flight and 503s, live stdio processes, auth
   events, deny-list sync age, store errors. Fixed buckets 0.05–10 s. No user, client or tool labels.
9. **Traces are off unless `OTEL_TRACES_EXPORTER` is set.** When on, autoexport; an HTTP server span
   that continues an inbound `traceparent` header; `traceparent` injected explicitly toward the
   upstream; `_meta` never touched; no MCP attributes while they are Development.
10. **Health:** `/livez` = the process; `/readyz` = config, keys and store. The IdP is not part of
    readiness: MCP requests are validated locally (ADR-0014), so an IdP outage must not drain every
    pod; IdP health is in metrics and `doctor`.
11. **`doctor --json`** with an exit code per check class.
12. **No pprof** unless a flag enables it on the internal listener, bound to localhost.
13. **Docs:** example Prometheus alert rules (IdP error rate, 401 spike, deny-list sync age, refresh
    failures) and a table of which clients propagate trace context.

## Consequences

- The audit schema, metric names and log fields are public interface, changed through deprecation as
  for configuration (ADR-0020).
- Clients that put trace context only in `_meta` join the upstream's trace, not ours.
- Two telemetry libraries (Prometheus client for metrics, OpenTelemetry for traces) while the OTel
  Prometheus exporter is Development.
- Later: OTLP metrics, exemplars, an exact OCSF emitter.

## Considered options

- Parse `_meta` to link our span: rejected; it needs body parsing (ADR-0003).
- HMAC user IDs in logs: rejected; still personal data, adds a secret, breaks Entra log correlation.
- IdP in readiness: rejected; it turns an IdP outage into a full outage.
- autoexport defaults: rejected; they send to localhost without the operator asking.
