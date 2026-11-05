# ADR-0018: Hardening — Origin and Host checks, bounded HTTP, Rewrite-only proxying

- Status: Accepted
- Date: 2026-11-06
- Issue: #18 (F17)

## Context

MCP 2026-07-28 (Streamable HTTP): "Servers **MUST** validate the `Origin` header on all incoming
connections … If the `Origin` header is present and invalid, servers **MUST** respond with HTTP 403";
local servers "SHOULD bind only to localhost". Go `net/http`: for server timeouts "A zero or negative
value means there will be no timeout"; `httputil.ReverseProxy.Director` "is deprecated … This function is
insecure" (headers it adds can be removed through `Connection`; inbound `X-Forwarded-For` is preserved).
RFC 9110 §7.6.1: intermediaries remove hop-by-hop headers and those named in `Connection`. OWASP ASVS 5.0:
4.1.3 (identity headers cannot be overridden), 4.2.1 (request smuggling), 13.4.x (no debug or exposed
monitoring), 16.x (log authentication and denials, no fail-open, a last-resort handler). Recent Go CVEs
hit `ReverseProxy` and HTTP/2.

Competitors (source): ToolHive's `Origin` check is the strictest; nobody validates `Host` on public
listeners; babs sets sensible timeouts, body limits and per-IP OAuth rate limits; sigbit sets no timeouts;
nobody cancels streams on shutdown; go-sdk had DNS-rebinding and cross-site advisories fixed in 1.4.1.
Clients (runtime, 2026-11-06): Node `fetch` and MCP Inspector CLI 2.14.0 (TypeScript SDK) send no
`Origin` to the MCP endpoint.

## Decision

1. **`Origin` on the MCP endpoint, before authentication:** an exact allowlist (scheme, host, port);
   multiple `Origin` headers or `null` get 403; a missing `Origin` passes. The default allowlist is empty,
   so browser-based clients must be listed.
2. **`Host`** is validated on every listener against the configured public URL plus operator-configured
   hosts (e.g. the ingress's internal name); a mismatch gets 421 and is logged; `doctor` shows the list.
3. **Bind `127.0.0.1` by default;** public addresses only when configured.
4. **`http.Server`:** `ReadHeaderTimeout` 10 s, `ReadTimeout` 30 s, `WriteTimeout` 0 with per-request
   deadlines via `ResponseController` for streams, `IdleTimeout` 120 s, `MaxHeaderBytes` 64 KiB.
5. **Body limits enforced while reading:** MCP 8 MiB, OAuth endpoints 64 KiB, consent 4 KiB.
6. **Reverse proxy:** `Rewrite` only; strip-then-inject per ADR-0016; `X-Forwarded-For` trusted only from
   configured CIDRs (none by default), untrusted values deleted.
7. **Upstream:** an in-flight cap per upstream (64, then 503); dial and response-header timeouts; request
   contexts cancelled when the client disconnects.
8. **Rate limits on OAuth endpoints only,** per IP (IPv6 grouped by /64): `/authorize` 30/min, `/token`
   60/min, `/register` 30/min, `/revoke` 30/min. No rate limiting of MCP traffic (ADR-0001), only the
   in-flight caps.
9. **Failure handling:** a recovery middleware that never dumps headers, a test that logs are redacted,
   shutdown within 25 s cancelling streams through context.
10. **Exposure:** no debug endpoints or TRACE; metrics and health on a separate internal listener.
11. **Development mode** (`--dev`) is the only source of relaxations (loopback `http`, ADR-0010); each is
    logged at startup.
12. **Process:** track the latest Go patch release; `govulncheck` in CI; fuzz tests for every parser
    (sealed tokens, redirect URIs, CIMD documents, era detection); go-sdk ≥ 1.4.1 if used.
13. **Security invariants 16–18** are added to `docs/quality-lenses.md`, and `AGENTS.md` requires every
    change to keep the invariants list.

## Consequences

- All limits are configurable within bounds; the defaults fit Claude's 10 s / 30 s client timeouts.
- Behind an ingress the operator lists the internal host, or requests fail with an explicit 421.
