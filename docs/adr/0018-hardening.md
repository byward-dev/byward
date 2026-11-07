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

## Amendment 2026-11-06 (OAuth rate limits built)

- §8 budgets add `/consent` 60/min (the consent answer; the page itself is served by `/authorize`, and a user may retry an answer) and the IdP callback 30/min. Each is a token bucket
  per endpoint and client address, with a burst of the per-minute budget. Values are 1–10,000 per minute through
  `BYWARD_OAUTH_RATE_LIMITS`, with no off switch.
- §6 is implemented as `BYWARD_TRUSTED_PROXIES` (CIDRs or addresses, none by default). The client address is
  the rightmost `X-Forwarded-For` entry that is not a trusted proxy, and it is shared by the request log, the audit
  stream and the limits.
- Over-budget responses:
  - `/token`, `/revoke` and `/register`: 429 with `Retry-After`, `no-store` and JSON `temporarily_unavailable`.
  - `/authorize`: a `temporarily_unavailable` redirect to a valid client, else a 429 page.
  - Browser endpoints: a 429 page.
  - Every refusal is audited as `rate_limited`.
- Limits are per process. Each endpoint tracks at most 100,000 addresses and then falls back to a shared bucket.
- A per-`client_id` limit on failed `/token` client authentication is deferred to DCR.

## Amendment 2026-11-06 (hardening gaps #102, #103, #105)

- **§7 response-header timeout:** `BYWARD_UPSTREAM_HEADER_TIMEOUT`, default 5 minutes, 1 s to 1 h. An upstream that
  answers a request with plain JSON sends its headers only when the tool has finished, so a short timeout would
  cut long tool calls (oauth2-proxy's 30 s does). 5 minutes is well beyond the TypeScript SDK's default request
  timeout (60 s) and equals Envoy's default stream idle timeout. A streamed response is not limited once its
  headers have arrived. A request that times out is answered as in ADR-0025: a `tools/call` gets a tool result
  with `isError`, another request a JSON-RPC error `-32603` with `data.upstreamTimeout`, a notification 202, a
  non-`POST` 405, and a request whose `id` is unknown 504. Its in-flight slot is freed and the upstream request
  is dropped.
- **§2 on the internal listener:** `Host` is checked there too. Kubelet probes and Prometheus address a pod by its
  IP, which changes, so the internal listener accepts any IP literal, `localhost`, and the `BYWARD_ALLOWED_HOSTS`
  names (port ignored); other names get 421. A DNS rebinding attack always carries the attacker's own host name.
- **§5 consent body:** the limit is 16 KiB, not 4 KiB. The consent answer carries the sealed consent flow, which
  holds the whole sign-in state: the login (up to 2,600 bytes of JSON, including the client's `state` of up to
  512 bytes) plus the flow's own fields, then sealed and base64url-encoded (about 4/3 larger). That reaches about
  4.7 KB with a 512-byte `state`, over 4 KiB. 16 KiB keeps the limit explicit with headroom.
- **§11 secret files:** outside `--dev`, a secret file (the Entra client secret, a static client's
  `client_secret_file`) that its group or others can read or write refuses to start, unless it is on a read-only
  mount: Kubernetes secret volumes are mode 0644 by default and can be changed by no one inside the pod. `--dev`
  logs the relaxation.
- **§12:** `govulncheck` (pinned in `mise.toml`) runs once per release GOOS in `mise run check`, so in CI, and
  weekly in `pin-freshness`.

## Amendment 2026-11-07 (request trailers, #167)

- **§6 reverse proxy:** the relay drops every request trailer an MCP client sends (`Rewrite` sets
  `Request.Trailer` to nil). Trailers arrive after a chunked body, so the strip-then-inject of ADR-0016 §4
  never sees them. `ReverseProxy` removes the client's `Trailer` header as hop-by-hop, but `Request.Clone`
  keeps the announced names, and the Transport announced and sent them on: a trailer named like the
  identity assertion, the upstream credential or a plain identity header reached the upstream by name,
  with an empty value, because the relay forwards before the body is read. Anything that read the body
  first would have sent the client's values too, for an upstream framework that reads trailers as headers
  to take for ours. Nothing legitimate is lost:
  - neither revision of the MCP transports spec (2025-06-18, 2025-11-25) mentions trailers;
  - none of the six official SDKs (TypeScript, Python, Go, Java, C#, Rust) or the HTTP libraries they use
    sends them;
  - the Fetch Standard forbids `Trailer` and `TE` as request headers, so a browser cannot send them;
  - RFC 9112 §7.1.2: a recipient that removes the chunked coding "MAY selectively retain or discard the
    received trailer fields".

  Sources checked 2026-11-07; research notes kept outside the repository. The stdio bridge reads its headers
  from the header section only, so a trailer is never read as one there either. Response trailers from the
  upstream are a separate matter.
