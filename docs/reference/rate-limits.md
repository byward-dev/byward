# OAuth endpoint rate limits

Decisions: [ADR-0018](../adr/0018-hardening.md) §6 and §8. MCP traffic is never rate-limited, only capped in flight
([ADR-0001](../adr/0001-scope-auth-only-proxy-entra-first-class.md)).

## Budgets

Requests per minute per client address. A token bucket per endpoint and address: a full minute's budget may arrive
at once, then it refills evenly (30/min means one more request every 2 s).

| Endpoint | Default | Response when over |
|---|---|---|
| `/authorize` | 30 | a redirect to the MCP client with `error=temporarily_unavailable`, `state` and `iss` (RFC 6749 §4.1.2.1) when the client and redirect URI are valid; otherwise a 429 page |
| `/consent` | 60 (a GET and a POST per sign-in) | 429 page |
| `/callback/{idp}` | 30 | 429 page; the IdP is not called |
| `/token` | 60 | 429 with JSON `{"error":"temporarily_unavailable",…}` and `Cache-Control: no-store`; the body is not read |
| `/revoke` | 30 | as `/token` |
| `/register` | 30 | as `/token` |

Every refusal carries `Retry-After` in whole seconds (RFC 6585 §4), is counted in `mcp_authproxy_rate_limited_total`,
and is audited as `rate_limited` ([observability](observability.md)). `/consent`, `/revoke` and `/register` apply
from the slices that add them. Metadata and JWKS are not limited.

Raise a budget with `MCP_AUTHPROXY_OAUTH_RATE_LIMITS`, for example `authorize=120,callback=120`. Each value is 1 to
10,000 per minute. There is no way to turn the limits off.

## Client address

- IPv4 addresses are limited one by one; **IPv6 addresses are grouped by /64**, because a client controls its whole
  /64.
- Without `MCP_AUTHPROXY_TRUSTED_PROXIES` (the default) the client address is the TCP peer and `X-Forwarded-For` is
  ignored.
- **Behind a reverse proxy or ingress,** list its addresses or CIDRs in `MCP_AUTHPROXY_TRUSTED_PROXIES`. Otherwise
  every user shares the proxy's budget. The client address is then the rightmost `X-Forwarded-For` entry that is not
  a trusted proxy, so a client cannot choose its own address by adding entries on the left. `Forwarded` (RFC 7239)
  is not read.

## Things to know

- **Shared addresses:** an office or VPN behind one public address shares one budget, so 30 sign-ins a minute by
  default. If many users there sign in at the same time (Monday morning), raise `authorize` and `callback`.
- **Per replica:** limits are kept in each process. Three replicas behind a load balancer allow three times the
  budget.
- **Memory:** each endpoint tracks up to 100,000 addresses. Idle ones are dropped. When that many are active, new
  addresses share one bucket, so a flood from changing addresses becomes a global limit instead of using unbounded
  memory.
- **Not limited yet:** failed client authentication per `client_id` at `/token`. It comes with dynamic client
  registration.
