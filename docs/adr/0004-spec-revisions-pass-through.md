# ADR-0004: Spec revisions — serve both eras, pass through, never translate

- Status: Accepted
- Date: 2026-11-05
- Issue: #3 (F2)

## Context

MCP clients in use on 2026-11-05 speak 2025-11-25 (VS Code, Cursor, MCP Inspector by default)
or are dual-era (Claude Code, claude.ai; the go, python and C# SDKs fall back by default). The
2026-07-28 spec defines dual-era implementations and a client fallback ("attempt a modern request
and inspect the body of a 400 Bad Request before falling back"), and states "legacy clients have
no fall-forward mechanism". No surveyed project translates between revisions; agentgateway says
so explicitly. Translation would mean synthesising `initialize`, mapping MRTR to server-initiated
requests and `subscriptions/listen` to GET streams — a protocol gateway (ADR-0001 non-goal).

Two spec rules need the upstream to know who the user is. In URL-mode elicitation, "The MCP
Server **MUST** verify the identity of the user who opens the URL before accepting information"
(`client/elicitation`). And for MRTR, servers "**SHOULD** include … the authenticated principal,
rejecting state presented by a different principal" in `requestState` (`basic/patterns/mrtr`).
Behind the proxy, an HTTP upstream can only do either if the proxy tells it who the user is.
The spec defines no mechanism for that, and the `io.modelcontextprotocol/` `_meta` prefix is
reserved, so it is the proxy's design choice (F13).

## Decision

1. **One endpoint serves both eras.** The proxy recognises the era per request only to do auth
   work; it never translates between revisions. Client and upstream negotiate through the proxy.
2. **Legacy era:** the proxy binds the `Mcp-Session-Id` the upstream issues on `initialize`
   to the authenticated user; a request presenting another user's session is rejected. GET and
   DELETE are forwarded, not answered by the proxy. _Amended by ADR-0007:_ the binding is
   stateless — the proxy replaces the upstream's session ID with a sealed one carrying the
   upstream ID and the user (as agentgateway wraps upstream session IDs), so any replica can
   check it. "Byte-transparent" means the message body; this header is rewritten.
3. **Modern era:** forwarded unchanged. The proxy does not validate `Mcp-Method`/`Mcp-Name`
   (it enforces no policy on mirrored headers).
4. **Every request is authenticated, `server/discover` included** (as the MCP conformance suite
   does).
5. **Identity propagation (F13) is a v1 requirement for HTTP upstreams**, so they can verify
   the user in URL-mode elicitation (MUST) and bind `requestState` and session state to the user
   (SHOULD). stdio upstreams are covered by ADR-0003's
   one-user-per-process invariant.

## Consequences

- An upstream that only speaks 2026-07-28 cannot serve 2025-11-25-only clients behind the proxy;
  operators choose a dual-era upstream for broad client support. Documented, matching the spec's
  compatibility matrix.
- The proxy has no version-specific body rewriting on the HTTP path, so new spec revisions mostly
  need no proxy change beyond era recognition.

## Amendment 2026-11-07 (no upgrades, response trailers or 1xx headers past the binding, #168, #176; backported to 0.1)

- **§2 legacy era, upgrades:** the relay never lets the upstream switch protocols. It drops a client's
  `Upgrade` (and the `Connection` that carries it) before forwarding, and answers an upstream's 101 with
  502 and none of its headers. On a 101, `ReverseProxy` takes over the connection and writes the
  upstream's response itself, past the binding, so the upstream's raw `Mcp-Session-Id` reached the MCP
  client, and with it a raw connection to the upstream that no later check saw. Streamable HTTP has no
  upgrade.
- **§2 legacy era, response trailers:** `ReverseProxy` copies the upstream's response trailers to the
  client after the body, past the binding that seals the header when the response starts, so an upstream
  that sent its session as a trailer (announced or not) reached the MCP client unsealed. The relay drops
  every upstream response trailer: before the response starts, so none is announced, and again when the
  body is closed, since the body reader fills them in at the end. The same covers `Access-Control-*` and
  `WWW-Authenticate`, which the relay drops only as headers. MCP does not use response trailers.
- **Both eras, informational responses:** `ReverseProxy` forwards an upstream's 1xx from a client-trace
  hook, past the cleaning of the final response, with any header the upstream set, then clears the whole
  header map. The relay keeps only `Link` (103 Early Hints) and `Mcp-Session-Id`, which the binding seals
  as it always did, on a 1xx; drops an HTTP/2 upstream's interim 101 (which takes that hook, not the 101
  refusal above, and would otherwise end the response); and puts the proxy's own headers (CORS,
  `X-Request-Id`) back on the final response, never over one it sets.
- In the first two cases the binding still held, since a raw ID gets 404, but the upstream's own session
  ID leaked. All three affected v0.1.0-rc.1.

