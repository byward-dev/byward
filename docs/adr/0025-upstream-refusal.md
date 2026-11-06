# ADR-0025: Upstream refusals are answered as JSON-RPC responses

- Status: Accepted
- Date: 2026-11-06
- Issue: #48 (follow-up to the slice 1.1 review)

## Context

The proxy only relays a request after checking the client's proxy token (ADR-0014), and it never
passes that token on (ADR-0003). So an upstream 401 or 403 means the upstream refused **the
proxy**: its credential (ADR-0016 §7) or its identity assertion, for example a missing role. Signing
the user in again cannot fix that.

MCP 2026-07-28 defines 403 only for the client's own token ("Invalid scopes or insufficient
permissions"), and tool-level failures as a tool result with `isError: true` ("Tool Execution
Error"). RFC 9110 §15.6.3 reserves 502 for an "invalid response" from the upstream, and a 403 is a
valid one.

Clients, read from source at their latest releases and tested at runtime on 2026-11-06 (research
S11-upstream-403, -status, -runtime):

| Client | 403 without a challenge | 502 | 200 with a JSON-RPC response |
|---|---|---|---|
| VS Code 1.145.2 (source) | treated like 401: new token, then forced re-registration | any status ≥ 300 puts the server into an error state and cancels pending requests | normal |
| go-sdk 1.8.0 (runtime) | session closed | call fails, session kept | normal |
| MCP Inspector 2.14.0 (runtime) | classified `auth_required` | plain error | normal |
| gemini-cli 0.67.0 (source) | server flagged as disconnected | server flagged as disconnected | normal |
| Claude Code 2.1.142 (runtime, no OAuth session) | one call, body shown to the model | same | normal |
| TS SDK 1.32.2, Python SDK 2.3.0 (runtime) | error, session kept | same | normal |

Competitors pass the upstream's 403 through (agentgateway, oauth2-proxy, Pomerium for a bare 403),
or send their own denials as 403 (ToolHive). Every one of them hits at least one row above.

## Decision

When the upstream answers **401 or 403**, its `WWW-Authenticate` header and the rest of its
headers are dropped, and:

1. **Anything but `POST`:** 405. For `GET` that is the spec's "no stream offered", for `DELETE`
   "termination not allowed"; clients treat both as harmless.
2. **A notification (no `id`):** 202.
3. **A request whose upstream body is already a JSON-RPC response with the same `id`:** that body,
   with status 200, so the upstream's own message arrives.
4. **Any other request:** 200 with a response to the request's `id`, the `id` echoed byte for byte:
   - `tools/call`: a tool result with `isError: true` and the text "The upstream MCP server denied
     this request; ask your operator." (for 401: "…rejected the proxy's credentials…");
   - other methods: JSON-RPC error `-32603` with the same message and
     `data.upstreamStatus`.
5. **If the `id` can't be read** (a batch, a truncated copy, or not JSON-RPC): 502.
6. **Every case** is logged at error level with the request ID, the upstream status and a hint
   (check the upstream credential, or the roles it requires).

To answer with the right `id`, the relay keeps a bounded copy (64 KiB) of each request body as it
streams to the upstream, and parses it only on this path. The upstream body is always read and
closed, so its connection returns to the pool. _Amends ADR-0003 §1_: the relay stays
byte-transparent except for upstream refusals. ADR-0021 is unchanged: bodies never reach logs.

## Consequences

- Clients see a readable denial instead of a login screen, a dead server or a closed session, and
  the model can tell the user to contact the operator.
- Upstream authors should deny tools with an `isError` result. An HTTP 401 or 403 from them is
  translated; the claims-contract doc (slice 4.1) says so.
- Memory: at most 64 KiB per in-flight request, so 4 MiB at the default cap of 64.
- A metric for upstream refusals is added with the metrics in slice 5.1.
- Unverified until the real-client check (slice 1.7): Claude Code inside an OAuth session, VS Code
  at runtime, Cursor and ChatGPT.

## Considered options

- Pass the 403 through, with or without its challenge: VS Code, go-sdk and Inspector misbehave.
- 502 or 500: VS Code and gemini-cli mark the server broken, and 502 misstates the upstream's answer.
- 401 with our challenge: a login loop, since signing in again cannot fix the upstream's refusal.
- Other 4xx codes (400, 409, 422, 424): wrong semantics, and go-sdk drops the connection.
- A setting to choose the behaviour: none needed yet.
