# ADR-0003: Upstream kinds — HTTP relay; stdio processes never shared between users

- Status: Accepted; amended by ADR-0025
- Date: 2026-11-05
- Issue: #2 (F1)

## Context

The proxy fronts MCP servers reached over HTTP and servers spawned as stdio processes. A stdio
server is built for exactly one client, and the spec says stdio implementations "SHOULD NOT"
use OAuth and take credentials from the environment — the proxy is how a stdio server gets
OAuth at all.

Prior art (source read 2026-11-05, see `docs/research/reference-projects.md`):

- **Shared process, proxy re-serves** (sigbit, sparfenyuk, TBXark): loses sampling,
  elicitation, roots and most notifications; the proxy becomes an MCP implementation.
- **Shared process, raw relay with id rewriting** (ToolHive): needs an `initialize` cache and
  per-session notification routing, and still rejects server→client requests (ToolHive #5744).
  Sharing without that care leaked replies between clients (supergateway < 4.1.0,
  ContextForge #4205).
- **Process per MCP session** (agentgateway, supergateway `--stateful`, Docker gateway
  `--long-lived`): byte-transparent, full feature fidelity, no cross-client leakage.
- **Process per user** (stainless-api/mcp-front; nicknikolakakis/mcp-auth-gateway, which
  injects the IdP token into the child — effectively passthrough): small and unmaintained.
- No project passes the user's identity into a shared stdio process safely; ContextForge's
  header→env restart is documented as unsafe for more than one client.

Spec 2026-07-28 changes this for the modern era: "The server **MUST NOT** write JSON-RPC
_requests_ to `stdout`" (server→client requests use MRTR), and "an open connection, such as a
STDIO process, is not a conversation or session". An `initialize` "selects legacy semantics,
scoped to the stdio process".

Clients (read 2026-11-05): Claude Code 2.1.318 and claude.ai probe `server/discover` and use
2026-07-28 when offered (claude-ai-mcp #1027 server log); VS Code and Cursor speak 2025-11-25
only. claude.ai chat opens a fresh 2025-11-25 session before essentially every tool call
(claude-ai-mcp #583, open). Most clients never send DELETE.

Measured on macOS 2026-11-05: the reference stdio servers (`everything`, `filesystem`,
`memory`, `time`, `fetch`) are dual-era; `@playwright/mcp` is legacy-only. Warm start-up
0.3–0.5 s; 120–240 MB per process including the `npx`/`uvx` launcher (~40 % of it). Four
`memory` processes on one file lost no writes but every session saw every other session's
entities.

## Decision

1. **HTTP upstream: byte-transparent reverse proxy.** The inbound `Authorization` header is
   always removed (no token passthrough). The upstream receives the authenticated user's
   identity per F13, which is a v1 requirement (ADR-0004). _Amended by ADR-0025:_ an upstream 401
   or 403 is answered as a JSON-RPC response, which needs the request's `id`.
2. **Invariant: an upstream process never serves more than one user.**
3. **Legacy-era traffic (2025-11-25): one upstream process per MCP session.** JSON-RPC is relayed
   unchanged — no id rewriting, no `initialize` cache; server→client requests and notifications
   behave as the server intends.
4. **Modern-era traffic (2026-07-28): one upstream process per user** (keyed by the IdP subject),
   used only when the stdio server answers a `server/discover` probe. JSON-RPC ids are rewritten
   only to separate that user's concurrent MCP clients.
5. **Guardrails:** per-upstream and per-user caps on live processes with least-recently-used
   eviction of idle ones; idle timeout (default 30 min); stderr always drained and logged; a
   crash fails only the affected session or user.
6. **Placeholders in upstream `args`/`env`** (e.g. `{session_dir}`, a per-session temp
   directory removed on close) so servers with fixed-path state can be isolated. User-derived
   placeholders are decided in F13.
7. **stdio upstreams act as the operator's service identity.** The proxy gates who reaches the
   upstream; per-user credentials for stdio are v2, with F13.
8. **No legacy HTTP+SSE upstream** (deprecated in 2026-07-28, SEP-2596).

## Consequences

- Memory scales with concurrent sessions and users; the caps and idle timeout are mandatory
  configuration. Docs recommend launching servers directly rather than via `npx`/`uvx`.
- A legacy-only stdio server used from claude.ai chat costs one process per tool call (#583);
  the per-user cap bounds it. Session-scoped server state is lost in that client regardless of
  the proxy.
- Servers that share host state across instances (`memory`, Desktop Commander, sqlite, git on
  one repo) expose one session's data to another unless the operator isolates it with
  placeholders; docs must say so. Browser servers need `--isolated` or a per-session
  `--user-data-dir`.

## Alternatives considered

- **One shared stdio process for all users** — rejected: loses or rejects server→client features
  on 2025-11-25; on 2026-07-28 users share in-process state and an upstream cannot bind MRTR
  `requestState` to a principal it cannot see.
- **Proxy as the only MCP client, re-serving the upstream** — rejected: makes the proxy an MCP
  gateway (ADR-0001 non-goal).
- **Process per request** — rejected: 0.3–0.5 s per call, loses server state, no server→client
  requests.
- **Defer the modern era for stdio to v1.x** — rejected: claude.ai chat would fall back to
  2025-11-25 and spawn a process per tool call.
- **Legacy SSE upstream** — rejected: deprecated; no evidence of demand.
