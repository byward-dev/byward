# ADR-0009: Redirect URI policy — exact HTTPS, any-port loopback, re-checked at /token

- Status: Accepted
- Date: 2026-11-05
- Issue: #9 (F8)

## Context

MCP 2026-07-28: "All redirect URIs **MUST** be either `localhost` or use HTTPS" (its own CIMD
example uses `http://127.0.0.1:3000/callback`). RFC 8252 §7.3: "The authorization server MUST
allow any port … for loopback IP redirect URIs" (`127.0.0.1`, `[::1]`); §8.3: `localhost` is
"NOT RECOMMENDED". RFC 9700 §2.1 and §4.1.3: exact string matching except variable ports for
loopback; §2.6: no `http` except native loopback.

Clients (docs, 2026-11-05): Claude Code declares `http://localhost/callback` and
`http://127.0.0.1/callback` with no port and needs both matched port-agnostically; hosted Claude
uses `https://claude.ai/api/mcp/auth_callback`; VS Code `http://127.0.0.1:33418/` and
`https://vscode.dev/redirect`; Cursor `http://localhost:8787/callback` and
`https://www.cursor.com/agents/mcp/oauth/callback`; ChatGPT uses the stable
`https://chatgpt.com/connector_platform_oauth_redirect` only when the server sends RFC 9207 `iss`.

Competitors: Pomerium, babs, Obot, xnyzer and lethek allow any loopback port (Pomerium not for
`[::1]`); only workers-oauth-provider and lethek re-check the redirect URI and S256 at `/token`;
FastMCP's upstream client allows unregistered redirect URIs, agentgateway echoes them unchecked,
babs allows custom schemes as an opt-in.

## Decision

1. **HTTPS:** exact string match.
2. **Loopback** (`127.0.0.1`, `[::1]`, `localhost`): `http` only, any port whether or not the
   registration has one; scheme, host, path and query identical; each host literal is its own entry.
3. **Rejected:** custom schemes (MCP MUST), any other `http`, wildcards, fragments, userinfo.
4. **Optional operator allowlist** for HTTPS redirect URIs; empty means any HTTPS URI the client
   registered, with the redirect host shown on consent. Startup rejects wildcard or non-HTTPS
   allowlist entries and an `http` issuer outside development mode.
5. **Re-checked at `/authorize` and `/token`** (code and refresh), so a narrowed allowlist takes
   effect at the next refresh.
6. **An invalid redirect URI gets an error page, never a redirect** (no open redirector).
7. **Limits:** at most 10 redirect URIs per registration, 512 characters each (configurable).
8. **Diagnostics:** errors say "registered X, sent Y"; logs record scheme, host and path, never
   the query; a mismatch metric by reason.
9. **Tests:** matching is a pure function with table-driven tests; every client's documented URIs
   are fixtures and documentation, not presets in code (Claude Code's host changed twice).

## Consequences

- _Amended by ADR-0010:_ **deliberate deviation.** The MCP security best practices say redirect
  URIs "Use exact string matching (not pattern matching or wildcards)". Rule 2 ignores the port on
  loopback because RFC 8252 §7.3 ("MUST allow any port … for loopback IP redirect URIs") and
  RFC 9700 §4.1.3 require it, and Claude Code registers loopback URIs without a port. Everything
  else is matched exactly.

- Clients that only offer custom schemes are unsupported, as the spec requires.
- ChatGPT's stable redirect URI depends on RFC 9207 `iss` (F16).
- Our consent page is the only place a user sees the redirect host — the IdP's consent names only
  our IdP app — so ADR-0009 depends on F7 showing it.

## Amendment 2026-11-06 (DCR, slice 2.2)

A DCR registration (RFC 7591) that lists some redirect URIs failing rules 1–3 **keeps the ones
that pass**. The registration succeeds, its response lists only the kept URIs (RFC 7591 §3.2.2
lets the server substitute values), and the operator log records the dropped ones at info with the
client ID, not as an error, following rule 8 (scheme, host and path, never the query).
`invalid_redirect_uri` is returned only when none passes. CIMD documents are unchanged: a single
failing URI still refuses the document, because the proxy cannot change a document it does not
own.

Why: Cursor registers `cursor://anysphere.cursor-mcp/oauth/callback` together with
`https://www.cursor.com/agents/mcp/oauth/callback` (Cursor 3.14.27; redirect URIs confirmed by
Cursor staff at forum.cursor.com/t/171867; fixture `internal/testutil/clientdocs/testdata/dcr/cursor.json`).
Refusing the whole registration would turn Cursor away over a URI the proxy would never redirect
to anyway.

**Cursor desktop's `cursor://` callback is not accepted; Cursor is verified in the HITL
compatibility run.** If Cursor desktop sends `redirect_uri=cursor://…` at `/authorize`, the proxy
shows its invalid-redirect error page (rule 6), so this amendment alone does not prove that Cursor
works. Rule 3 still rejects custom schemes, and this slice does not loosen it. Whether to allow
custom schemes for desktop apps is a separate decision for the maintainer, to be made once the
compatibility run shows what Cursor actually sends.
