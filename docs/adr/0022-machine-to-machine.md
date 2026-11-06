# ADR-0022: Machine-to-machine — accept Entra app-only tokens, opt-in, in v0.1

- Status: Accepted
- Date: 2026-11-06
- Issue: #16 (F15)

## Context

Headless callers (CI, scheduled jobs, agents) cannot run a browser login. MCP defines two extensions
for them: OAuth client credentials (`io.modelcontextprotocol/oauth-client-credentials`) and
Enterprise-Managed Authorization (ID-JAG, draft-ietf-oauth-identity-assertion-authz-grant-06). Entra
issues no ID-JAG.

Clients (source and docs, 2026-11-06):
- The Python SDK v2.3.0, the TypeScript SDK v2.4.0 and the FastMCP client ship client credentials.
- Most headless callers send a token obtained elsewhere as a static header. Claude Code, VS Code,
  Cursor, Gemini CLI, Inspector and Claude.ai (Team/Enterprise) support static `Authorization` headers;
  ChatGPT does not.
- Claude Code `-p` and Agent SDK runs cannot run the OAuth flow; they use `${VAR}` headers or
  `headersHelper`, a command that prints headers.

Entra (Learn, 2026-11-06): client credentials, managed identity and Agent ID (GA) give app-only tokens;
`idtyp` is "the most accurate way" to tell app-only from delegated; checking only `tid` and `oid`
authorizes every service principal in the tenant. OBO "only works for user principals".

Competitors (source) all ship a non-interactive path: oauth2-proxy extra JWT issuers, Pomerium JWT
bearer, agentgateway JWT and API keys, Obot API keys, microsoft/mcp-gateway Entra app roles, ToolHive
ID-JAG. Their advisories:
- token sources mixed by a fallback chain (FastMCP MultiAuth);
- no issuer binding (FastMCP, ToolHive);
- jwt-bearer replay (ToolHive);
- audience confusion (Obot).

agentgateway refuses to send its own IdP credential on a caller's `client_credentials` request.

Runtime (2026-11-06):
- Real tenant, client credentials:
  - **without a role assignment Entra still issued a token**, with no `roles`;
  - with a role: `idtyp: app`, `roles`, no `scp`, `azp` = client, `sub` = `oid` = service principal;
  - "assignment required" and no role: AADSTS501051, no token;
  - header `typ: JWT`, `alg: RS256`, `aud` = the API's client ID, v2 `iss`.
- Claude Code 2.1.142 with `headersHelper`:
  - the helper runs once per connection;
  - a 401 at connect tries OAuth discovery and `/register`, then drops the server without running the
    helper again;
  - a 401 mid-session runs the helper again, reconnects and retries the call.

## Decision

1. **The MCP endpoint accepts Entra app-only tokens**, off by default
   (`MCP_AUTHPROXY_APP_TOKENS=entra`), Entra only.
2. **The validator is chosen by token format, never by fallback:** our type prefix → sealed path
   (ADR-0014); a three-part JWT → the app-only path, only when enabled; anything else → 401.
3. **App-only path checks:** signature from the tenant's JWKS; `alg` `RS256` and `typ` `JWT` pinned;
   `iss` = the configured tenant's v2 issuer; `aud` = our app's client ID; `exp`/`nbf` with the 30 s
   leeway; **`idtyp` = `app` and no `scp`**, so a delegated Entra token is never accepted directly.
4. **Access gate:** at least one required app role (startup refuses an empty role list on this path);
   optional `azp` allowlist. Never `tid` plus `oid` alone. Checked on every request, since there is no
   grant.
5. **Principal:** `sub` = the service principal's `oid`; the identity assertion (ADR-0016) adds
   `principal_type: client` (users get `principal_type: user`); stdio runs one process per client
   principal under the same caps (ADR-0003). No consent, refresh or OBO on this path.
6. **`init entra`** adds an app role for applications, the `idtyp` optional claim and "assignment
   required".
7. **Audit and metrics** count app-only results separately (ADR-0021).
8. **Docs:** `headersHelper` and `${VAR}` examples that fetch a fresh token on every run (GitHub
   Actions OIDC → Entra, managed identity); role changes for managed identities take hours because of
   token caching.
9. **Never send our IdP credential on a caller's behalf** (invariant 19). `/token` answers
   `client_credentials` and `jwt-bearer` with `unsupported_grant_type`; metadata does not list them.
10. **v0.2:** client credentials at our own authorization server; ID-JAG once Entra issues it or users
    ask.

## Consequences

- Amends ADR-0014: a second token type at the MCP endpoint, chosen by format.
- A 401 to Claude Code triggers a `/register` attempt; ADR-0008 deletes never-used registrations after
  24 h.
- Delegated Entra tokens keep going through the broker; only app-only tokens bypass it.
- The real-Entra CI lane (F21) tests the GitHub Actions OIDC path end to end.

## Considered options

- Client credentials and jwt-bearer at our `/token`, issuing sealed tokens: v0.2; callers need an extra
  exchange step, and jwt-bearer needs a replay store.
- Defer all M2M: rejected; headless callers would reach the upstream around the proxy.
- Try validators in turn: rejected; that is the FastMCP MultiAuth flaw.
