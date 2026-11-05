# ADR-0015: Authorization — an access gate at login and refresh, no per-request denials in v0.1

- Status: Accepted
- Date: 2026-11-05
- Issue: #13 (F12)

## Context

MCP 2026-07-28 defines scopes and 403 `insufficient_scope` step-up ("more scope will fix it") but no
"forbidden" signal for tools, and no per-tool authorization beyond "Implement proper access controls".
Clients (source): VS Code treats 401 and 403 alike and, on a 403, retries and then re-registers
(`forceNewRegistration`); the TypeScript SDK re-authorizes with a union of scopes; Claude Code shows
"needs additional permissions" and asks the user to edit scopes. A hard deny sent as 403 therefore
loops or misleads. Per-tool rules would need the JSON-RPC body (breaking the byte-transparent relay,
ADR-0003) or the 2026-07-28 `Mcp-Name` header, which legacy clients do not send.

Reliable rule inputs in the ID token: Entra `roles` (confirmed in a real tenant), `groups` when
configured (overage → unavailable), `tid`; Okta `groups` if configured; Keycloak roles only with "Add
to ID token"; Google only `hd` and `email_verified`. Microsoft Learn: unassigned users get AADSTS50105
when "Assignment required" is on, but "Users with a Global Administrator role can sign in to
applications, regardless of the assignment required settings"; an assignment to "Default Access" adds
no `roles` claim; nested groups do not count.

Competitors (source): babs and sigbit gate at login (babs re-checks at refresh); Pomerium, agentgateway,
ToolHive (Cedar), Microsoft's gateway and Obot do per-tool rules — agentgateway's CEL deny rules fail
open on expression errors, Kong and FastMCP had authorization bypasses, and ToolHive sets the bar
(reject batches, match mirrored headers to the body, exact names, filter every list, deny by default).
Nobody ships 403 step-up.

## Decision

1. **The access gate** is checked when a grant is created and at every refresh, before any proxy token
   is issued — never per MCP request. Optional allowlists: tenant (`tid`), required app roles
   (`roles`), groups (opt-in, `ApplicationGroup`; overage denies), email domain with `email_verified`
   (generic IdPs), `hd` (Google).
2. **Denials:** at login, our error page ("you don't have access — ask your operator"); at refresh,
   `invalid_grant`, so the client signs in again and lands on that page. No 403 is ever used for a
   denial; with a single scope in v0.1 there is no step-up either.
3. **Empty gate:** for single-tenant Entra it allows every user of the tenant, with a warning at every
   startup and in `doctor` ("all users of tenant X can sign in; guests too unless restricted"). For
   Google and multi-tenant IdPs an empty gate refuses to start unless an explicit flag allows it,
   logged at every start.
4. **Setup guide:** Entra "Assignment required" plus app roles first, noting that Global
   Administrators bypass assignment at the Entra level (our role gate still applies) and that "Default
   Access" carries no `roles`.
5. **Gate configuration is validated at startup;** invalid configuration refuses to start. Every
   denial is audited (F20). stdio upstreams get the same gate.
6. **Not in v0.1:** per-tool rules and `tools/list` filtering. If added later they must meet ToolHive's
   bar — reject batches, require `Mcp-Method`/`Mcp-Name` and match them to the body (400 / -32020),
   exact case-sensitive names, filter every list including streamed ones, deny by default, never fail
   open — and stay simple allow/deny lists (ADR-0001: no policy language). An "exclude guests" option
   using the `acct` claim (`1` for guests per Microsoft's docs) is a later candidate.

## Consequences

- Revoking someone's access takes effect at their next refresh (at most one access-token lifetime) or
  immediately through the operator's revoke commands (ADR-0006).
- The gate's configuration keys become public interface.
