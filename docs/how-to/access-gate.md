# Restrict who can sign in (the access gate)

The access gate decides which users may use the proxy at all. It is checked when a user signs in
and, once refresh tokens arrive (slice 1.6), at every refresh; never on individual MCP requests. A user the gate turns away sees
"You don't have access to this server. Ask your operator for access." MCP clients never get a 403
for a user gate decision. Background: [ADR-0015](../adr/0015-access-gate.md).

Headless callers with [app-only tokens](app-tokens.md) have their own gate (`BYWARD_APP_ROLES`,
`BYWARD_APP_CLIENT_IDS`), checked on every MCP request, which answers `403` when it refuses;
`BYWARD_GATE_TENANTS` applies to them too.

## Settings

Every list is optional. When several are set, a user must pass all of them. Within one list, any
one entry is enough.

| Setting | Matches | Notes |
|---|---|---|
| `BYWARD_GATE_TENANTS` | Entra `tid` | Tenant GUIDs. In single-tenant mode it must include your tenant; a multi-tenant (`organizations`) app always needs it (ADR-0012 §2). |
| `BYWARD_GATE_ROLES` | `roles` (an OIDC IdP: the claim named by `BYWARD_OIDC_ROLES_CLAIM`, [OIDC how-to](oidc.md#4-who-may-sign-in)) | App role values, case-sensitive. The user needs at least one. |
| `BYWARD_GATE_GROUPS` | `groups` (an OIDC IdP: the claim named by `BYWARD_OIDC_GROUPS_CLAIM`) | Entra group object IDs. If Entra leaves the groups out because the user is in too many (over 200), the user is denied. |
| `BYWARD_GATE_EMAIL_DOMAINS` | email domain | Only verified emails, exact domain (no subdomains). OIDC IdPs only ([OIDC how-to](oidc.md)): not available with Entra, whose `email` is not verified. |
| `BYWARD_GATE_HOSTED_DOMAINS` | Google `hd` | Google Workspace domains, with `BYWARD_IDP=google` only. With exactly one domain, Google is also asked to show only that Workspace's accounts. |
| `BYWARD_GATE_ALLOW_EMPTY` | — | Allows an empty gate where the proxy otherwise refuses to start (see below). |

All lists are comma-separated. An invalid entry, such as a tenant that is not a GUID or an email
domain with Entra, or a list that is set but names nothing, stops the proxy at startup with a
message naming the setting, for example `BYWARD_GATE_TENANTS: "contoso" is not a GUID`.

## Empty gate

- **Single-tenant Entra:** every user of your tenant can sign in, including guests unless you
  restrict them. The proxy starts, and logs a warning at every start.
- **Google or generic OIDC** (not supported yet; listed so the rule is known): anyone with an account could sign in, so the proxy refuses to start
  unless `BYWARD_GATE_ALLOW_EMPTY=true`. With that setting it logs a warning at every start.

## Entra: recommended setup

1. In the enterprise application, set **Assignment required** to **Yes**. Users who are not
   assigned are then stopped by Entra itself (AADSTS50105).
2. Define an app role, for example `MCP.User`, assign it to the users or groups who should have
   access, and set `BYWARD_GATE_ROLES=MCP.User`.
3. Know the two gaps:
   - Global Administrators can sign in regardless of **Assignment required**. The role gate still
     applies to them.
   - An assignment to **Default Access** carries no `roles` claim, so such users fail a role gate.
4. Group-based access is opt-in. Emit only the groups assigned to the application
   (`groupMembershipClaims: ApplicationGroup`), which keeps users well under the overage limit.
   Nested groups do not count.

The gate is read at startup, so a change needs a restart. It then takes effect at each user's next sign-in; with refresh tokens (slice 1.6), at their next
refresh, at most one access-token lifetime later. Every denial is an `access_denied` audit event
([observability reference](../reference/observability.md)) whose `reason` is the rule that refused
the user (`tenant`, `role`, `group`, `groups_unavailable`, `email_domain` or `hosted_domain`), with
the user's pseudonymous key (`user_key`), the client ID and the request ID.
