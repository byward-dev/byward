# mcp-authproxy

An auth-only proxy between **MCP clients** and an **upstream** MCP server. It makes the
upstream look like a spec-compliant OAuth-protected MCP server, delegating user
authentication to an **IdP**.

## Language

**MCP client**:
The application speaking MCP to us on the user's behalf (Claude, VS Code, Cursor, ChatGPT, MCP Inspector).
_Avoid_: client (alone), agent, consumer

**Client registration**:
How an **MCP client** obtains a client identity at the **broker**: Dynamic Client Registration (DCR, RFC 7591), a Client ID Metadata Document (CIMD), or a static pre-registered client.
_Avoid_: DCR (when meaning any of the three), app registration

**Client trust level**:
How far the **broker** vouches for an **MCP client**'s identity on the **consent** page: verified (CIMD host trusted by the **operator**), domain (any other CIMD host, shown as-is) or not verified (DCR).
_Avoid_: verified app, trusted client (alone)

**IdP**:
The external identity provider that authenticates the **user** (Entra ID, Keycloak, Okta, Google, …). Always the IdP — never "upstream".
_Avoid_: upstream, auth server (ambiguous), provider (alone, except in code as `idp.Provider`)

**IdP app**:
Our own static OAuth client registration at the **IdP** (e.g. an Entra app registration), configured by the **operator**.
_Avoid_: client, app (alone)

**Upstream**:
The MCP server behind the proxy — reached over HTTP or spawned as a stdio process. Always the MCP server.
_Avoid_: backend, target, origin, downstream

**Upstream process**:
The OS process of a stdio **upstream**; it never serves more than one **user** (ADR-0003).
_Avoid_: child, backend process, worker

**Era**:
The family of MCP spec revisions a request belongs to: legacy (`initialize` handshake, 2025-11-25 and earlier) or modern (stateless, 2026-07-28 and later).
_Avoid_: protocol mode, version (when meaning the family)

**MCP session**:
A legacy-era session between an **MCP client** and an **upstream**, identified by `Mcp-Session-Id` and bound to one **user**.
_Avoid_: session (alone — ambiguous with login/browser sessions), connection

**Broker**:
The proxy's authorization-server role toward **MCP clients**: it serves AS metadata, handles **client registration**, consent, `/authorize`, `/token`, and itself acts as an OAuth client of the **IdP** using the **IdP app**.
_Avoid_: proxy AS, OAuth proxy, authorization server (alone)

**IdP token**:
A token issued by the **IdP** (ID token, access token, refresh token).
_Avoid_: upstream token, access token (alone)

**Proxy token**:
A token issued by the **broker** to an **MCP client**, audience-bound to this proxy's resource URL.
_Avoid_: access token (alone), session token

**Grant**:
One **user**'s authorization of one **MCP client** at the **broker**; it owns the refresh-token family and the stored **IdP tokens**, and revoking it ends every **proxy token** issued under it.
_Avoid_: session, authorization (alone)

**Downstream API**:
An API the **upstream** calls on the **user**'s behalf (e.g. Microsoft Graph); the MCP spec calls it an "upstream API".
_Avoid_: upstream API, backend

**Consent**:
The **user**'s explicit, per-**MCP client** approval recorded by the **broker** before it forwards an authorization request to the **IdP** (required by the MCP security best practices against the confused-deputy problem).
_Avoid_: approval, authorization (alone)

**User**:
The human who signs in at the **IdP** and on whose behalf the **MCP client** acts.
_Avoid_: client, operator

**Operator**:
The person who deploys and configures the proxy (IdP app, upstream, policy).
_Avoid_: user, admin

## Flagged ambiguities

- The MCP spec says "upstream API" (security considerations, token passthrough) for what we call a
  **downstream API**; in this repo **upstream** is always the MCP server behind the proxy. When
  quoting the spec, keep its words and add the mapping.
