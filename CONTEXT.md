# byward

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
The external identity provider that authenticates the **user** (Entra ID, Keycloak, Okta, Google, …), reached through the **environment proxy** when one applies. Always the IdP — never "upstream".
_Avoid_: upstream, auth server (ambiguous), provider (alone, except in code as `idp.Provider`)

**IdP app**:
Our own static OAuth client registration at the **IdP** (e.g. an Entra app registration), configured by the **operator**.
_Avoid_: client, app (alone)

**IdP preset**:
A named set of defaults for the generic OIDC **IdP** adapter (`google`, `okta`, `auth0`, `keycloak`); data, not code. Entra is an adapter of its own, not a preset.
_Avoid_: provider type, connector

**Rate limit**:
A per-minute budget of requests to one of the **broker**'s OAuth endpoints from one client address (IPv6 grouped by /64). Never applied to MCP traffic.
_Avoid_: throttle (alone), quota

**Upstream**:
The MCP server behind the proxy — reached over HTTP (through the **environment proxy** when one applies) or spawned as a stdio process. Always the MCP server.
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

**Protected resource**:
The proxy's resource-server role toward **MCP clients**: it serves protected resource metadata (RFC 9728) and admits MCP requests only with a valid **proxy token** (ADR-0013, ADR-0014).
_Avoid_: RS (alone), gateway, resource (alone)

**IdP token**:
A token issued by the **IdP** (ID token, access token, refresh token).
_Avoid_: upstream token, access token (alone)

**Proxy token**:
A token issued by the **broker** to an **MCP client**, audience-bound to this proxy's resource URL.
_Avoid_: access token (alone), session token

**Identity assertion**:
The short-lived JWT (RFC 9068 `at+jwt`) the proxy signs and sends an HTTP **upstream** on every request, saying which **user** and **MCP client** it is for; never the client's token (ADR-0016).
_Avoid_: forwarded token, identity header (alone), passthrough

**Plain identity headers**:
The opt-in `X-Byward-*` headers that repeat the **identity assertion**'s values, unsigned, for an HTTP **upstream** that cannot verify a JWT; safe only when the upstream is reachable through the proxy alone (ADR-0016 §5).
_Avoid_: identity header (alone), trusted headers, forwarded user

**App-only token**:
An **IdP token** that a headless caller (CI job, managed identity, agent) got with its own credential, with no **user** behind it, and sends the MCP endpoint instead of a **proxy token**; accepted only from Entra, opt-in, with a required app role (ADR-0022). Its caller is a client principal (see **principal type**).
_Avoid_: service token, machine token, M2M token (alone)

**Upstream credential**:
The operator's own header value (e.g. an API key) the proxy sends an HTTP **upstream** on every request, read from a secret file, in a header the **identity assertion** does not use; never a **user**'s or **MCP client**'s token (ADR-0016 §7).
_Avoid_: upstream token, service token, passthrough

**Grant**:
One **user**'s authorization of one **MCP client** at the **broker**; it owns the refresh-token family and the stored **IdP tokens**, and revoking it ends every **proxy token** issued under it.
_Avoid_: session, authorization (alone)

**Downstream API**:
An API the **upstream** calls on the **user**'s behalf (e.g. Microsoft Graph); the MCP spec calls it an "upstream API".
_Avoid_: upstream API, backend

**Downstream token**:
A token for a **downstream API**, obtained by the proxy On-Behalf-Of the **user** and sent to an HTTP **upstream** in a configured header, or given to a stdio **upstream process** through its **token socket**; never stored or logged (ADR-0017).
_Avoid_: OBO token, delegated token

**Access gate**:
The **operator**'s rule for which **users** may use the proxy at all (tenant, app roles, groups, email domain, Google's hosted domain `hd`; the roles and groups claims are configurable for an OIDC **IdP**), checked when a **grant** is created and at every refresh — never per MCP request (ADR-0015).
_Avoid_: policy, ACL, authorization rules (alone)

**Consent**:
The **user**'s explicit, per-**MCP client** approval recorded by the **broker** before it forwards an authorization request to the **IdP** (required by the MCP security best practices against the confused-deputy problem).
_Avoid_: approval, authorization (alone)

**Environment proxy**:
The HTTP proxy `HTTPS_PROXY`, `HTTP_PROXY` and `NO_PROXY` name, which the relay to an HTTP **upstream**, calls to the **IdP**, doctor's self-probe and trace export go through; never byward itself (`internal/envproxy`).
_Avoid_: proxy (alone), egress proxy, forward proxy

**User**:
The human who signs in at the **IdP** and on whose behalf the **MCP client** acts.
_Avoid_: client, operator

**Operator**:
The person who deploys and configures the proxy (IdP app, upstream, access gate).
_Avoid_: user, admin

**User key**:
The stable ID of a **user**, or of an app-only caller, at the **IdP**: `tid:oid` for Entra, the subject claim's value for an OIDC IdP. It is `sub` in the **identity assertion** and `user_key` in audit records.
_Avoid_: user ID (alone), email, username

**Principal type**:
Who a request acts for: `user`, or `client` for an app-only caller (a client principal, with no **user** behind it); sent as `principal_type` in the **identity assertion** and as `BYWARD_PRINCIPAL_TYPE` to an **upstream process** (ADR-0022 §5).
_Avoid_: caller type, actor

**Public URL**:
The MCP endpoint's URL as **MCP clients** reach it (`BYWARD_PUBLIC_URL`); its origin is the **broker**'s issuer, the `iss` of every **identity assertion**.
_Avoid_: base URL, external URL

**Store**:
The **broker**'s persistent state: **grants**, codes, refresh-token hashes, revocations, **client registrations**, remembered **consents**, spent logins and client assertions. SQLite by default, PostgreSQL for several replicas; keys never live in it (ADR-0007).
_Avoid_: database (alone), cache

**Store epoch**:
A number in the **store** that a restore from an older copy moves on; refresh tokens of **grants** from an older epoch are refused, so their **users** sign in again (ADR-0007 §9).
_Avoid_: generation, version

**Sealing key**:
A key from `BYWARD_KEYS_DIR` that seals (AES-256-GCM) **proxy tokens**, codes, stored **IdP tokens** and login and consent state; the key file that sorts last seals, and every key file opens (ADR-0006 §8). Not the key that signs the **identity assertion**.
_Avoid_: signing key, secret

**Deny list**:
The in-memory list of revoked **grants** and subject cut-offs that each replica rebuilds from the **store** every 5 s; a **proxy token** it covers is refused, and every token once the list is too stale (ADR-0006 §3).
_Avoid_: blocklist, revocation cache

**Relaxation**:
A protection turned off by an explicit setting (development mode, `BYWARD_INSECURE_NO_AUTH`), always logged at startup (security invariant 12).
_Avoid_: insecure mode (alone), override

**IdP alert**:
An **IdP** error that will not clear without the **operator**, such as the IdP refusing the **IdP app**'s credential; counted in `byward_idp_alerts_total` and logged once at error level (#204; [observability](docs/reference/observability.md)).
_Avoid_: IdP error (alone), outage

**Upstream refusal**:
An **upstream**'s 401 or 403, which refuses the proxy (its **upstream credential** or **identity assertion**), not the **MCP client**: answered as a JSON-RPC response, never as a sign-in challenge (ADR-0025).
_Avoid_: upstream 403 (alone), auth error

**Token socket**:
The Unix socket the proxy gives a stdio **upstream process** (`BYWARD_DOWNSTREAM_TOKEN_SOCKET`) to ask for its **user**'s **downstream token**; only that process and its descendants are answered (ADR-0017, #141).
_Avoid_: token file, credential endpoint

**Internal listener**:
The second listener (`BYWARD_INTERNAL_LISTEN`, `127.0.0.1:9090` by default) for `/metrics`, `/livez`, `/readyz` and the assertion keys; plain http, never exposed like the public one (ADR-0018 §10).
_Avoid_: admin port, management API

**SSRF guard**:
The only way the proxy fetches a URL an **MCP client** supplied (a CIMD document, a client's `jwks_uri`): `https` on port 443, public addresses checked when dialling, no redirects, size and time limits (ADR-0008 §4; `internal/ssrfguard`).
_Avoid_: URL filter, safe fetcher

**Serving certificate**:
The **operator**'s TLS certificate and key that byward serves on its public listener when it terminates TLS (`BYWARD_TLS_CERT_FILE`, `BYWARD_TLS_KEY_FILE`); a replaced file is served from the next connection on (ADR-0019 §9 as amended, #183).
_Avoid_: TLS cert (alone), ingress certificate

## Flagged ambiguities

- "Proxy" alone is byward. The HTTP proxy the process environment names is the **environment
  proxy**.

- The MCP spec says "upstream API" (security considerations, token passthrough) for what we call a
  **downstream API**; in this repo **upstream** is always the MCP server behind the proxy. When
  quoting the spec, keep its words and add the mapping.
