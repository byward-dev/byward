# ADR-0013: Discovery and errors — both well-known paths, one issuer, `iss` everywhere

- Status: Accepted
- Date: 2026-11-05
- Issue: #17 (F16)

## Context

MCP 2026-07-28: servers offer `resource_metadata` in `WWW-Authenticate` or a well-known URI; clients
use the header URL when present, otherwise "**MUST** fall back to constructing and requesting the
well-known URIs in the order listed" — path-inserted, then root. For authorization-server metadata the
`issuer` "**MUST** be identical to the issuer identifier used to construct the well-known URL. If they
differ, the client **MUST NOT** use the metadata". Servers "**SHOULD** include the `iss` parameter in
authorization responses, including error responses" and advertise it; the spec expects this to become
a MUST. RFC 9728 §3.3: `resource` must be identical to the identifier the well-known path was built
from. Streamable HTTP: "Servers **MUST** validate the `Origin` header on all incoming connections".

Clients: Claude uses the first `authorization_servers` entry and does not fall back, and requires
`resource` to equal the URL as the user entered it; ChatGPT needs an exact issuer and `iss` on every
authorization response for its stable redirect URI; Claude Code (TypeScript SDK discovery) tries the
path-aware URL first, treats CORS failures as a reason to fall back, and sends `MCP-Protocol-Version`
on metadata requests. MCP Inspector web routes OAuth requests through its own backend; the official
MCP authorization tutorial enables CORS on its example server. Competitors (grep-level): only babs
serves both protected-resource paths and `iss` on errors; sigbit #95 shipped a hard-coded issuer;
workers-oauth-provider is the only one with browser-oriented CORS (exposing `WWW-Authenticate`).

## Decision

1. **Protected resource metadata** at both the path-inserted and the root well-known URI, identical:
   `resource` = the public MCP URL exactly as users enter it, without a trailing slash;
   `authorization_servers` = our issuer only; `scopes_supported`; `bearer_methods_supported`
   `["header"]`; `resource_name`; `resource_documentation`.
2. **Authorization-server metadata** at `/.well-known/oauth-authorization-server` and
   `/.well-known/openid-configuration` (path-inserted when the proxy runs under a path prefix), with an
   `issuer` derived once from the configured public URL and used identically everywhere, the ADR-0008
   flags and `revocation_endpoint` (ADR-0006).
3. **RFC 9207 `iss`** on every authorization response, success and error, with
   `authorization_response_iss_parameter_supported: true`.
4. **Errors:** an invalid redirect URI or client gets an HTML page (400), never a redirect; other
   `/authorize` errors redirect with `error`, `state` and `iss`; `/token`, `/register` and `/revoke`
   return JSON with `Cache-Control: no-store` (400, or 401 with `WWW-Authenticate` for client
   authentication failures); `error_description` uses fixed strings, never raw IdP text.
5. **401 on the MCP endpoint:** `WWW-Authenticate: Bearer resource_metadata="…", scope="…"`, plus
   `error="invalid_token"` when a token was presented. Authorization denials and
   `insufficient_scope` are F12's.
6. **CORS on the discovery and OAuth endpoints only** (metadata, `/token`, `/register`, `/revoke`):
   echo the `Origin`, no credentials, allow `Authorization`, `Content-Type` and
   `MCP-Protocol-Version`, expose `WWW-Authenticate` and `Retry-After`. The consent page and callback
   are navigations and get none. The MCP endpoint's `Origin` allowlist (403 otherwise) is F17's.
7. **`Cache-Control: max-age=3600`** on metadata documents (RFC 9728 §7.10); errors are never cached.
8. **`doctor` self-probe:** fetch our metadata as each client does (path-inserted, then root); check
   `resource` against the public URL, `issuer` identity everywhere, `authorization_servers[0]`, the
   ADR-0008 flags, and that an unauthenticated POST returns a 401 whose `resource_metadata` resolves.

## Consequences

- Our metadata is public interface: fields are only ever added.
- Each client rule above becomes a test fixture (F21).
- Signed metadata (RFC 9728 `signed_metadata`) is not produced: no client verifies it.
