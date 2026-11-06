# ADR-0010: Consent screen — before the IdP, per client, remembered only for trusted clients

- Status: Accepted
- Date: 2026-11-05
- Issue: #8 (F7)

## Context

The MCP spec: proxies with a static client ID "**MUST** obtain user consent for each dynamically
registered client before forwarding to third-party authorization servers", and "**MUST** clearly
display the redirect URI hostname". The MCP security best practices require proxies to "Maintain a
registry of approved `client_id` values per user" and "Check this registry **before** initiating the
third-party authorization flow"; the page MUST name the client, "Display the specific third-party
API scopes being requested", show the redirect URI, implement CSRF protection and prevent framing;
consent cookies MUST be `__Host-`, `Secure`, `HttpOnly`, `SameSite=Lax`, signed and bound to the
client; `state` is stored "**only after** consent" and set "**immediately before**" the IdP redirect.
OWASP ASVS 5.0.0 10.7.1 (L2): "If the identity of the client cannot be assured, the authorization
server must always explicitly prompt the user for consent"; 10.7.2 adds "the lifetime of these
authorizations"; 10.7.3 asks for review and revocation. RFC 9700 §4.16 requires clickjacking
prevention; RFC 6749 §4.1.2.1 forbids redirecting to an invalid redirect URI.

Competitors (source, 2026-11-05): Pomerium, agentgateway and sigbit have no real per-client consent.
ToolHive and babs are the references: ToolHive requires exactly one matching `Origin`, labels names
"(not verified)" and checks the user after the callback; babs denies with `access_denied` + `state` +
`iss` and runs without JavaScript. lethek notes the flow ID is not CSRF protection. FastMCP
remembers per browser for 365 days and breaks on double clicks (#5774).

Clients open the page in the system browser (VS Code, Gemini CLI, Claude Code, Cursor) or the same
tab (Inspector web); claude.ai, ChatGPT and mobile contexts are undocumented; none frames it.
Browser cookies therefore cannot carry remembered consent reliably. Safari does not accept `Secure`
cookies over `http://localhost`. Browsers disagree on whether `form-action` blocks the redirect after
a form submission (MDN), and ToolHive omits it for that reason. Entra shows its own consent unless an
admin grants tenant-wide consent, and labels unverified publishers "Unverified".

## Decision

1. **Consent happens before the IdP redirect**, for every client.
2. **When to ask:** static clients and verified CIMD hosts (ADR-0008 client trust levels) are asked
   once and then remembered; domain CIMD hosts and DCR clients are asked every time (ASVS 10.7.1).
3. **Remembered consent is a server-side registry** keyed by user (`tid`+`oid` for Entra), client,
   redirect URI and resource, scopes a subset of those approved, 30 days. A sealed `__Host-` cookie is
   only a hint for the check before the IdP redirect; without it we ask. After the callback the
   registry is checked for the actual user; a mismatching hint is discarded and the page is shown.
   `prompt=consent` forces the page.
4. **The page shows:** the client name with its trust level (control characters stripped, 80
   characters), the CIMD host, the redirect host (loopback: "an app on this computer" plus a warning;
   punycode beside Unicode; a warning if it differs from the CIMD host), the upstream, the IdP ("You'll
   sign in with Microsoft Entra next"), the IdP scopes we request in operator-supplied plain words with
   the raw strings behind a disclosure, the lifetime ("up to 30 days"), and the operator's name and
   optional logo. Advertised scopes without operator text are a startup warning.
5. **CSRF:** exactly one `Origin` equal to our configured public URL (never the `Host` header);
   missing or `null` is rejected; `Sec-Fetch-Site: same-origin` as a second check; a `__Host-`
   binding cookie whose name includes an instance ID; a sealed single-use flow token (10 minutes)
   consumed atomically, with an idempotent double submit; `state` set only after Allow.
6. **Headers on every response:** CSP `default-src 'none'; script-src 'none'; object-src 'none';
   base-uri 'none'; frame-ancestors 'none'` plus same-origin styles and images (no `form-action`);
   `X-Frame-Options: DENY`; `Cache-Control: no-store`; `Referrer-Policy: same-origin`; no
   `Cross-Origin-Opener-Policy: same-origin`. No external assets. _Amended 2026-11-06 (slice 1.4):_
   `no-referrer` made Chromium post the consent form with `Origin: null` (Fetch serialises the
   origin as `null` for a non-CORS POST under that policy), which §5 rejects; `same-origin` still
   sends no referrer to any other origin.
7. **Page behaviour:** server-rendered, no JavaScript; Allow and Deny equal in weight, neither
   auto-focused; Allow accepted only after about 1 s (server-side); WCAG 2.2 AA; an expired flow gets
   a "start again from your app" page.
8. **Deny** returns `access_denied` with `state` and `iss` to a validated redirect URI only; anything
   else gets an error page.
9. **IdP leg:** `response_mode=query`, never `form_post`, so the `SameSite=Lax` binding survives.
10. **Development mode** on loopback `http` uses cookies without the `__Host-` prefix (Safari),
    logged as development-only and refused otherwise. Cookie formats are versioned.
11. **Revocation:** operator commands in v0.1 (they also end the grant, ADR-0006); a user-facing
    "connected apps" page is v0.2.
12. **Audit events** for consent shown, granted, denied and remembered consent used; metrics per
    client trust level.

## Consequences

- **Known gap:** ASVS 10.7.3 (L2, user review and revocation) is met only through the operator until
  the v0.2 page; the security-posture page says so.
- Users in ephemeral or mobile browser sessions may see the page more often; that is the safe outcome.
- Without tenant-wide admin consent, users see Entra's consent after ours; the Entra setup guide (F10)
  recommends admin consent and covers publisher verification and user assignment.
- Test matrix (F21): Claude Code or Gemini CLI, Inspector web, claude.ai web automated; mobile and
  ChatGPT checked by hand before each release.

## Considered options

- Consent after the IdP login (we would know the user) — rejected: the spec requires it before.
- Remembered consent in a browser cookie only (FastMCP) — rejected: unreliable across client browser
  contexts and weaker than per user.
- Always ask every client — rejected: the best practices require a per-user registry, and ASVS allows
  remembering clients whose identity is assured.
- `form-action 'self'` or babs's interstitial page — rejected: Chrome would block the post-submit
  redirect; the interstitial adds a hop for no extra protection given no scripts and `base-uri 'none'`.
- Rich authorization requests, consent receipts, passkey re-confirmation, a per-user "always deny"
  list, i18n and custom templates — later or rejected.
