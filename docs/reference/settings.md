# Settings reference

Generated from the settings registry (`internal/config`); do not edit by hand.
Run `BYWARD_UPDATE_REFERENCE=1 go test ./internal/config/` after changing a setting.

Precedence: flag > environment > default. Secrets are read only from files.

| Flag | Environment | Default | Description |
|---|---|---|---|
| `--public-url` | `BYWARD_PUBLIC_URL` | — | public URL of the MCP endpoint exactly as users enter it, e.g. https://mcp.example.com/mcp; an internationalized host in its ASCII (xn--) form |
| `--upstream-url` | `BYWARD_UPSTREAM_URL` | — | URL of the HTTP upstream MCP server; or set a stdio upstream with upstream-command |
| `--upstream-header-timeout` | `BYWARD_UPSTREAM_HEADER_TIMEOUT` | 5m | how long the HTTP upstream may take to send its response headers; a request that waits longer gets a JSON-RPC timeout error, and a streamed response is not limited once its headers arrive; 1s to 1h (ADR-0018 §7) |
| `--upstream-credential-file` | `BYWARD_UPSTREAM_CREDENTIAL_FILE` | — | HTTP upstream: a header value the proxy sends with every upstream request, such as an API key the upstream needs from the proxy itself; never the user's or the client's token; read at start, never logged (ADR-0016 §7, docs/how-to/upstream-credential.md) |
| `--upstream-credential-header` | `BYWARD_UPSTREAM_CREDENTIAL_HEADER` | Authorization | the header that carries upstream-credential; inbound copies are always removed; it never shares a header with the identity assertion, so with Authorization here set assertion-header to another header (ADR-0016 §7) |
| `--upstream-command` | `BYWARD_UPSTREAM_COMMAND` | — | stdio upstream: the command as a JSON array, e.g. ["/usr/local/bin/server","--flag"], never run through a shell; or give it after -- on the command line (docs/how-to/stdio-upstream.md) |
| `--upstream-env-file` | `BYWARD_UPSTREAM_ENV_FILE` | — | stdio upstream: KEY=VALUE lines set in the environment of each upstream process, besides the inherited PATH, HOME, USER, LOGNAME, TMPDIR, TZ, LANG and LC_* (ADR-0016 §6); values are never logged |
| `--stdio-max-processes` | `BYWARD_STDIO_MAX_PROCESSES` | 64 | stdio upstream: most upstream processes alive at once; when full, the least recently used idle one is stopped (ADR-0003 §5) |
| `--stdio-max-processes-per-user` | `BYWARD_STDIO_MAX_PROCESSES_PER_USER` | 8 | stdio upstream: most upstream processes one user has alive at once; when full, that user's least recently used idle one is stopped |
| `--listen` | `BYWARD_LISTEN` | 127.0.0.1:8080 | address to listen on; public addresses only when configured |
| `--allowed-origins` | `BYWARD_ALLOWED_ORIGINS` | — | comma-separated Origin values allowed on the MCP endpoint (scheme://host[:port]); an internationalized host in its ASCII (xn--) form |
| `--allowed-hosts` | `BYWARD_ALLOWED_HOSTS` | — | comma-separated extra Host values accepted besides the public URL's host; an internationalized host in its ASCII (xn--) form |
| `--scope` | `BYWARD_SCOPE` | mcp | the scope advertised in protected resource metadata and 401 challenges |
| `--resource-name` | `BYWARD_RESOURCE_NAME` | — | human-readable resource name in protected resource metadata |
| `--resource-documentation` | `BYWARD_RESOURCE_DOCUMENTATION` | — | documentation URL in protected resource metadata |
| `--log-format` | `BYWARD_LOG_FORMAT` | json | log format: json or text |
| `--trusted-proxies` | `BYWARD_TRUSTED_PROXIES` | — | comma-separated CIDRs or addresses of reverse proxies whose X-Forwarded-For is trusted for the client address (ADR-0018 §6); empty trusts none |
| `--oauth-rate-limits` | `BYWARD_OAUTH_RATE_LIMITS` | — | per-minute limits per client address on OAuth endpoints, e.g. authorize=60,token=120 (ADR-0018 §8); unset endpoints keep their defaults |
| `--internal-listen` | `BYWARD_INTERNAL_LISTEN` | 127.0.0.1:9090 | address of the internal listener for /metrics, /livez and /readyz (ADR-0018 §10); empty turns it off |
| `--idp` | `BYWARD_IDP` | entra | the IdP users sign in with: entra, or oidc for any OpenID Connect IdP, or one of its presets google, okta, auth0, keycloak (ADR-0011, docs/how-to/oidc.md); the callback path is /callback/<idp> |
| `--entra-tenant` | `BYWARD_ENTRA_TENANT` | — | Entra tenant ID (a GUID) of the IdP app |
| `--entra-client-id` | `BYWARD_ENTRA_CLIENT_ID` | — | application (client) ID of the IdP app registration |
| `--entra-client-secret-file` | `BYWARD_ENTRA_CLIENT_SECRET_FILE` | — | client secret of the IdP app |
| `--entra-client-secret-expires-at` | `BYWARD_ENTRA_CLIENT_SECRET_EXPIRES_AT` | — | when the client secret expires, as a date (2027-11-06) or an RFC 3339 time; the proxy warns at startup and doctor warns from 30 days before (ADR-0012 §10) |
| `--oidc-issuer` | `BYWARD_OIDC_ISSUER` | — | with an oidc IdP: the issuer URL, exactly as its discovery document states it (https); google defaults to https://accounts.google.com |
| `--oidc-client-id` | `BYWARD_OIDC_CLIENT_ID` | — | with an oidc IdP: the client ID of the proxy's app at the IdP |
| `--oidc-client-secret-file` | `BYWARD_OIDC_CLIENT_SECRET_FILE` | — | with an oidc IdP: the client secret; give this or BYWARD_OIDC_CLIENT_KEY_FILE |
| `--oidc-client-key-file` | `BYWARD_OIDC_CLIENT_KEY_FILE` | — | with an oidc IdP: a PEM private key (RSA or EC P-256) for private_key_jwt instead of a secret |
| `--oidc-client-key-id` | `BYWARD_OIDC_CLIENT_KEY_ID` | — | with an oidc IdP: the key ID (kid) the IdP registered for BYWARD_OIDC_CLIENT_KEY_FILE |
| `--oidc-scopes` | `BYWARD_OIDC_SCOPES` | — | with an oidc IdP: comma-separated scopes to request besides openid and the preset's |
| `--oidc-subject-claim` | `BYWARD_OIDC_SUBJECT_CLAIM` | sub | with an oidc IdP: the claim that identifies a user; one users can change (email, preferred_username, upn, name) logs a warning |
| `--oidc-name` | `BYWARD_OIDC_NAME` | — | with an oidc IdP: its name on the consent page; default: the preset's name, or the issuer's host |
| `--data-dir` | `BYWARD_DATA_DIR` | /var/lib/byward | data directory, an absolute path; the keys, clients and store settings default to paths in it (ADR-0007 §6, docs/how-to/state.md) |
| `--keys-dir` | `BYWARD_KEYS_DIR` | — | directory of sealing keys; each file is one key, its name the key ID; default: keys in the data directory (docs/how-to/sealing-keys.md) |
| `--assertion-keys-dir` | `BYWARD_ASSERTION_KEYS_DIR` | — | directory of the identity assertion's signing keys: PEM ECDSA P-256 files, each name the key ID; the key whose ID sorts last signs; needed with an HTTP upstream; default: assertion-keys in the data directory (docs/how-to/identity-assertion.md) |
| `--assertion-header` | `BYWARD_ASSERTION_HEADER` | Authorization | request header that carries the identity assertion to the HTTP upstream, as Bearer <JWT>; inbound copies are always removed (ADR-0016 §2) |
| `--identity-headers` | `BYWARD_IDENTITY_HEADERS` | false | also send the HTTP upstream the user in plain headers (X-Byward-Subject, X-Byward-Client-Id, and X-Byward-Roles, -Groups, -Email, -Name for the assertion's claims), percent-encoded; safe only when the upstream is reachable through this proxy alone (ADR-0016 §5, docs/how-to/plain-identity-headers.md) |
| `--assertion-claims` | `BYWARD_ASSERTION_CLAIMS` | roles | comma-separated optional claims in the identity assertion: roles, groups, email, name; or none (ADR-0016 §1, docs/reference/identity-assertion.md) |
| `--static-clients-file` | `BYWARD_STATIC_CLIENTS_FILE` | — | JSON file of pre-registered MCP clients; default: clients.json in the data directory, optional while CIMD or DCR is on; a file you name must exist (docs/reference/static-clients.md) |
| `--gate-tenants` | `BYWARD_GATE_TENANTS` | — | access gate: comma-separated Entra tenant IDs allowed to sign in (docs/how-to/access-gate.md) |
| `--gate-roles` | `BYWARD_GATE_ROLES` | — | access gate: comma-separated app roles; users need at least one (docs/how-to/access-gate.md) |
| `--gate-groups` | `BYWARD_GATE_GROUPS` | — | access gate: comma-separated group IDs; users need one, and groups overage denies (docs/how-to/access-gate.md) |
| `--gate-email-domains` | `BYWARD_GATE_EMAIL_DOMAINS` | — | access gate: comma-separated domains of a verified email; oidc IdPs only, never Entra (docs/how-to/access-gate.md) |
| `--gate-hosted-domains` | `BYWARD_GATE_HOSTED_DOMAINS` | — | access gate: comma-separated Google Workspace domains (hd claim); BYWARD_IDP=google only; with one domain it is also sent to Google as the hd hint (docs/how-to/access-gate.md) |
| `--dcr` | `BYWARD_DCR` | true | accept Dynamic Client Registration at /register (Cursor, Gemini CLI) and advertise it; false turns it off (docs/how-to/dcr.md) |
| `--client-denylist` | `BYWARD_CLIENT_DENYLIST` | — | comma-separated CIMD client IDs (https URLs) and redirect host names refused for CIMD and DCR clients (docs/how-to/dcr.md) |
| `--cimd` | `BYWARD_CIMD` | true | accept MCP clients identified by a Client ID Metadata Document URL (Claude, VS Code) and advertise it; false turns it off (docs/how-to/cimd.md) |
| `--cimd-trusted-hosts` | `BYWARD_CIMD_TRUSTED_HOSTS` | — | comma-separated hosts whose client metadata documents you vouch for: their apps show as trusted by you on the consent page (docs/how-to/cimd.md) |
| `--cimd-allowed-hosts` | `BYWARD_CIMD_ALLOWED_HOSTS` | — | comma-separated hosts allowed to publish client metadata documents besides the trusted ones; empty allows any host (docs/how-to/cimd.md) |
| `--gate-allow-empty` | `BYWARD_GATE_ALLOW_EMPTY` | false | allow an empty access gate for a Google or generic OIDC IdP (anyone with an account can sign in); no effect with Entra (docs/how-to/access-gate.md) |
| `--operator-name` | `BYWARD_OPERATOR_NAME` | — | who runs this proxy, shown on the consent page, e.g. Contoso IT |
| `--scope-description` | `BYWARD_SCOPE_DESCRIPTION` | — | what the scope lets an app do, in plain words for the consent page, e.g. Read and query your team's dashboards |
| `--store-dir` | `BYWARD_STORE_DIR` | — | state directory of the SQLite store, an absolute path, created with mode 0700; the directory to back up; default: state in the data directory (ADR-0007, docs/how-to/state.md) |
| `--store-counter-file` | `BYWARD_STORE_COUNTER_FILE` | — | restore-detection counter file, an absolute path outside the state directory and its backups; default: store-writes next to the keys directory (ADR-0007 §9) |
| `--refresh-grace` | `BYWARD_REFRESH_GRACE` | 30s | how long a just-rotated refresh token is still accepted, for a client retrying a lost response; 0s to 60s (ADR-0006 §4) |
| `--insecure-no-auth` | `BYWARD_INSECURE_NO_AUTH` | false | no authentication at all, for trying the proxy out and for tests; loopback only (ADR-0027) |
| `--dev` | `BYWARD_DEV` | false | development mode: enables the relaxations it logs at startup |

Actions: `--version [--json]`, `--print-config`, `--help`.
Commands (`check --offline`, `doctor`, `init entra`): [commands reference](commands.md).

Exit codes: 0 success, 1 runtime error, 2 configuration error; `doctor` adds 4, 8 and 12.
