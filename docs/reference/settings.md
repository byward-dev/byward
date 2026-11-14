# Settings reference

Generated from the settings registry (`internal/config`); do not edit by hand.
Run `BYWARD_UPDATE_REFERENCE=1 go test ./internal/config/` after changing a setting.

Precedence: flag > environment > default. Secrets are read only from files.

- [Endpoint](#endpoint)
- [IdP](#idp)
- [IdP: Microsoft Entra ID](#idp-microsoft-entra-id)
- [IdP: OpenID Connect](#idp-openid-connect)
- [Access gate](#access-gate)
- [Client registration](#client-registration)
- [App-only callers](#app-only-callers)
- [Upstream: HTTP](#upstream-http)
- [Upstream: stdio](#upstream-stdio)
- [Identity to the upstream](#identity-to-the-upstream)
- [Downstream tokens (On-Behalf-Of)](#downstream-tokens-on-behalf-of)
- [Sealing keys and store](#sealing-keys-and-store)
- [Operations](#operations)
- [Consent page](#consent-page)
- [Development and trying it out](#development-and-trying-it-out)

## Endpoint

| Flag | Environment | Default | Description |
|---|---|---|---|
| `--public-url` | `BYWARD_PUBLIC_URL` | — | public URL of the MCP endpoint exactly as users enter it, e.g. https://mcp.example.com/mcp; an internationalized host in its ASCII (xn--) form |
| `--listen` | `BYWARD_LISTEN` | 127.0.0.1:8080 | address to listen on; public addresses only when configured |
| `--tls-cert-file` | `BYWARD_TLS_CERT_FILE` | — | serve TLS on the listener: an absolute path to the PEM certificate, followed by any intermediates; with tls-key-file; needs an https public-url; a replaced file is served from the next connection on, with no restart (docs/how-to/tls.md) |
| `--tls-key-file` | `BYWARD_TLS_KEY_FILE` | — | serve TLS on the listener: an absolute path to the certificate's unencrypted PEM private key, readable by the proxy's user alone or on a read-only mount; with tls-cert-file (docs/how-to/tls.md) |
| `--allowed-origins` | `BYWARD_ALLOWED_ORIGINS` | — | comma-separated Origin values allowed on the MCP endpoint (scheme://host[:port]); an internationalized host in its ASCII (xn--) form |
| `--allowed-hosts` | `BYWARD_ALLOWED_HOSTS` | — | comma-separated extra Host values accepted besides the public URL's host; an internationalized host in its ASCII (xn--) form |
| `--scope` | `BYWARD_SCOPE` | mcp | the scope advertised in protected resource metadata and 401 challenges |
| `--resource-name` | `BYWARD_RESOURCE_NAME` | — | human-readable resource name in protected resource metadata |
| `--resource-documentation` | `BYWARD_RESOURCE_DOCUMENTATION` | — | documentation URL in protected resource metadata |

## IdP

| Flag | Environment | Default | Description |
|---|---|---|---|
| `--idp` | `BYWARD_IDP` | entra | the IdP users sign in with: entra, or oidc for any OpenID Connect IdP, or one of its presets google, okta, auth0, keycloak (ADR-0011, docs/how-to/oidc.md); the callback path is /callback/<idp> |

## IdP: Microsoft Entra ID

| Flag | Environment | Default | Description |
|---|---|---|---|
| `--entra-tenant` | `BYWARD_ENTRA_TENANT` | — | Entra tenant ID (a GUID) of the IdP app |
| `--entra-client-id` | `BYWARD_ENTRA_CLIENT_ID` | — | application (client) ID of the IdP app registration |
| `--entra-client-secret-file` | `BYWARD_ENTRA_CLIENT_SECRET_FILE` | — | client secret of the IdP app |
| `--entra-client-certificate-file` | `BYWARD_ENTRA_CLIENT_CERTIFICATE_FILE` | — | instead of a client secret: a PEM file with the IdP app's certificate and its unencrypted RSA private key (2048 bits or more); the certificate must be uploaded to the app registration; recommended for production (ADR-0012 §5, docs/how-to/entra-certificate.md) |
| `--entra-federated-token-file` | `BYWARD_ENTRA_FEDERATED_TOKEN_FILE` | — | instead of a client secret: an absolute path to a file holding a federated token (a JWT from another identity provider, such as GitHub Actions or AKS workload identity) that byward sends Entra as its client assertion, re-reading the file for every token request; the app registration needs a matching federated identity credential (ADR-0012 §5, docs/how-to/entra-federated-credential.md) |
| `--entra-client-secret-expires-at` | `BYWARD_ENTRA_CLIENT_SECRET_EXPIRES_AT` | — | when the client secret expires, as a date (2027-11-06) or an RFC 3339 time; the proxy warns at startup and doctor warns from 30 days before (ADR-0012 §10) |

## IdP: OpenID Connect

| Flag | Environment | Default | Description |
|---|---|---|---|
| `--oidc-issuer` | `BYWARD_OIDC_ISSUER` | — | with an oidc IdP: the issuer URL, exactly as its discovery document states it (https); google defaults to https://accounts.google.com |
| `--oidc-client-id` | `BYWARD_OIDC_CLIENT_ID` | — | with an oidc IdP: the client ID of the proxy's app at the IdP |
| `--oidc-client-secret-file` | `BYWARD_OIDC_CLIENT_SECRET_FILE` | — | with an oidc IdP: the client secret; give this or BYWARD_OIDC_CLIENT_KEY_FILE |
| `--oidc-client-key-file` | `BYWARD_OIDC_CLIENT_KEY_FILE` | — | with an oidc IdP: a PEM private key (RSA or EC P-256) for private_key_jwt instead of a secret |
| `--oidc-client-key-alg` | `BYWARD_OIDC_CLIENT_KEY_ALG` | — | with an oidc IdP and BYWARD_OIDC_CLIENT_KEY_FILE: the client assertion's signing algorithm, PS256 or RS256 for an RSA key, ES256 for an EC P-256 key; default PS256 for RSA, ES256 for EC. Okta refuses PS256: use RS256 there (docs/how-to/oidc.md) |
| `--oidc-client-key-id` | `BYWARD_OIDC_CLIENT_KEY_ID` | — | with an oidc IdP: the key ID (kid) the IdP registered for BYWARD_OIDC_CLIENT_KEY_FILE |
| `--oidc-scopes` | `BYWARD_OIDC_SCOPES` | — | with an oidc IdP: comma-separated scopes to request besides openid and the preset's |
| `--oidc-subject-claim` | `BYWARD_OIDC_SUBJECT_CLAIM` | sub | with an oidc IdP: the claim that identifies a user; one users can change (email, preferred_username, upn, name) logs a warning |
| `--oidc-roles-claim` | `BYWARD_OIDC_ROLES_CLAIM` | roles | with an oidc IdP: the ID token claim the access gate (BYWARD_GATE_ROLES) and the identity assertion read roles from, such as a namespaced https://example.com/roles; the default is roles for every preset (docs/how-to/oidc.md) |
| `--oidc-groups-claim` | `BYWARD_OIDC_GROUPS_CLAIM` | groups | with an oidc IdP: the ID token claim the access gate (BYWARD_GATE_GROUPS) and the identity assertion read groups from, such as a namespaced https://example.com/groups; the default is groups for every preset (docs/how-to/oidc.md) |
| `--oidc-name` | `BYWARD_OIDC_NAME` | — | with an oidc IdP: its name on the consent page; default: the preset's name, or the issuer's host |

## Access gate

| Flag | Environment | Default | Description |
|---|---|---|---|
| `--gate-tenants` | `BYWARD_GATE_TENANTS` | — | access gate: comma-separated Entra tenant IDs allowed to sign in (docs/how-to/access-gate.md) |
| `--gate-roles` | `BYWARD_GATE_ROLES` | — | access gate: comma-separated app roles; users need at least one (docs/how-to/access-gate.md) |
| `--gate-groups` | `BYWARD_GATE_GROUPS` | — | access gate: comma-separated group IDs; users need one, and groups overage denies (docs/how-to/access-gate.md) |
| `--gate-email-domains` | `BYWARD_GATE_EMAIL_DOMAINS` | — | access gate: comma-separated domains of a verified email; oidc IdPs only, never Entra (docs/how-to/access-gate.md) |
| `--gate-hosted-domains` | `BYWARD_GATE_HOSTED_DOMAINS` | — | access gate: comma-separated Google Workspace domains (hd claim); BYWARD_IDP=google only; with one domain it is also sent to Google as the hd hint (docs/how-to/access-gate.md) |
| `--gate-allow-empty` | `BYWARD_GATE_ALLOW_EMPTY` | false | allow an empty access gate for a Google or generic OIDC IdP (anyone with an account can sign in); no effect with Entra (docs/how-to/access-gate.md) |

## Client registration

| Flag | Environment | Default | Description |
|---|---|---|---|
| `--static-clients-file` | `BYWARD_STATIC_CLIENTS_FILE` | — | JSON file of pre-registered MCP clients; default: clients.json in the data directory, optional while CIMD or DCR is on; a file you name must exist (docs/reference/static-clients.md) |
| `--dcr` | `BYWARD_DCR` | true | accept Dynamic Client Registration at /register (Cursor, Gemini CLI) and advertise it; false turns it off (docs/how-to/dcr.md) |
| `--client-denylist` | `BYWARD_CLIENT_DENYLIST` | — | comma-separated CIMD client IDs (https URLs) and redirect host names refused for CIMD and DCR clients (docs/how-to/dcr.md) |
| `--cimd` | `BYWARD_CIMD` | true | accept MCP clients identified by a Client ID Metadata Document URL (Claude, VS Code) and advertise it; false turns it off (docs/how-to/cimd.md) |
| `--cimd-trusted-hosts` | `BYWARD_CIMD_TRUSTED_HOSTS` | — | comma-separated hosts whose client metadata documents you vouch for: their apps show as trusted by you on the consent page (docs/how-to/cimd.md) |
| `--cimd-allowed-hosts` | `BYWARD_CIMD_ALLOWED_HOSTS` | — | comma-separated hosts allowed to publish client metadata documents besides the trusted ones; empty allows any host (docs/how-to/cimd.md) |

## App-only callers

| Flag | Environment | Default | Description |
|---|---|---|---|
| `--app-tokens` | `BYWARD_APP_TOKENS` | off | accept app-only tokens from headless callers at the MCP endpoint: off, or entra (BYWARD_IDP=entra only; ADR-0022, docs/how-to/app-tokens.md) |
| `--app-roles` | `BYWARD_APP_ROLES` | — | with BYWARD_APP_TOKENS=entra, required: comma-separated app roles on the proxy's app; an app-only caller needs at least one (docs/how-to/app-tokens.md) |
| `--app-client-ids` | `BYWARD_APP_CLIENT_IDS` | — | with BYWARD_APP_TOKENS=entra: comma-separated application (client) IDs allowed to call (azp); default: any caller with a role (docs/how-to/app-tokens.md) |

## Upstream: HTTP

| Flag | Environment | Default | Description |
|---|---|---|---|
| `--upstream-url` | `BYWARD_UPSTREAM_URL` | — | URL of the HTTP upstream MCP server; or set a stdio upstream with upstream-command |
| `--upstream-header-timeout` | `BYWARD_UPSTREAM_HEADER_TIMEOUT` | 5m | how long the HTTP upstream may take to send its response headers; a request that waits longer gets a JSON-RPC timeout error, and a streamed response is not limited once its headers arrive; 1s to 1h (ADR-0018 §7) |
| `--upstream-credential-file` | `BYWARD_UPSTREAM_CREDENTIAL_FILE` | — | HTTP upstream: a header value the proxy sends with every upstream request, such as an API key the upstream needs from the proxy itself; never the user's or the client's token; read at start, never logged (ADR-0016 §7, docs/how-to/upstream-credential.md) |
| `--upstream-credential-header` | `BYWARD_UPSTREAM_CREDENTIAL_HEADER` | Authorization | the header that carries upstream-credential; inbound copies are always removed; it never shares a header with the identity assertion, so with Authorization here set assertion-header to another header (ADR-0016 §7) |
| `--upstream-strip-headers` | `BYWARD_UPSTREAM_STRIP_HEADERS` | — | HTTP upstream: comma-separated request headers removed before every upstream request, besides the built-in ones, compared in any case with _ read as -: the headers an upstream takes its settings or credentials from, such as x-argocd-base-url; exact names only, so list a family such as X-Atlassian-*-Url name by name; MCP's own headers are refused (docs/how-to/harden-a-deployment.md) |

## Upstream: stdio

| Flag | Environment | Default | Description |
|---|---|---|---|
| `--upstream-command` | `BYWARD_UPSTREAM_COMMAND` | — | stdio upstream: the command as a JSON array, e.g. ["/usr/local/bin/server","--flag"], never run through a shell; or give it after -- on the command line (docs/how-to/stdio-upstream.md) |
| `--upstream-env-file` | `BYWARD_UPSTREAM_ENV_FILE` | — | stdio upstream: KEY=VALUE lines set in the environment of each upstream process, besides the inherited PATH, HOME, USER, LOGNAME, TMPDIR, TZ, LANG and LC_* (ADR-0016 §6); values are never logged |
| `--stdio-max-processes` | `BYWARD_STDIO_MAX_PROCESSES` | 64 | stdio upstream: most upstream processes alive at once; when full, the least recently used idle one is stopped (ADR-0003 §5) |
| `--stdio-max-processes-per-user` | `BYWARD_STDIO_MAX_PROCESSES_PER_USER` | 8 | stdio upstream: most upstream processes one user has alive at once; when full, that user's least recently used idle one is stopped |
| `--stdio-stream-idle-timeout` | `BYWARD_STDIO_STREAM_IDLE_TIMEOUT` | 10m | stdio upstream: a process kept busy only by open streams (a legacy GET stream, a subscriptions/listen) that has had no traffic for this long can be stopped when a process cap is full; 0 keeps such processes however long they are quiet, otherwise at least 1m |

## Identity to the upstream

| Flag | Environment | Default | Description |
|---|---|---|---|
| `--assertion-keys-dir` | `BYWARD_ASSERTION_KEYS_DIR` | — | directory of the identity assertion's signing keys: PEM ECDSA P-256 files, each name the key ID; the key whose ID sorts last signs; needed with an HTTP upstream; default: assertion-keys in the data directory (docs/how-to/identity-assertion.md) |
| `--assertion-header` | `BYWARD_ASSERTION_HEADER` | Authorization | request header that carries the identity assertion to the HTTP upstream, as Bearer <JWT>; inbound copies are always removed (ADR-0016 §2) |
| `--identity-headers` | `BYWARD_IDENTITY_HEADERS` | false | also send the HTTP upstream the user in plain headers (X-Byward-Subject, X-Byward-Client-Id, X-Byward-Principal-Type, and X-Byward-Roles, -Groups, -Email, -Email-Verified, -Name for the assertion's claims), percent-encoded; safe only when the upstream is reachable through this proxy alone (ADR-0016 §5, docs/how-to/plain-identity-headers.md) |
| `--assertion-claims` | `BYWARD_ASSERTION_CLAIMS` | roles | comma-separated optional claims in the identity assertion: roles, groups, email, name; or none (ADR-0016 §1, docs/reference/identity-assertion.md) |
| `--assertion-unverified-email` | `BYWARD_ASSERTION_UNVERIFIED_EMAIL` | false | with email in BYWARD_ASSERTION_CLAIMS: also assert an email the IdP has not verified (Entra never verifies one), marked email_verified false; never authorize on it (docs/how-to/identity-assertion.md) |

## Downstream tokens (On-Behalf-Of)

| Flag | Environment | Default | Description |
|---|---|---|---|
| `--obo-scopes` | `BYWARD_OBO_SCOPES` | — | On-Behalf-Of: space-separated scopes of one downstream API, e.g. https://graph.microsoft.com/User.Read; the HTTP upstream then gets a token for them in BYWARD_OBO_HEADER on every request, a stdio upstream on its token socket (BYWARD_DOWNSTREAM_TOKEN_SOCKET); empty turns it off (ADR-0017, docs/how-to/downstream-apis.md) |
| `--obo-header` | `BYWARD_OBO_HEADER` | X-Byward-Downstream-Token | On-Behalf-Of: request header that carries the downstream API token to the HTTP upstream, as Bearer <token>; inbound copies are always removed (ADR-0017 §3); not for a stdio upstream |

## Sealing keys and store

| Flag | Environment | Default | Description |
|---|---|---|---|
| `--data-dir` | `BYWARD_DATA_DIR` | /var/lib/byward | data directory, an absolute path; the keys, clients and store settings default to paths in it (ADR-0007 §6, docs/how-to/state.md) |
| `--keys-dir` | `BYWARD_KEYS_DIR` | — | directory of sealing keys; each file is one key, its name the key ID; default: keys in the data directory (docs/how-to/sealing-keys.md) |
| `--store-dir` | `BYWARD_STORE_DIR` | — | state directory of the SQLite store, an absolute path, created with mode 0700; the directory to back up; default: state in the data directory (ADR-0007, docs/how-to/state.md) |
| `--store-postgres-dsn-file` | `BYWARD_STORE_POSTGRES_DSN_FILE` | — | the PostgreSQL store, for more than one replica of an HTTP upstream: a file holding the connection string (a URL or key=value pairs, pool settings such as pool_max_conns included); setting it selects PostgreSQL 15 or later instead of SQLite; sslmode=verify-full is required outside --dev; never logged (ADR-0007, docs/how-to/postgres.md) |
| `--store-counter-file` | `BYWARD_STORE_COUNTER_FILE` | — | restore-detection counter file, an absolute path outside the state directory and its backups; default: store-writes next to the keys directory (ADR-0007 §9) |

## Operations

| Flag | Environment | Default | Description |
|---|---|---|---|
| `--log-format` | `BYWARD_LOG_FORMAT` | json | log format: json or text |
| `--trusted-proxies` | `BYWARD_TRUSTED_PROXIES` | — | comma-separated CIDRs or addresses of reverse proxies whose X-Forwarded-For is trusted for the client address (ADR-0018 §6); empty trusts none |
| `--oauth-rate-limits` | `BYWARD_OAUTH_RATE_LIMITS` | — | per-minute limits per client address on OAuth endpoints, e.g. authorize=60,token=120 (ADR-0018 §8); unset endpoints keep their defaults |
| `--internal-listen` | `BYWARD_INTERNAL_LISTEN` | 127.0.0.1:9090 | address of the internal listener for /metrics, /livez and /readyz (ADR-0018 §10); empty turns it off |
| `--refresh-grace` | `BYWARD_REFRESH_GRACE` | 30s | how long a just-rotated refresh token is still accepted, for a client retrying a lost response; 0s to 60s (ADR-0006 §4) |

## Consent page

| Flag | Environment | Default | Description |
|---|---|---|---|
| `--operator-name` | `BYWARD_OPERATOR_NAME` | — | who runs this proxy, shown on the consent page, e.g. Contoso IT |
| `--scope-description` | `BYWARD_SCOPE_DESCRIPTION` | — | what the scope lets an app do, in plain words for the consent page, e.g. Read and query your team's dashboards |

## Development and trying it out

| Flag | Environment | Default | Description |
|---|---|---|---|
| `--insecure-no-auth` | `BYWARD_INSECURE_NO_AUTH` | false | no authentication at all, for trying the proxy out and for tests; loopback only (ADR-0027) |
| `--dev` | `BYWARD_DEV` | false | development mode: enables the relaxations it logs at startup |

## Actions, commands and exit codes

Actions: `--version [--json]`, `--print-config`, `--help` ([proxy actions](commands.md#proxy-actions)).
Commands: [commands reference](commands.md).

Exit codes: 0 success, 1 runtime error, 2 configuration error; `doctor` adds 4, 8 and 12.

## Other environment variables

These are not settings, so `--print-config` does not show them.

| Variable | Read or set by | Meaning |
|---|---|---|
| `OTEL_*` | the proxy, through the OpenTelemetry SDK | traces, off unless `OTEL_TRACES_EXPORTER` is set ([observability](observability.md)) |
| `SSL_CERT_FILE`, `SSL_CERT_DIR` | the proxy, through Go | the CAs it trusts for outbound TLS: the IdP, the upstream, an MCP client's CIMD document and `jwks_uri`, and the PostgreSQL store when its DSN has no `sslrootcert` ([private CA](../how-to/private-ca.md)) |
| `HTTPS_PROXY`, `HTTP_PROXY`, `NO_PROXY` | the proxy, through Go | the environment proxy: the relay to an HTTP upstream, IdP calls, doctor's self-probe and trace export go through it ([doctor](commands.md#checks) names it) |
| `BYWARD_SUBJECT`, `BYWARD_ISSUER`, `BYWARD_PRINCIPAL_TYPE` | set by the proxy for a stdio upstream process | who the process acts for ([stdio upstream](../how-to/stdio-upstream.md)) |
| `BYWARD_DOWNSTREAM_TOKEN_SOCKET` | set by the proxy for a stdio upstream process, read by `byward downstream-token` | the token socket the process asks for its user's downstream token |
