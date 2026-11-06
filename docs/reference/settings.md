# Settings reference

Generated from the settings registry (`internal/config`); do not edit by hand.
Run `BYWARD_UPDATE_REFERENCE=1 go test ./internal/config/` after changing a setting.

Precedence: flag > environment > default. Secrets are read only from files.

| Flag | Environment | Default | Description |
|---|---|---|---|
| `--public-url` | `BYWARD_PUBLIC_URL` | — | public URL of the MCP endpoint exactly as users enter it, e.g. https://mcp.example.com/mcp; an internationalized host in its ASCII (xn--) form |
| `--upstream-url` | `BYWARD_UPSTREAM_URL` | — | URL of the HTTP upstream MCP server |
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
| `--entra-tenant` | `BYWARD_ENTRA_TENANT` | — | Entra tenant ID (a GUID) of the IdP app |
| `--entra-client-id` | `BYWARD_ENTRA_CLIENT_ID` | — | application (client) ID of the IdP app registration |
| `--entra-client-secret-file` | `BYWARD_ENTRA_CLIENT_SECRET_FILE` | — | client secret of the IdP app |
| `--data-dir` | `BYWARD_DATA_DIR` | /var/lib/byward | data directory, an absolute path; the keys, clients and store settings default to paths in it (ADR-0007 §6, docs/how-to/state.md) |
| `--keys-dir` | `BYWARD_KEYS_DIR` | — | directory of sealing keys; each file is one key, its name the key ID; default: keys in the data directory (docs/how-to/sealing-keys.md) |
| `--static-clients-file` | `BYWARD_STATIC_CLIENTS_FILE` | — | JSON file of pre-registered MCP clients; default: clients.json in the data directory (docs/reference/static-clients.md) |
| `--gate-tenants` | `BYWARD_GATE_TENANTS` | — | access gate: comma-separated Entra tenant IDs allowed to sign in (docs/how-to/access-gate.md) |
| `--gate-roles` | `BYWARD_GATE_ROLES` | — | access gate: comma-separated app roles; users need at least one (docs/how-to/access-gate.md) |
| `--gate-groups` | `BYWARD_GATE_GROUPS` | — | access gate: comma-separated group IDs; users need one, and groups overage denies (docs/how-to/access-gate.md) |
| `--gate-email-domains` | `BYWARD_GATE_EMAIL_DOMAINS` | — | access gate: comma-separated domains of a verified email; generic OIDC IdPs only, so not usable with Entra (the only IdP so far) (docs/how-to/access-gate.md) |
| `--gate-hosted-domains` | `BYWARD_GATE_HOSTED_DOMAINS` | — | access gate: comma-separated Google Workspace domains (hd claim); Google only, so not usable with Entra (the only IdP so far) (docs/how-to/access-gate.md) |
| `--gate-allow-empty` | `BYWARD_GATE_ALLOW_EMPTY` | false | allow an empty access gate for a Google or generic OIDC IdP (anyone with an account can sign in); no effect with Entra (docs/how-to/access-gate.md) |
| `--operator-name` | `BYWARD_OPERATOR_NAME` | — | who runs this proxy, shown on the consent page, e.g. Contoso IT |
| `--scope-description` | `BYWARD_SCOPE_DESCRIPTION` | — | what the scope lets an app do, in plain words for the consent page, e.g. Read and query your team's dashboards |
| `--store-dir` | `BYWARD_STORE_DIR` | — | state directory of the SQLite store, an absolute path, created with mode 0700; the directory to back up; default: state in the data directory (ADR-0007, docs/how-to/state.md) |
| `--store-counter-file` | `BYWARD_STORE_COUNTER_FILE` | — | restore-detection counter file, an absolute path outside the state directory and its backups; default: store-writes next to the keys directory (ADR-0007 §9) |
| `--refresh-grace` | `BYWARD_REFRESH_GRACE` | 30s | how long a just-rotated refresh token is still accepted, for a client retrying a lost response; 0s to 60s (ADR-0006 §4) |
| `--insecure-no-auth` | `BYWARD_INSECURE_NO_AUTH` | false | no authentication at all, for trying the proxy out and for tests; loopback only (ADR-0027) |
| `--dev` | `BYWARD_DEV` | false | development mode: enables the relaxations it logs at startup |

Actions: `--version [--json]`, `--print-config`, `--help`.

Exit codes: 0 success, 1 runtime error, 2 configuration error.
