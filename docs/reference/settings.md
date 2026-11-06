# Settings reference

Generated from the settings registry (`internal/config`); do not edit by hand.
Run `MCP_AUTHPROXY_UPDATE_REFERENCE=1 go test ./internal/config/` after changing a setting.

Precedence: flag > environment > default. Secrets are read only from files.

| Flag | Environment | Default | Description |
|---|---|---|---|
| `--public-url` | `MCP_AUTHPROXY_PUBLIC_URL` | — | public URL of the MCP endpoint exactly as users enter it, e.g. https://mcp.example.com/mcp; an internationalized host in its ASCII (xn--) form |
| `--upstream-url` | `MCP_AUTHPROXY_UPSTREAM_URL` | — | URL of the HTTP upstream MCP server |
| `--listen` | `MCP_AUTHPROXY_LISTEN` | 127.0.0.1:8080 | address to listen on; public addresses only when configured |
| `--allowed-origins` | `MCP_AUTHPROXY_ALLOWED_ORIGINS` | — | comma-separated Origin values allowed on the MCP endpoint (scheme://host[:port]); an internationalized host in its ASCII (xn--) form |
| `--allowed-hosts` | `MCP_AUTHPROXY_ALLOWED_HOSTS` | — | comma-separated extra Host values accepted besides the public URL's host; an internationalized host in its ASCII (xn--) form |
| `--scope` | `MCP_AUTHPROXY_SCOPE` | mcp | the scope advertised in protected resource metadata and 401 challenges |
| `--resource-name` | `MCP_AUTHPROXY_RESOURCE_NAME` | — | human-readable resource name in protected resource metadata |
| `--resource-documentation` | `MCP_AUTHPROXY_RESOURCE_DOCUMENTATION` | — | documentation URL in protected resource metadata |
| `--log-format` | `MCP_AUTHPROXY_LOG_FORMAT` | json | log format: json or text |
| `--internal-listen` | `MCP_AUTHPROXY_INTERNAL_LISTEN` | 127.0.0.1:9090 | address of the internal listener for /metrics, /livez and /readyz (ADR-0018 §10); empty turns it off |
| `--entra-tenant` | `MCP_AUTHPROXY_ENTRA_TENANT` | — | Entra tenant ID (a GUID) of the IdP app |
| `--entra-client-id` | `MCP_AUTHPROXY_ENTRA_CLIENT_ID` | — | application (client) ID of the IdP app registration |
| `--entra-client-secret-file` | `MCP_AUTHPROXY_ENTRA_CLIENT_SECRET_FILE` | — | client secret of the IdP app |
| `--keys-dir` | `MCP_AUTHPROXY_KEYS_DIR` | — | directory of sealing keys; each file is one key, its name the key ID (docs/how-to/sealing-keys.md) |
| `--static-clients-file` | `MCP_AUTHPROXY_STATIC_CLIENTS_FILE` | — | JSON file of pre-registered MCP clients (docs/reference/static-clients.md) |
| `--gate-tenants` | `MCP_AUTHPROXY_GATE_TENANTS` | — | access gate: comma-separated Entra tenant IDs allowed to sign in (docs/how-to/access-gate.md) |
| `--gate-roles` | `MCP_AUTHPROXY_GATE_ROLES` | — | access gate: comma-separated app roles; users need at least one (docs/how-to/access-gate.md) |
| `--gate-groups` | `MCP_AUTHPROXY_GATE_GROUPS` | — | access gate: comma-separated group IDs; users need one, and groups overage denies (docs/how-to/access-gate.md) |
| `--gate-email-domains` | `MCP_AUTHPROXY_GATE_EMAIL_DOMAINS` | — | access gate: comma-separated domains of a verified email; generic OIDC IdPs only, so not usable with Entra (the only IdP so far) (docs/how-to/access-gate.md) |
| `--gate-hosted-domains` | `MCP_AUTHPROXY_GATE_HOSTED_DOMAINS` | — | access gate: comma-separated Google Workspace domains (hd claim); Google only, so not usable with Entra (the only IdP so far) (docs/how-to/access-gate.md) |
| `--gate-allow-empty` | `MCP_AUTHPROXY_GATE_ALLOW_EMPTY` | false | allow an empty access gate for a Google or generic OIDC IdP (anyone with an account can sign in); no effect with Entra (docs/how-to/access-gate.md) |
| `--insecure-no-auth` | `MCP_AUTHPROXY_INSECURE_NO_AUTH` | false | no authentication at all, for trying the proxy out and for tests; loopback only (ADR-0027) |
| `--dev` | `MCP_AUTHPROXY_DEV` | false | development mode: enables the relaxations it logs at startup |

Actions: `--version [--json]`, `--print-config`, `--help`.

Exit codes: 0 success, 1 runtime error, 2 configuration error.
