# Settings reference

Generated from the settings registry (`internal/config`); do not edit by hand.
Run `MCP_AUTHPROXY_UPDATE_REFERENCE=1 go test ./internal/config/` after changing a setting.

Precedence: flag > environment > default. Secrets are read only from files.

| Flag | Environment | Default | Description |
|---|---|---|---|
| `--public-url` | `MCP_AUTHPROXY_PUBLIC_URL` | — | public URL of the MCP endpoint exactly as users enter it, e.g. https://mcp.example.com/mcp |
| `--upstream-url` | `MCP_AUTHPROXY_UPSTREAM_URL` | — | URL of the HTTP upstream MCP server |
| `--listen` | `MCP_AUTHPROXY_LISTEN` | 127.0.0.1:8080 | address to listen on; public addresses only when configured |
| `--allowed-origins` | `MCP_AUTHPROXY_ALLOWED_ORIGINS` | — | comma-separated Origin values allowed on the MCP endpoint (scheme://host[:port]) |
| `--allowed-hosts` | `MCP_AUTHPROXY_ALLOWED_HOSTS` | — | comma-separated extra Host values accepted besides the public URL's host |
| `--scope` | `MCP_AUTHPROXY_SCOPE` | mcp | the scope advertised in protected resource metadata and 401 challenges |
| `--resource-name` | `MCP_AUTHPROXY_RESOURCE_NAME` | — | human-readable resource name in protected resource metadata |
| `--resource-documentation` | `MCP_AUTHPROXY_RESOURCE_DOCUMENTATION` | — | documentation URL in protected resource metadata |
| `--log-format` | `MCP_AUTHPROXY_LOG_FORMAT` | json | log format: json or text |
| `--dev` | `MCP_AUTHPROXY_DEV` | false | development mode: enables the relaxations it logs at startup |

Actions: `--version [--json]`, `--print-config`, `--help`.

Exit codes: 0 success, 1 runtime error, 2 configuration error.
