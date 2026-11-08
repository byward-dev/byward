<p align="center"><img src="docs/assets/byward-logo.svg" alt="byward owl logo" width="128" height="128"></p>

# byward

[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/byward-dev/byward/badge)](https://scorecard.dev/viewer/?uri=github.com/byward-dev/byward)

**A sign-in gate for MCP servers.** byward puts any [MCP](https://modelcontextprotocol.io) server,
HTTP or stdio, behind OAuth 2.1 and your identity provider, with first-class Microsoft Entra ID
support. One Go binary, configured by environment variables.

> **Latest release: [v0.1.0](https://github.com/byward-dev/byward/releases/tag/v0.1.0).** byward
> is pre-1.0 and has not had an independent security audit. Read the
> [security posture](docs/security-posture.md) before deploying it. `main` is ahead of the release;
> the docs for v0.1.0 are [at its tag](https://github.com/byward-dev/byward/tree/v0.1.0/docs).

## How it works

```
MCP client ──OAuth 2.1──▶ byward ──sign-in──▶ Entra ID
 (Claude, ChatGPT,          │
  VS Code, Cursor…)         └──▶ MCP server (HTTP or stdio)
                                 never sees the client's or the IdP's token
```

- **MCP clients sign in with standard OAuth 2.1.** byward is the authorization server: it signs the
  user in at Entra, shows its own consent page, and issues short-lived tokens of its own.
- **Clients connect without manual setup**, through Client ID Metadata Documents (CIMD) or Dynamic
  Client Registration (DCR). Static clients cover anything else.
- **The MCP server needs no auth code.** It never gets the client's token (no token passthrough).
- **Access is gated** by Entra app roles and groups. Refresh tokens rotate with reuse detection, and
  operators can revoke a user or everyone.
- **Built to run:** SQLite state, rate limits on the OAuth endpoints, a structured audit stream,
  Prometheus metrics, and `byward doctor` to check a deployment.

## Verified clients

Signed in through byward against a real Entra tenant and called a tool:

| Client | How it registers |
|---|---|
| Claude Code | CIMD (or a static client) |
| claude.ai | CIMD |
| ChatGPT | CIMD |
| VS Code | CIMD |
| Cursor 3.29.9 (2.6.22 does not work) | DCR |

The TypeScript, Python and Go MCP SDK clients and MCP Inspector run against byward in CI.

## Try it

The [Entra quickstart](docs/how-to/quickstart-entra.md) registers the app (or `byward init entra`
prints the commands for you) and then runs byward in front of your MCP server:

```sh
docker run --rm -p 8080:8080 --user "$(id -u):$(id -g)" \
  -v "$PWD/byward-data:/var/lib/byward" \
  -v "$PWD/entra-client-secret:/run/secrets/entra-client-secret:ro" \
  -e BYWARD_PUBLIC_URL=https://mcp.example.com/mcp \
  -e BYWARD_UPSTREAM_URL=http://upstream.internal:3001/mcp \
  -e BYWARD_ENTRA_TENANT="$TENANT_ID" \
  -e BYWARD_ENTRA_CLIENT_ID="$APP_ID" \
  -e BYWARD_ENTRA_CLIENT_SECRET_FILE=/run/secrets/entra-client-secret \
  -e BYWARD_LISTEN=0.0.0.0:8080 \
  ghcr.io/byward-dev/byward:latest
```

byward does not terminate TLS: put it behind your ingress or reverse proxy. Then work through the
[hardening checklist](docs/how-to/harden-a-deployment.md).

Images and archives are signed with cosign and carry build provenance; how to verify them:
[packaging](docs/reference/packaging.md).

## Documentation

- **How-to guides:** [stdio upstreams](docs/how-to/stdio-upstream.md),
  [access gate](docs/how-to/access-gate.md), [CIMD](docs/how-to/cimd.md), [DCR](docs/how-to/dcr.md),
  [state and backups](docs/how-to/state.md), [all guides](docs/how-to/)
- **Reference:** [settings](docs/reference/settings.md), [commands](docs/reference/commands.md),
  [observability](docs/reference/observability.md)
- **Design:** [scope and non-goals](docs/adr/0001-scope-auth-only-proxy-entra-first-class.md),
  [all decisions](docs/adr/), [glossary](CONTEXT.md), [feature backlog](docs/features.md),
  [landscape research](docs/research.md)

## Development

Requires [mise](https://mise.jdx.dev). Then install the tools CI uses and run the checks:

```sh
mise install go golangci-lint go:golang.org/x/tools/cmd/goimports actionlint zizmor shellcheck go:github.com/google/go-licenses/v2
mise run check
```

Details, including why `azure-cli` is not needed here: [CONTRIBUTING.md](CONTRIBUTING.md#making-a-change).

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) (including the AI-assistance policy) and the
[Code of Conduct](CODE_OF_CONDUCT.md). Report vulnerabilities privately: [SECURITY.md](SECURITY.md).

MCP is a trademark of LF Projects, LLC. byward is an independent project.

## License

[Apache-2.0](LICENSE)
