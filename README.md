# mcp-authproxy

[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/corker/mcp-authproxy/badge)](https://scorecard.dev/viewer/?uri=github.com/corker/mcp-authproxy)

> **Status: design phase.** Nothing to run yet.

An auth-only proxy that puts any [MCP](https://modelcontextprotocol.io) server — stdio or
HTTP — behind spec-compliant OAuth 2.1 / OIDC, with first-class Microsoft Entra ID support.
One Go binary, configured by environment variables.

- Scope and non-goals: [ADR-0001](docs/adr/0001-scope-auth-only-proxy-entra-first-class.md)
- Landscape research: [docs/research.md](docs/research.md)
- Feature backlog: [docs/features.md](docs/features.md)

## Development

Requires [mise](https://mise.jdx.dev). Then:

```sh
mise install
mise run check
```

Release artifacts (image, archives, SBOMs) and how to verify them:
[docs/reference/packaging.md](docs/reference/packaging.md).

## License

[Apache-2.0](LICENSE)
