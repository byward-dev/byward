Client ID Metadata Documents published by real MCP clients, captured 2026-11-06 with
`curl -H 'Accept: application/json'`. Fixtures only, never presets in code (ADR-0009 §9); refresh
them when a client changes its document. `*.headers` keep only Cache-Control and Content-Type.

| File | URL |
|---|---|
| claude-code.json | https://claude.ai/oauth/claude-code-client-metadata |
| claude-ai.json | https://claude.ai/oauth/mcp-oauth-client-metadata (claude.ai's client ID is not confirmed by any document found) |
| vscode.json | https://vscode.dev/oauth/client-metadata.json |
