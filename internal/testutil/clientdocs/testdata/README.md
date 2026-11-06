Client ID Metadata Documents published by real MCP clients, captured 2026-11-06 with
`curl -H 'Accept: application/json'`. Fixtures only, never presets in code (ADR-0009 §9); refresh
them when a client changes its document. `*.headers` keep only Cache-Control and Content-Type.

| File | URL |
|---|---|
| claude-code.json | https://claude.ai/oauth/claude-code-client-metadata |
| claude-ai.json | https://claude.ai/oauth/mcp-oauth-client-metadata (claude.ai's client ID is not confirmed by any document found) |
| vscode.json | https://vscode.dev/oauth/client-metadata.json |

## Dynamic client registration requests (`dcr/`)

The JSON bodies these clients POST to `/register` (RFC 7591), reconstructed from their source on
2026-11-06 rather than captured traffic. Fixtures only; refresh them when a client changes.

| File | Source |
|---|---|
| dcr/gemini-cli.json | gemini-cli @9676e7e (core 0.69.0-nightly), packages/core/src/mcp/oauth-provider.ts:124-131; the loopback port is OS-assigned, 52341 is an example |
| dcr/mcp-inspector.json | inspector @4d3464c, core/auth/providers.ts:319-342; the MCP TypeScript SDK (@modelcontextprotocol/client 2.4.0 @1e608ca) sends the host's metadata, auth.ts:2563-2609 |
| dcr/cursor.json | Cursor 3.14.27, forum.cursor.com/t/167608 (user report); the redirect URIs are confirmed by Cursor staff in forum.cursor.com/t/171867, the other fields are [unverified]. Its `cursor://` callback fails the redirect policy (ADR-0009) and is dropped |
