// The TypeScript SDK client (@modelcontextprotocol/sdk, pinned in package-lock.json) signing in
// through byward as a pre-registered public client and calling the upstream's tool.
// Usage: node client.mjs <MCP URL> <client ID> <callback port> <text>
// It prints "Please navigate to: <URL>" on stderr; the Go test plays the browser and requests the
// callback, and "RESULT: <text>" on stdout once the tool answered.
import http from 'node:http';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/sdk/client/streamableHttp.js';
import { UnauthorizedError } from '@modelcontextprotocol/sdk/client/auth.js';

const [mcpUrl, clientId, port, text] = process.argv.slice(2);
const redirectUrl = `http://127.0.0.1:${port}/callback`;

let resolveCode;
const code = new Promise((resolve) => { resolveCode = resolve; });
const callback = http.createServer((req, res) => {
  resolveCode(new URL(req.url, redirectUrl).searchParams.get('code'));
  res.end('signed in');
});
await new Promise((resolve) => callback.listen(Number(port), '127.0.0.1', resolve));

let tokens;
let verifier;
const provider = {
  get redirectUrl() { return redirectUrl; },
  get clientMetadata() {
    return { client_name: 'ts-sdk-real-client', redirect_uris: [redirectUrl], grant_types: ['authorization_code', 'refresh_token'],
      response_types: ['code'], token_endpoint_auth_method: 'none' };
  },
  clientInformation() { return { client_id: clientId }; },
  tokens() { return tokens; },
  saveTokens(t) { tokens = t; },
  redirectToAuthorization(url) { console.error(`Please navigate to: ${url}`); },
  saveCodeVerifier(v) { verifier = v; },
  codeVerifier() { return verifier; },
};

const client = new Client({ name: 'ts-sdk-real-client', version: '1.0.0' });
let transport = new StreamableHTTPClientTransport(new URL(mcpUrl), { authProvider: provider });
try {
  await client.connect(transport);
} catch (e) {
  if (!(e instanceof UnauthorizedError)) throw e;
  await transport.finishAuth(await code);
  transport = new StreamableHTTPClientTransport(new URL(mcpUrl), { authProvider: provider });
  await client.connect(transport);
}
const result = await client.callTool({ name: 'echo', arguments: { text } });
console.log(`RESULT: ${result.content[0].text}`);
await client.close();
callback.close();
