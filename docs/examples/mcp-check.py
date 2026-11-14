# /// script
# requires-python = ">=3.11"
# dependencies = ["mcp==2.3.0"]
# ///
"""Check byward without an AI client: register (DCR), sign in through the browser, list the tools,
and call the reference server's echo tool if there is one.

    uv run --script mcp-check.py http://localhost:8080/mcp

The browser comes back to http://127.0.0.1:33418/callback, which this script listens on.
"""
import asyncio, sys
from urllib.parse import parse_qs, urlparse

import httpx2
from mcp import ClientSession
from mcp.client.auth import AuthorizationCodeResult, OAuthClientProvider
from mcp.client.streamable_http import streamable_http_client
from mcp.shared.auth import OAuthClientMetadata

URL, PORT = sys.argv[1], 33418
REDIRECT = f"http://127.0.0.1:{PORT}/callback"


class Memory:  # tokens and the registration (DCR) live only for this run
    tokens = client = None
    async def get_tokens(self): return self.tokens
    async def set_tokens(self, tokens): self.tokens = tokens
    async def get_client_info(self): return self.client
    async def set_client_info(self, client): self.client = client


async def main():
    redirected = asyncio.get_running_loop().create_future()

    async def on_callback(reader, writer):  # the browser lands here after the sign-in
        target = (await reader.readline()).decode().split(" ")[1]
        writer.write(b"HTTP/1.1 200 OK\r\nContent-Length: 9\r\nConnection: close\r\n\r\nsigned in")
        await writer.drain()
        writer.close()
        if not redirected.done():
            redirected.set_result(target)

    server = await asyncio.start_server(on_callback, "127.0.0.1", PORT)

    async def show(url):
        print(f"Open this URL in a browser and sign in:\n{url}", file=sys.stderr, flush=True)

    async def code():
        q = parse_qs(urlparse(await redirected).query)
        if "error" in q:
            sys.exit(f"sign-in refused: {q['error'][0]}")
        return AuthorizationCodeResult(code=q["code"][0], state=q.get("state", [None])[0], iss=q.get("iss", [None])[0])

    auth = OAuthClientProvider(server_url=URL, storage=Memory(), redirect_handler=show, callback_handler=code,
                               client_metadata=OAuthClientMetadata(client_name="mcp-check", redirect_uris=[REDIRECT],
                                                                   token_endpoint_auth_method="none"))
    async with httpx2.AsyncClient(auth=auth, timeout=120) as http:
        async with streamable_http_client(URL, http_client=http) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                tools = await session.list_tools()
                print("tools:", ", ".join(t.name for t in tools.tools))
                if any(t.name == "echo" for t in tools.tools):  # the MCP reference server's tool
                    result = await session.call_tool("echo", {"message": "hello through byward"})
                    print("echo:", result.content[0].text)
    server.close()


asyncio.run(main())
