"""The Python SDK client (mcp, pinned in requirements.txt) signing in through byward as a
pre-registered public client and calling the upstream's tool.

Usage: python client.py <MCP URL> <client ID> <callback port> <text>
It prints "Please navigate to: <URL>" on stderr; the Go test plays the browser and requests the
callback, and "RESULT: <text>" on stdout once the tool answered.
"""

import asyncio
import sys
from urllib.parse import parse_qs, urlparse

import httpx2
from mcp import ClientSession
from mcp.client.auth import AuthorizationCodeResult, OAuthClientProvider
from mcp.client.streamable_http import streamable_http_client
from mcp.shared.auth import OAuthClientInformationFull, OAuthClientMetadata, OAuthToken

MCP_URL, CLIENT_ID, PORT, TEXT = sys.argv[1], sys.argv[2], int(sys.argv[3]), sys.argv[4]
REDIRECT = f"http://127.0.0.1:{PORT}/callback"


class Memory:
    """Token storage holding the pre-registered client, so no registration is attempted."""

    def __init__(self) -> None:
        self.tokens: OAuthToken | None = None

    async def get_tokens(self) -> OAuthToken | None:
        return self.tokens

    async def set_tokens(self, tokens: OAuthToken) -> None:
        self.tokens = tokens

    async def get_client_info(self) -> OAuthClientInformationFull | None:
        return OAuthClientInformationFull(client_id=CLIENT_ID, redirect_uris=[REDIRECT], token_endpoint_auth_method="none")

    async def set_client_info(self, client_info: OAuthClientInformationFull) -> None:
        pass


async def main() -> None:
    redirected: asyncio.Future[str] = asyncio.get_running_loop().create_future()

    async def on_callback(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        request_line = (await reader.readline()).decode()
        target = request_line.split(" ")[1]
        writer.write(b"HTTP/1.1 200 OK\r\nContent-Length: 9\r\nConnection: close\r\n\r\nsigned in")
        await writer.drain()
        writer.close()
        if not redirected.done():
            redirected.set_result(target)

    server = await asyncio.start_server(on_callback, "127.0.0.1", PORT)

    async def redirect_handler(url: str) -> None:
        print(f"Please navigate to: {url}", file=sys.stderr, flush=True)

    async def callback_handler() -> AuthorizationCodeResult:
        query = parse_qs(urlparse(await redirected).query)
        return AuthorizationCodeResult(code=query["code"][0], state=query.get("state", [None])[0], iss=query.get("iss", [None])[0])

    provider = OAuthClientProvider(
        server_url=MCP_URL,
        client_metadata=OAuthClientMetadata(client_name="python-sdk-real-client", redirect_uris=[REDIRECT], token_endpoint_auth_method="none"),
        storage=Memory(),
        redirect_handler=redirect_handler,
        callback_handler=callback_handler,
    )
    async with httpx2.AsyncClient(auth=provider) as http_client:
        async with streamable_http_client(MCP_URL, http_client=http_client) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                result = await session.call_tool("echo", {"text": TEXT})
                print(f"RESULT: {result.content[0].text}", flush=True)
    server.close()


asyncio.run(main())
