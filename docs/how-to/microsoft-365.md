# Microsoft 365 data for each signed-in user: a Graph MCP server with On-Behalf-Of

> Verified against a real tenant on 2026-11-13 with Graph `User.Read`, over HTTP and stdio. Mail,
> calendar and the other workloads were not tested: the test users had no Microsoft 365 licence.

Mail, calendar, OneDrive, SharePoint and Teams data lives behind
[Microsoft Graph](https://learn.microsoft.com/en-us/graph/overview). An MCP server that calls Graph
with the signed-in user's own token sees only what that user may see: Graph enforces the user's
rights, not the server.

byward gets that token for you. It exchanges each user's sign-in for a Graph token with Entra's
[On-Behalf-Of](downstream-apis.md) flow and passes it to the server in `Authorization`. The server
holds no Entra credentials, and never sees byward's own token. This is for **self-hosted** Graph
MCP servers; Microsoft's hosted Work IQ MCP is already Entra-native.

## 1. Grant the Graph permissions

On byward's app registration (the [Entra quickstart](quickstart-entra.md)), under **API
permissions**, add Microsoft Graph **delegated** permissions for the data the server reads, then
**Grant admin consent**. byward always needs admin consent, even for permissions a user could
otherwise consent to: On-Behalf-Of has no screen to ask the user on ([§1](downstream-apis.md#1-grant-the-api-permissions)).

| Permission | Lets the server read | Graph: admin consent required (delegated) |
|---|---|---|
| `User.Read` | the user's profile | No |
| `Mail.Read` | the user's mail | No |
| `Calendars.Read` | the user's calendars | No |
| `Files.Read.All` | all files the user can access | No |
| `Sites.Read.All` | items in all site collections | No |
| `Chat.Read` | the user's chat messages | No |
| `ChannelMessage.Read.All` | the user's channel messages | Yes |
| `User.Read.All` | all users' full profiles | Yes |
| `Group.Read.All` | all groups | Yes |
| `Mail.Send` | send mail as the user | No |

Source: the [Graph permissions reference](https://learn.microsoft.com/en-us/graph/permissions-reference).
Grant only what the server's tools use. Every permission is delegated: the server can never reach
more than the signed-in user can.

## 2. Configure byward

```sh
BYWARD_OBO_SCOPES="https://graph.microsoft.com/User.Read https://graph.microsoft.com/Mail.Read https://graph.microsoft.com/Calendars.Read"
BYWARD_OBO_HEADER=Authorization
BYWARD_ASSERTION_HEADER=X-Byward-Assertion
BYWARD_UPSTREAM_URL=http://graph-mcp.internal:8000/mcp
```

- **One API per token.** Every scope in `BYWARD_OBO_SCOPES` must be a Graph scope: Entra issues a
  token for one API per request.
- `BYWARD_OBO_HEADER=Authorization` gives the server `Authorization: Bearer <Graph token>`, which is
  what Graph MCP servers expect. The identity assertion moves to `X-Byward-Assertion`, since the two
  must not share a header ([downstream APIs](downstream-apis.md#an-upstream-that-reads-the-users-token-from-authorization)).
- This guide uses an HTTP upstream. A stdio upstream gets the Graph token from its token socket
  instead of a header, and `BYWARD_OBO_HEADER` is refused for it
  ([downstream APIs: a stdio upstream](downstream-apis.md#5-a-stdio-upstream)).

## 3. A minimal Graph MCP server

This server, in Python with the official MCP SDK 1.x (tested with 1.30.0; SDK 2.x renamed FastMCP
to MCPServer), lists the signed-in user's five newest messages.
It forwards the `Authorization` header it receives to Graph and does nothing else with it:

```python
# graph_mcp.py: pip install "mcp[cli]<2" httpx
import httpx
from mcp.server.fastmcp import FastMCP, Context

mcp = FastMCP("graph-mail", host="127.0.0.1", port=8000)

@mcp.tool()
async def latest_mail(ctx: Context) -> list[dict]:
    """The signed-in user's five newest messages: sender, subject and time."""
    auth = ctx.request_context.request.headers.get("authorization")
    if not auth:
        raise ValueError("no Graph token: is byward's On-Behalf-Of on?")
    async with httpx.AsyncClient() as client:
        r = await client.get(
            "https://graph.microsoft.com/v1.0/me/messages",
            params={"$top": "5", "$select": "from,subject,receivedDateTime"},
            headers={"Authorization": auth},
        )
    r.raise_for_status()
    return [
        {
            "from": m.get("from", {}).get("emailAddress", {}).get("address"),
            "subject": m.get("subject"),
            "received": m.get("receivedDateTime"),
        }
        for m in r.json().get("value", [])
    ]

if __name__ == "__main__":
    mcp.run(transport="streamable-http")
```

Bind it where only byward can reach it: anyone who can call it directly can present any Graph
token.

## 4. Use ms-365-mcp-server

[ms-365-mcp-server](https://github.com/Softeria/ms-365-mcp-server) (MIT) is a ready-made Graph MCP
server. Started with `--http`, it requires `Authorization: Bearer <token>` on every MCP request and
uses that request-provided token for its Graph calls, which is exactly what byward sends with
`BYWARD_OBO_HEADER=Authorization` ([#205](https://github.com/byward-dev/byward/issues/205)).

- Run it with `--read-only` for read access only, and narrow its tools with `--enabled-tools`.
- Match `BYWARD_OBO_SCOPES` to what its enabled tools need: `--list-permissions` prints them.

## 5. When Entra refuses

Entra can refuse the exchange; the client then gets an answer it can show, never a 401
([§4](downstream-apis.md#4-when-entra-refuses)). Until the cause is fixed the client cannot connect:
`initialize` is refused too, so look in byward's error log. For Microsoft 365, two causes are common:

- **`consent_required`**: a permission in `BYWARD_OBO_SCOPES` has no admin consent. The error log's
  `admin_consent_url` opens the consent screen for a tenant administrator.
- **`interaction_required`**: a Conditional Access policy on Graph (for example multifactor
  authentication for Exchange Online) wants a step the proxy cannot complete. Check the user's
  sign-in log for the policy; passing its challenge to the client is not supported yet.
