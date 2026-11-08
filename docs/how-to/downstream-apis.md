# Call a downstream API as the user: On-Behalf-Of

An upstream MCP server that calls an API such as Microsoft Graph for the signed-in user can get a
token for that API from byward. byward exchanges the user's sign-in for it with Entra's
On-Behalf-Of flow and sends it with every request to the upstream, in a header of its own
([ADR-0017](../adr/0017-delegation-obo.md)). The upstream never needs Entra credentials, and never
sees the user's sign-in token.

Supported: Microsoft Entra (`BYWARD_IDP=entra`, the default), with an HTTP upstream or a stdio
one. A stdio upstream asks its token socket for the token instead of reading a header
([section 5](#5-a-stdio-upstream)). An app-only caller ([app-only tokens](app-tokens.md)) acts for no user, so its requests
reach the upstream without a downstream token; the assertion's `principal_type` says so.

> Not yet verified against a real tenant in this release; the fake IdP's Entra profile is the test.

## 1. Grant the API permissions

On the app registration byward signs users in with (see the [Entra quickstart](quickstart-entra.md)):

1. **API permissions → Add a permission**: the downstream API's **delegated** permissions, for
   example Microsoft Graph `User.Read`.
2. **Grant admin consent** for the tenant. Users cannot consent to these themselves through
   byward: On-Behalf-Of has no screen to ask them on.

Without consent, Entra refuses the exchange (AADSTS65001), and byward tells the operator how to fix
it (section 4).

## 2. Configure the scopes

```sh
BYWARD_OBO_SCOPES="https://graph.microsoft.com/User.Read"
```

- Give the scopes of **one** API (Entra issues a token for one API per request), in one of three
  forms:
  - a scope URI, for example `https://graph.microsoft.com/User.Read https://graph.microsoft.com/Mail.Read`;
  - `api://<app ID>/<scope>` for an API of your own;
  - `<app ID>/<scope>` for an API known by its application ID, for example
    `6dae42f8-4368-4678-94ff-3960e28e3630/.default` for the Azure Kubernetes Service server app,
    whose ID Microsoft lists as the token audience in
    [its kubelogin guide](https://learn.microsoft.com/en-us/azure/aks/kubelogin-authentication).
    Use one form for all of an API's scopes: `api://<app ID>/…` and `<app ID>/…` are not mixed.
- Never give sign-in scopes (`openid`, `offline_access`): byward requests those itself.
- Empty (the default) turns On-Behalf-Of off.

## 3. Read the token in the upstream

Every request to the upstream carries:

```
X-Byward-Downstream-Token: Bearer <token for the downstream API>
```

- Use the value as the `Authorization` header of your call to the downstream API.
- The header name is `BYWARD_OBO_HEADER`. It must differ from the identity assertion's header
  (`BYWARD_ASSERTION_HEADER`) and from the upstream credential's (`BYWARD_UPSTREAM_CREDENTIAL_HEADER`).
- A client can never supply it. Every inbound copy is removed, even while On-Behalf-Of is off.
- The token is for the user who made the MCP request. byward keeps it in memory, per replica, until
  a minute before it expires. It is never stored or logged.
- While On-Behalf-Of is on, byward's own access tokens expire a minute before the user's Entra token
  does. The client's normal refresh then renews both, so every request has a valid sign-in to
  exchange.

### An upstream that reads the user's token from `Authorization`

Many Entra-protected MCP servers expect the user's token in `Authorization: Bearer`, and call the
downstream API with it. Give them the downstream token there, and move the identity assertion to a
header of its own:

```
BYWARD_ASSERTION_HEADER=X-Byward-Assertion
BYWARD_OBO_HEADER=Authorization
```

The upstream then gets exactly one `Authorization`, `Bearer <token for the downstream API>`; the
client's own `Authorization` (byward's access token) is always removed first. An app-only caller
([app-only tokens](app-tokens.md)) gets no downstream token, so its requests reach the upstream
without `Authorization`.

## 4. When Entra refuses

The MCP client never gets a 401 or 403 for these, which would send it into a sign-in loop. It gets
an answer it can show the user, as for an [upstream refusal](../adr/0025-upstream-refusal.md):

- a tool call returns a tool error;
- any other request gets a JSON-RPC error with `data.downstream` set to the reason.

Nothing reaches the upstream.

| Reason | Cause | What to do |
|---|---|---|
| `consent_required` | AADSTS65001: the API permissions are not consented | Open the admin-consent URL from the error log (`admin_consent_url`) as a tenant administrator, or grant consent in the portal |
| `interaction_required` | Conditional Access wants a step the proxy cannot complete for the downstream API | Check the sign-in log for the policy; passing its challenge to the client's next sign-in is not supported yet |
| `unavailable` | Entra did not answer, or refused byward's own credential | As for sign-in failures: check the IdP's health and the client secret or certificate |
| `failed` | Anything else | The error log names the AADSTS code and Entra's trace and correlation IDs |

Each refusal is in the audit stream as `downstream_token_refused`, and is counted in
`byward_downstream_tokens_total{outcome}`
([observability reference](../reference/observability.md)).

The admin-consent URL returns to byward's `/callback/entra`, which shows a confirmation or error
page. That redirect cannot be verified, so it changes nothing: the next request simply exchanges
again. Entra itself records the consent.

## 5. A stdio upstream

A [stdio upstream](stdio-upstream.md) process asks byward for the token when it needs it, on a Unix
socket named in its environment. The socket accepts only that process and the processes it starts
(a launcher such as `npx` or `uvx` included).

```
BYWARD_DOWNSTREAM_TOKEN_SOCKET=/tmp/byward-session-1234/token.sock
```

Connect, write one JSON object on one line, and read one line back:

```
→ {}
← {"access_token":"eyJ0eXAi...","expires_at":"2026-11-08T13:00:00Z"}
← {"error":"consent_required"}
```

Use `Bearer <access_token>` for the downstream API, and ask again before `expires_at`. Each answer
is for the user this process serves, from the sign-in of the request it served last.

| `error` | Meaning |
|---|---|
| `consent_required`, `interaction_required`, `unavailable`, `failed` | As in [section 4](#4-when-entra-refuses). The client's request was already answered by byward, so this happens only when a token expired between requests. |
| `sign_in_expired` | The user's sign-in has expired since their last request. Their next request renews it; ask again then. |
| `no_user` | The process serves an app-only caller, which acts for no user. |
| `refused` | The connection came from a process outside this upstream process's tree. |
| `bad_request` | The request was not one JSON object on one line. |

Python:

```python
import json, os, socket

def downstream_token() -> str:
    with socket.socket(socket.AF_UNIX) as s:
        s.connect(os.environ["BYWARD_DOWNSTREAM_TOKEN_SOCKET"])
        s.sendall(b"{}\n")
        answer = json.loads(s.makefile().readline())
    if "error" in answer:
        raise RuntimeError("no downstream token: " + answer["error"])
    return answer["access_token"]
```

TypeScript (Node):

```ts
import { createConnection } from "node:net";
import { createInterface } from "node:readline";

export function downstreamToken(): Promise<string> {
  return new Promise((resolve, reject) => {
    const s = createConnection(process.env.BYWARD_DOWNSTREAM_TOKEN_SOCKET!, () => s.write("{}\n"));
    createInterface({ input: s }).once("line", (line) => {
      s.end();
      const a = JSON.parse(line);
      a.error ? reject(new Error("no downstream token: " + a.error)) : resolve(a.access_token);
    });
    s.on("error", reject);
  });
}
```

- A server that reads a fixed environment variable needs this change. A token that expires within
  the hour cannot reach it any other way without restarting it, which would end the session.
- `BYWARD_OBO_HEADER` has no effect for a stdio upstream, and setting it is refused.
- A server started with `docker run -i` cannot reach the socket: its process does not descend from
  the one byward started. Nor can a process that detached by forking twice (`(cmd &)`, a daemon):
  the kernel gives it a new parent, so it no longer descends from the upstream process.
- Every upstream process runs as byward's uid. On a host that lets processes of one uid read each
  other's memory (`kernel.yama.ptrace_scope` 0, Debian's default), another user's process could read
  the token from memory. byward warns at startup and in `doctor`; see
  [Harden a deployment §10](harden-a-deployment.md#10-isolate-stdio-upstream-processes).
- On Linux before 6.5, and on macOS (for development only), a narrow race remains: a process that
  hands its connection to another and exits, with its process ID reused inside the upstream's tree
  before byward checks it, would pass the check ([ADR-0017](../adr/0017-delegation-obo.md), amendment of 2026-11-08).
