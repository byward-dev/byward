# ADR-0027: `--insecure-no-auth`, a loopback-only mode without authentication

- Status: Accepted
- Date: 2026-11-06
- Issue: #48 (follow-up), #60 (stdio)

## Context

ADR-0005 §2 rejected an "off" mode: "An auth proxy with auth off is a foot-gun." Two needs
argue for a narrow exception:

- **Trying it out:** running a stdio MCP server over HTTP in one command before choosing an IdP.
  Anonymous bridges are widely used (2026-11-06: sparfenyuk/mcp-proxy about 888k PyPI downloads a
  month, supergateway about 344k on npm, against ★185 for an auth proxy like sigbit's). A mode
  that later becomes authenticated with the same binary and URL keeps those users.
- **Testing:** the MCP conformance `server` command has no option to send a token or header, so it
  can only test an unauthenticated server. Without this mode, ADR-0024 §4a needs a test-only
  token injector.

Evidence (research ANON-mode.md; runtime 2026-11-06):

- **Spec 2026-07-28:** servers MUST validate `Origin` and answer 403 when it's invalid; local
  servers SHOULD bind to localhost. The security guide: "Binding to 127.0.0.1 is not an
  authentication boundary."
- **Competitors:**
  - supergateway binds every interface and has no Host/Origin check;
  - mcp-proxy binds 127.0.0.1 but just fixed a DNS-rebinding advisory (GHSA-8grc-q47q-7v3r);
  - ToolHive `thv run` only warns on a non-loopback bind;
  - go-sdk's automatic rebinding check does nothing inside a container.

  None refuses to start, or ties its Host allowlist to a configured URL.
- **Clients:** with no protected-resource metadata and no 401, none of Claude Code, MCP Inspector,
  go-sdk, the TS SDK, the Python SDK or gemini-cli (runtime) or VS Code (source) asks for
  `/.well-known/*`. Claude Code and VS Code treat any 403 as "needs auth".
- **Docker (Docker Desktop 28.4, runtime):**
  - with `-p 127.0.0.1:P:P` the port is unreachable from the LAN;
  - with `-p P:P` the LAN reaches it, a forged `Host: localhost` is accepted, and the container
    sees the same peer address for local and LAN callers;
  - so the container cannot check the host-side publish.

## Decision

1. **`--insecure-no-auth`** (`BYWARD_INSECURE_NO_AUTH`) serves the upstream with no
   authentication: no token check, no protected-resource metadata, no 401 challenge, no broker
   endpoints.
2. **Startup refuses** unless:
   - the public URL is loopback;
   - the listen address is loopback, or the proxy runs in a container (`/.dockerenv` or
     `/run/.containerenv`) **with its own network namespace**. Host networking (`--network host`)
     binds the host's interfaces, so it is detected from `/proc/self/net/dev` and refused: only
     `lo`, the kernel's tunnel placeholders and an `ethN` with a peer (`iflink` ≠ `ifindex`, as
     for veth, macvlan and ipvlan; a physical NIC has them equal) are allowed, and an unknown interface or an
     unreadable list also refuses (measured on Docker 28.4: host networking adds `docker0`,
     `bond0`, `dummy0`, `teql0`, `services1`);
   - extra allowed hosts and origins are loopback only;
   - no authentication setting is present (settings marked `Auth` in the registry).
3. **Every protection stays on:** the exact Host allowlist from the public URL (it blocks DNS
   rebinding), the `Origin` check, the header stripping (an inbound `Authorization` never reaches
   the upstream), body limits and admission caps. An `access_token` query parameter is stripped
   by the relay in every mode.
   - The proxy's own origin (default port dropped) is always allowed: another site cannot forge
     it. The conformance `dns-rebinding-protection` scenario passes 2/2 for both eras with this.
4. **Startup log, at warning level:**
   - "AUTHENTICATION IS OFF", naming the URL, and saying that the upstream receives no identity;
   - inside a container, the `docker run -p 127.0.0.1:PORT:PORT …` command;
   - the next step towards sign-in.
5. **`http` is allowed for the loopback public URL** without `--dev`.
6. **The `Origin` 403 body names the fix** (`BYWARD_ALLOWED_ORIGINS`), since clients read a
   403 as "needs auth".
7. _Amends ADR-0005 §2:_ an "off" mode exists only inside these fences.
8. _Amends ADR-0024 §4a:_ MCP conformance `server` runs against the binary in this mode at
   `http://127.0.0.1:…`. The token injector is not needed for that lane.

## Consequences

- Anyone who can reach the listener can use the upstream: other local users, and the LAN if a
  container port is published on all interfaces. The docs say so, and show the safe
  `-p 127.0.0.1:…` form.
- Hosts with Docker Engine before 28.0 let the local network segment reach ports published on
  127.0.0.1 (moby#45610). Documented, since it can't be detected from inside the container.
- stdio in this mode runs as one anonymous user, so the modern era shares one process (slice 3.1);
  the audit stream records `principal_type: anonymous` (slice 5.1).
- Rootless Podman with pasta copies the host's interface name (e.g. `enp3s0`) and is refused;
  use a loopback listen address there.
- Cursor is unverified (slice 1.7).

## Considered options

- No such mode (ADR-0005 as written): loses both needs.
- Fold it into `--dev`: hides the most dangerous relaxation among the dev conveniences.
- `--no-auth` on any address (supergateway): one typo exposes the upstream to the network.
- A second acknowledgement flag for containers: no more verifiable than detection, and it breaks
  the one-line try-out.
- Accept only the container gateway as peer: Docker Desktop shows the same peer for LAN callers.
