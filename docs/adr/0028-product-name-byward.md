# ADR-0028: The product is named byward

- Status: Accepted
- Date: 2026-11-06
- Issue: none (decided while planning the launch)

## Context

The project started as `mcp-authproxy`. Before v0.1.0 two problems with that name came up:

- **Confusion with direct competitors.** `sigbit/mcp-auth-proxy` and `babs/mcp-auth-proxy` are
  auth proxies for MCP servers whose names differ from ours by one hyphen. In search results,
  chat, list entries and launch posts the names read as the same project.
- **The MCP trademark.** The LF Projects trademark policy (lfprojects.org/policies/trademark-policy,
  last updated 2026-10-22) lists "Model Context Protocol®" as registered and "MCP™" as in use. It
  says "A trademark should not be used as part of your product name" and should not be
  "hyphenated"; "<your product name> for <LF Projects mark>" is the allowed form. Whether the
  policy reaches an open-source project name is not stated; the plain reading is that it does.

The name is public interface: the Go module path, the binary, the container image, every setting
(`--flag` and environment variable), the token and cookie prefixes, metric names and the audit
stream. Before the first release a rename costs one mechanical change; after it, every user's
configuration breaks.

Candidates were checked against GitHub, Go modules, Docker Hub, npm and DNS, and against existing
auth, proxy and agent-security projects (research notes kept outside the repository). Most
gate and guard words are already used by agent-security projects.

## Decision

1. **The product is named byward**, after the Byward Tower, the gatehouse through which the Tower
   of London is entered. The description is "byward, a sign-in gate for MCP servers": MCP appears
   only in the descriptive "for MCP" form.
2. **Home:** the GitHub organisation `byward-dev` and the domain `byward.dev`. Go module
   `github.com/byward-dev/byward`; image `ghcr.io/byward-dev/byward`; binary `byward`.
3. **Conventions:**
   - settings: `BYWARD_*` environment variables (the flag names are unchanged);
   - token and cookie prefix `byw_` (not `bw_`, which the Bitwarden CLI uses);
   - metric prefix `byward_`;
   - default paths `/var/lib/byward`, `/etc/byward`.
4. **Earlier ADRs** have the product name, setting prefix and paths substituted editorially. No
   decision in them changed; their history before this ADR is in git.

## Consequences

- Trademark databases were checked by the maintainer on 2026-11-06 (USPTO, and TMview for the EU
  and national offices; Nice classes 9 and 42). No live BYWARD mark in either class was found; the
  only hit in them had expired. This was a knock-out search, not a legal clearance opinion.
- No compatibility shims: nothing was released under the old name.
- The repository moves from `corker/mcp-authproxy` to `byward-dev/byward`. GitHub redirects the
  web and git URLs, but not the Go module path or image path, which is why both changed at once.
- Keyless signing identities name the repository, so release verification commands use the new
  path.

## Considered options

- Keep `mcp-authproxy`, or ask LF Projects for permission: rejected, the competitor confusion
  remains either way.
- `hailgate`, `durward`, `keepward`, `stilegate`: clean but less distinctive or harder to say.
- Stay under the personal account (`corker/byward`): rejected, because a later move would change
  the module and image paths a second time.
