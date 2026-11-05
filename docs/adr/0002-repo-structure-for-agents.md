# ADR-0002: Repository structure optimised for coding agents

- Status: Accepted
- Date: 2026-11-05

## Context

Most development on this repo is done with Claude Code; as a public project, contributors
may use other agents. Agents work best with one source of instructions, a single
verification command, deterministic feedback, and a domain vocabulary that matches package
names.

## Decision

1. **Instructions:** `AGENTS.md` holds the content; `CLAUDE.md` is `@AGENTS.md`. Claude Code
   reads a lone `AGENTS.md` only from v2.1.277 and ignores it when a `CLAUDE.md` exists, so
   the import is required (https://code.claude.com/docs/en/memory). Per-directory files only
   when an area has local rules — as `CLAUDE.md`, which loads on read/write/edit.
2. **Planning:** decisions in `docs/adr/`; work items in GitHub Issues with milestones;
   `docs/features.md` is an index only.
3. **Binary only:** all code in `internal/`, per https://go.dev/doc/modules/layout ("Server
   projects … keep the Go packages implementing the server's logic in the `internal`
   directory"). Packages may be promoted to a public API later without breaking users.
4. **Packages by domain concept**, named after `CONTEXT.md` terms; adapters (IdP, upstream,
   store) are one package each behind an interface; packages are created when their feature
   is built. Evidence: dex splits `server/` into concept packages down to ~200 lines
   (`consent`, `discovery`) and keeps one package per connector; ToolHive splits
   `pkg/auth/{dcr,discovery,obo,sessionbinding}` and separates validation (`pkg/auth`) from
   issuance (`pkg/authserver`) — measured 2026-11-05.
5. **One verification command:** mise tasks; `mise run check` locally and in CI.
6. **Hooks:** a PostToolUse hook formats each edited `.go` file. Tests and lint stay an
   instruction (they need judgement mid-TDD); CI is the hard gate.
7. **Test harness in-repo:** fake IdP with quirk profiles (`entra`, `okta`, …), fake HTTP and
   stdio upstreams that echo received identity, and a scripted MCP client driving the full
   OAuth flow headlessly. Keycloak testcontainer in `test:integration`; real Entra as a
   scheduled CI lane; real clients on a manual release checklist.
8. **Committed `.claude/settings.json`:** format hook + read-mostly allowlist; merges and
   pushes always ask. Project skills (`add-idp-adapter`, …) are written after the second
   adapter exists, not before. `.mcp.json` added once `mise run dev` exists.
9. **`CONTEXT.md` seeded** with the terms that collide in this domain (client, upstream,
   token, broker).
10. **License:** Apache-2.0, matching agentgateway, Pomerium, ToolHive, dex, Envoy.

## Alternatives considered

- `CLAUDE.md` only — rejected: public repo, other agents.
- Markdown-only planning — rejected: Issues are visible to contributors and close via PRs.
- `pkg/` layout (sigbit, oauth2-proxy, ToolHive) — rejected: implicit public API.
- Layer packages (`models/`, `repository/`, `utils/`) — rejected: features span every layer.
- Start with one `internal/auth` package — rejected: peers split by concept even when small.
- Makefile / Taskfile / just — rejected: mise already pins the toolchain.
- Per-edit test hooks or a Stop hook running `check` — rejected: noisy mid-TDD, slows every turn.
- MIT — viable; rejected for the lack of an explicit patent grant in security infrastructure.
