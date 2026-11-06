# mcp-authproxy — instructions for coding agents

Auth-only proxy that puts any MCP server (stdio or HTTP) behind OAuth 2.1 / OIDC, with
first-class Microsoft Entra ID support. Single Go binary. Scope and non-goals: ADR-0001.

## Before you start

- Domain words are defined in `CONTEXT.md`. Use them exactly — especially **IdP** vs
  **upstream** (upstream is always the MCP server, never the IdP).
- Decisions live in `docs/adr/`. Read the relevant ADR before changing a design.
- Work items live in GitHub Issues (`gh issue view <n>`); `docs/features.md` is the index.
- When grilling a feature, walk `docs/quality-lenses.md`.

## Commands

All tools are pinned in `mise.toml`; `mise run` resolves them, no shell activation needed.

| Task | Command |
|---|---|
| Format (writes) | `mise run fmt` |
| Unit tests | `mise run test` |
| Integration tests (Docker) | `mise run test:integration` |
| **Everything CI runs** | `mise run check` |

**Run `mise run check` before claiming a change is done.** CI runs the same task.

## Layout rules

1. All code under `internal/`; `cmd/mcp-authproxy` stays thin (config → wire → run). No `pkg/`.
   This is a binary, not a library (ADR-0002).
2. Packages are named after `CONTEXT.md` concepts. No `util`, `common`, `models`, `helpers`.
3. Adapters are one package each behind an interface: `internal/idp/<provider>`,
   `internal/upstream/<kind>`, `internal/store/<impl>`. Core packages depend on the
   interface only; `internal/server` is the only place that wires concrete adapters.
4. Create a package when the feature that needs it is built — no empty scaffolding.
5. Tests sit next to the code. Shared fakes (fake IdP, fake upstream, scripted MCP client)
   live in `internal/testutil/`.

## Security rules

- Never pass an inbound token through to the upstream (MCP spec: no token passthrough).
- Never log tokens, secrets, authorization codes, or PKCE verifiers.
- Named IdP endpoints are derived from config, never overridable to arbitrary URLs.
- Outbound fetches of client-supplied URLs (CIMD, metadata) go through the SSRF guard.
- Every change keeps the security invariants in `docs/quality-lenses.md` (section "Invariants").

## Branching & merging

- Never commit to `main`. Feature branch → PR (`gh pr create`) → squash merge.
- Do not merge PRs or push to `main` yourself; the maintainer reviews and merges.
- Commit messages: Conventional Commits (`feat:`, `fix:`, `docs:`, `chore:`, `test:`).
- Disclose AI help with the `Co-Authored-By` trailer. Agents never add `Signed-off-by` (ADR-0023).

## Agent skills

### Issue tracker

GitHub Issues on `corker/mcp-authproxy` via the `gh` CLI. See `docs/agents/issue-tracker.md`.

### Triage labels

Default vocabulary (`needs-triage`, `needs-info`, `ready-for-agent`, `ready-for-human`, `wontfix`). See `docs/agents/triage-labels.md`.

### Domain docs

Single-context: `CONTEXT.md` + `docs/adr/` at the repo root. See `docs/agents/domain.md`.
