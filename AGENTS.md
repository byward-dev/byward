# byward — instructions for coding agents

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
| Release build and smoke test, no publish (Docker) | `mise run release:smoke` |
| Add or change a setting | edit `internal/config/settings.go`, then `BYWARD_UPDATE_REFERENCE=1 go test ./internal/config/` |

**Run `mise run check` before claiming a change is done.** CI runs the same task.

**Before reporting a PR ready, sweep its diff** against `origin/main` with `/sweep-runtime`,
`/sweep-solid` and `/sweep-tests`. Push the fixes, and list each angle's findings and fixes (or
"no findings") in the PR description. Agents never merge.

- **When:** once the code is complete, never mid-implementation, and before asking for the merge
  slot.
- **How much:** the coordinating session sets the tier when it hands out the work; without one, take
  the tier the table gives for the code you changed.

  | Tier | For | Angles |
  |---|---|---|
  | Full | Code behind the security invariants: broker, tokens, IdP, relay, upstream, stdio, logging redaction, security settings | All |
  | Standard | Other production code | runtime, coverage, quality, names, single responsibility |
  | Tests | Test-only changes | coverage, quality, determinism, data-driven |
  | None | Docs and CI configuration | None; say so in the PR |

- **Angles:** runtime (run the changed code, edge cases included); the five SOLID angles (single
  responsibility, open/closed, Liskov substitution, interface segregation, dependency inversion);
  the seven test angles (coverage, quality, names, pyramid, determinism, data-driven,
  structure vs behaviour). The `/sweep-*` skills are not in this repository; without them, review
  each angle by hand.
- **Rounds:** round 1 runs every angle of the tier. After that, re-run only the angles that had
  findings or whose files a fix touched; the last of those rounds must be clean. Stop after 5
  rounds. Anything still open goes in the PR description or a `ready-for-agent` issue.

## Layout rules

1. All code under `internal/`; `cmd/byward` stays thin (config → wire → run). No `pkg/`.
   This is a binary, not a library (ADR-0002).
2. Packages are named after `CONTEXT.md` concepts or ADR terms. No `util`, `common`, `models`,
   `helpers`.
3. Adapters are one package each behind an interface: `internal/idp/<provider>`,
   `internal/upstream/<kind>`, `internal/store/<impl>`. Core packages depend on the
   interface only; `internal/server` is the only place that wires concrete adapters. The one
   exception: `cmd/byward`'s `downstream-token` is a client of `internal/upstream/stdio`'s token
   socket.
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
- The full AI-assistance policy and the test policy are in `CONTRIBUTING.md`.

## Working in parallel

Several agents often work on this repo at once. These rules keep their work from colliding.

- **Own git worktree.** Work only in your own worktree off `origin/main`. Never `checkout`, `switch`,
  `reset`, `stash` or `pull` in the main checkout, and never touch another worktree.
- **Subagents get a unique scratch path.** Chain `cd <path> && <command>` so a failed `cd` stops the
  command instead of running it elsewhere. No `git checkout --`/`reset` in subagent briefs. Stop only
  processes you started, matched by your own scratch path, never with `kill -9` on a name pattern.
- **Gate every push on the check.** Chain with `&&`, never `;`: `mise run check && git push …`.
  Capture the log with a redirect, not a pipe: `mise run check > check.log 2>&1 && git push …`.
  A pipe (`| tee`, `| grep`, `| tail`) returns the last command's status and hides a failing check.
- **Open PRs freely; merge one at a time.** Any number of PRs may be open and get CI. Don't
  rebase while you work, not even when `main` moves. Rebase earlier only when
  `git merge-tree --write-tree origin/main HEAD` reports a conflict.
- **The merge slot.** When the sweeps are clean, report READY. The coordinating session gives
  the merge slot to one PR at a time. Holding it: rebase onto `origin/main`, keep both sides of
  any conflict, re-run the check and any sweep a code conflict touched, push, and report again.
  The PR is then merged before the slot moves on.
- **Generated files are never hand-merged.** `docs/reference/settings.md` conflicts are resolved
  by regenerating it: `BYWARD_UPDATE_REFERENCE=1 go test ./internal/config/`.
- **Sweeps run as one subagent per angle** (runtime; 5 SOLID; 7 tests) through ordinary subagent
  calls. Multi-agent workflow tooling needs the maintainer's explicit opt-in.
- **A mutation result counts only if the run was real:** the baseline is green with the same
  toolchain (the pinned Go, not an untrusted tool setup that fails before tests run), and the killing
  test is named and seen failing on the mutant.
- **Don't poll CI in loops.** The GitHub API budget is shared by every agent on the account; let the
  coordinating session watch checks, or wait at least 60 s between polls.
- **One session files issues.** When several agents work at once, send issue drafts to the
  coordinating session instead of filing them, so nothing is filed twice.

## Agent skills

### Issue tracker

GitHub Issues on `byward-dev/byward` via the `gh` CLI. See `docs/agents/issue-tracker.md`.

### Triage labels

Default vocabulary (`needs-triage`, `needs-info`, `ready-for-agent`, `ready-for-human`, `wontfix`). See `docs/agents/triage-labels.md`.

### Domain docs

Single-context: `CONTEXT.md` + `docs/adr/` at the repo root. See `docs/agents/domain.md`.
