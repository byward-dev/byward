# byward — instructions for coding agents

Auth-only proxy that puts any MCP server (stdio or HTTP) behind OAuth 2.1 / OIDC, with
first-class Microsoft Entra ID support. Single Go binary. Scope and non-goals: ADR-0001.

## Before you start

- Domain words are defined in `CONTEXT.md`. Use them exactly — especially **IdP** vs
  **upstream** (upstream is always the MCP server, never the IdP).
- Decisions live in `docs/adr/`. Read the relevant ADR before changing a design.
- Work items live in GitHub Issues (`gh issue view <n>`). The docs index is `docs/README.md`.
- When grilling a feature, walk `docs/quality-lenses.md`.
- Reuse before writing. Before adding a helper, fake, parser or test recorder, search `origin/main`
  for one that already does it and extend it. A second copy is extracted at the third caller,
  and the second copy cites the first.

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
  | Standard | Other production code | runtime, reuse, coverage, quality, names, single responsibility |
  | Tests | Test-only changes | coverage, quality, determinism, data-driven |
  | Pinned | A change whose whole effect a decision golden or a registry walk shows (below) | runtime, coverage; for Full-tier code, also the reviewer reads the golden diff |
  | None | Docs and CI configuration | None; say so in the PR |

- **Pinned:** a decision golden records, per input family, what every check decides. It covers the host
  checks (#656) and the printing surfaces of secret-shaped values (#657). A registry walk applies one
  settings rule to every setting (#658). When such a golden or walk shows the whole effect of a
  change, and its "nothing newly allowed" test passes, the Pinned tier replaces Full or Standard.
  It runs one round. Any decision the diff newly allows goes back to the code's own tier.

- **Angles:** runtime (run the changed code, edge cases included); reuse (search `origin/main`, not
  only the diff, for a function that already does what the diff adds, or a second implementation of
  a concept `CONTEXT.md` names: use or extend the existing one); the five SOLID angles (single
  responsibility, open/closed, Liskov substitution, interface segregation, dependency inversion);
  the seven test angles (coverage, quality, names, pyramid, determinism, data-driven,
  structure vs behaviour). The `/sweep-*` skills are not in this repository; without them, review
  each angle by hand.
- **Rounds:** round 1 runs every angle of the tier. After that, re-run only the angles that had
  findings or whose files a fix touched; the last of those rounds must be clean. Stop after 5
  rounds. Anything still open goes in the PR description or a `ready-for-agent` issue.
- **Severity gate:** a finding is fixed in the PR only when it breaks a security invariant, is a
  correctness bug an operator, user or client can hit, or duplicates existing code. Anything else
  goes to the PR's "Known residuals" with one line why, or is dropped: wording, an input no real
  client or operator sends, a new golden column or family with no production check behind it.
  The same-gap rule below still decides where class findings go.
- **No new abstraction:** a sweep fix may not add an interface or abstraction with fewer than 3
  callers. SOLID findings are fixed within that limit.
- **Same gap elsewhere:** a finding that another setting, check or surface has the gap the PR fixes
  doesn't become a new per-instance issue. It goes into that class's golden or walk (#656, #657,
  #658), or into "Known gaps" in `docs/security-posture.md`. A class with no golden or walk
  yet gets one class-level issue.

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
- Every change keeps the security invariants in `docs/security-posture.md` (section "Security invariants").

## Branching & merging

- Never commit to `main`. Feature branch → PR (`gh pr create`) → squash merge.
- Do not merge PRs or push to `main` yourself; the maintainer reviews and merges.
- Commit messages: Conventional Commits (`feat:`, `fix:`, `docs:`, `chore:`, `test:`).
- Disclose AI help with the `Co-Authored-By` trailer. Agents never add `Signed-off-by` (ADR-0023).
- The full AI-assistance policy and the test policy are in `CONTRIBUTING.md`.

## Working in parallel

When several agents work on this repo at once, also follow
[docs/maintainers/agent-fleet.md](docs/maintainers/agent-fleet.md): worktrees, the merge slot, CI polling
and issue filing.

## Agent skills

### Issue tracker

GitHub Issues on `byward-dev/byward` via the `gh` CLI. See `docs/agents/issue-tracker.md`.

### Triage labels

Default vocabulary (`needs-triage`, `needs-info`, `ready-for-agent`, `ready-for-human`, `wontfix`). See `docs/agents/triage-labels.md`.

### Domain docs

Single-context: `CONTEXT.md` + `docs/adr/` at the repo root. See `docs/agents/domain.md`.
