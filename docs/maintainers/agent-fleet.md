# Agent fleet rules

Rules for when several coding agents work on this repository at once, under a coordinating
session. A single agent making one change needs only [AGENTS.md](../../AGENTS.md).

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
