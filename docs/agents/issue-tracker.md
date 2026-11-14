# Issue tracker: GitHub

Issues and PRDs for this repo live as GitHub issues on `byward-dev/byward`. Use the `gh`
CLI for all operations.

## Conventions

- **Create an issue**: `gh issue create --title "..." --body "..."`. Use a heredoc for multi-line bodies.
- **Read an issue**: `gh issue view <number> --comments`, filtering comments by `jq` and also fetching labels.
- **List issues**: `gh issue list --state open --json number,title,body,labels,comments --jq '[.[] | {number, title, body, labels: [.labels[].name], comments: [.comments[].body]}]'` with appropriate `--label` and `--state` filters.
- **Comment on an issue**: `gh issue comment <number> --body "..."`
- **Apply / remove labels**: `gh issue edit <number> --add-label "..."` / `--remove-label "..."`
- **Close**: `gh issue close <number> --comment "..."`

Infer the repo from `git remote -v` — `gh` does this automatically when run inside a clone.

## Repo-specific rules

- The issues are the backlog. `docs/archive/features.md` maps the v0.1 features (`F<n>`) to
  their issues and ADRs; it is history and is not updated.
- The triage labels exist on the repo; their strings are in `docs/agents/triage-labels.md`.
- Use `CONTEXT.md` vocabulary in issue titles and bodies (see `docs/agents/domain.md`).

## When a skill says "publish to the issue tracker"

Create a GitHub issue.

## When a skill says "fetch the relevant ticket"

Run `gh issue view <number> --comments`.
