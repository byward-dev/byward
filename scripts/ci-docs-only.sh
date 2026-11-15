#!/bin/sh
# Prints docs-only=true when every file a change touches is documentation, else docs-only=false:
# the output of .github/workflows/ci.yml's `changes` job, appended to $GITHUB_OUTPUT.
#   ci-docs-only.sh <base sha> <head sha>   the change is base...head; an empty sha means false
#   ci-docs-only.sh --classify              the changed paths come on stdin (the table test)
# false runs every job, so anything this script cannot be sure of is false.
set -eu

# docs succeeds when every path on stdin is documentation: Markdown outside the code trees, or an
# image under docs/. Any other path, or no path at all, fails. docs/examples holds a Dockerfile
# the release smoke test builds, and testdata belongs to the tests.
docs() {
  seen=0
  f=
  while IFS= read -r f || [ -n "$f" ]; do # a last line without a newline counts too
    seen=1
    case $f in
      .github/* | mise.toml | go.* | internal/* | cmd/* | scripts/* | *testdata* | docs/examples/*) return 1 ;;
      *.md) ;;
      docs/*.png | docs/*.svg | docs/*.jpg | docs/*.jpeg | docs/*.gif | docs/*.webp) ;;
      *) return 1 ;;
    esac
  done
  [ "$seen" -eq 1 ]
}

if [ "${1:-}" = --classify ]; then
  if docs; then echo docs-only=true; else echo docs-only=false; fi
  exit 0
fi

base=${1:-}
head=${2:-}
if [ -z "$base" ] || [ -z "$head" ]; then
  echo "ci-docs-only: no base and head (a push, or an event without them): run everything" >&2
  echo docs-only=false
  exit 0
fi
# --no-renames: a rename must list both paths; with rename detection, internal/x/a.go moved to
# docs/a.md would list only docs/a.md, and a change that deletes code would pass as docs-only.
if ! files=$(git diff --no-renames --name-only "$base...$head"); then
  echo "ci-docs-only: cannot diff $base...$head: run everything" >&2
  echo docs-only=false
  exit 0
fi
printf 'ci-docs-only: changed files:\n%s\n' "$files" >&2
if printf '%s\n' "$files" | docs; then echo docs-only=true; else echo docs-only=false; fi
