#!/bin/sh
# Docs lint (part of `mise run check`): fails on wording that goes stale, and on a byward image tag
# other than the one in scripts/docs-image-tag, in the repository's Markdown.
#
# Stale wording, outside docs/adr/ and docs/archive/ (dated records, where it is history):
#   "not supported yet", "not yet supported"  say what is supported, or link the issue
#   "in v0.1"                                 a release qualifier that outlived its release
#   "slice 1.x"                               an internal delivery label
#   "as of YYYY-MM-DD" without a version      name the release the statement is about
#   "byward:latest"                           pin the image tag
# Image tag, everywhere but docs/archive/: every ghcr.io/byward-dev/byward:<tag> names the tag in
# scripts/docs-image-tag; vX.Y.Z (a placeholder) and snapshot-* (a local build) are allowed.
#
# A line holding "docs-lint: allow" (e.g. <!-- docs-lint: allow: the reason -->) is not checked.
# Usage: sh scripts/docs-lint.sh [repository root]
set -eu
root=${1:-.}
# Drop every trailing slash (so rel below is relative); "/" stays as it is.
case $root in (*[!/]*) root=${root%"${root##*[!/]}"} ;; esac
tag_file="$root/scripts/docs-image-tag"
[ -f "$tag_file" ] || { echo "docs-lint: $tag_file is missing" >&2; exit 2; }
tag=$(grep -v '^#' "$tag_file" | tr -d '[:space:]')
[ -n "$tag" ] || { echo "docs-lint: $tag_file holds no tag" >&2; exit 2; }

found=$(find "$root" \( -name .git -o -name .claude -o -name build -o -name dist -o -name node_modules -o -name testdata \) -prune -o -name '*.md' -type f -print | sort |
  while IFS= read -r f; do
    rel=${f#"$root"/}
    stale=1
    case $rel in (docs/adr/*) stale=0 ;; esac
    case $rel in (docs/archive/*) continue ;; esac
    awk -v file="$rel" -v stale="$stale" -v want="$tag" '
      /docs-lint: allow/ { next }
      {
        line = tolower($0)
        if (stale) {
          if (line ~ /not supported yet|not yet supported/) print file ":" NR ": \"not supported yet\": say what is supported, or link the issue"
          if (line ~ /in v0\.1([^0-9]|$)/) print file ":" NR ": \"in v0.1\": a release qualifier that outlived its release"
          if (line ~ /slice[ -]1\.[0-9]/) print file ":" NR ": \"slice 1.x\": an internal delivery label"
          if (line ~ /as of [0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]/ && line !~ /v[0-9]+\.[0-9]+/) print file ":" NR ": \"as of <date>\" without a version: name the release"
          if (line ~ /byward:latest/) print file ":" NR ": \"byward:latest\": pin the image tag"
        }
        rest = $0
        while (match(rest, /ghcr\.io\/byward-dev\/byward:[A-Za-z0-9][A-Za-z0-9._-]*/)) {
          t = substr(rest, RSTART + 26, RLENGTH - 26)
          if (t != want && t != "vX.Y.Z" && t !~ /^snapshot-/) print file ":" NR ": image tag " t ", want " want " (scripts/docs-image-tag)"
          rest = substr(rest, RSTART + RLENGTH)
        }
      }' "$f"
  done)

if [ -n "$found" ]; then
  printf '%s\n' "$found"
  echo "docs-lint: fix the lines above, or mark one that is right with <!-- docs-lint: allow: the reason -->" >&2
  exit 1
fi
