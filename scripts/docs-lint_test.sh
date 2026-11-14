#!/bin/sh
# Table test for docs-lint.sh against fixture repositories (no network).
set -eu
# A developer's CDPATH makes cd print the directory, which $(cd ... && pwd) would capture.
unset CDPATH
here="$(cd "$(dirname "$0")" && pwd)"
script="$here/docs-lint.sh"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
failures=0

# check NAME WANT_EXIT FILE CONTENT [WANT_OUTPUT]: a fresh repository whose tag file holds TAGFILE
# (default: a comment and v1.2.3) and whose FILE holds CONTENT; the lint, given ROOT_SUFFIX after
# the repository path, must exit WANT_EXIT, and its output match WANT_OUTPUT (grep -E) when given.
check() {
  name=$1 want_code=$2 file=$3 content=$4 want=${5:-}
  repo="$tmp/repo"
  rm -rf "$repo"
  mkdir -p "$repo/scripts" "$repo/$(dirname "$file")"
  printf '%b' "${TAGFILE:-# a comment\nv1.2.3\n}" >"$repo/scripts/docs-image-tag"
  printf '%s\n' "$content" >"$repo/$file"
  set +e
  out=$(sh "$script" "$repo${ROOT_SUFFIX:-}" 2>&1)
  code=$?
  set -e
  ok=1
  [ "$code" -eq "$want_code" ] || ok=0
  if [ -n "$want" ]; then printf '%s\n' "$out" | grep -Eq "$want" || ok=0; fi
  if [ "$ok" -eq 0 ]; then
    echo "FAIL $name: exit $code (want $want_code), output: $out"
    failures=$((failures + 1))
  fi
}

check "clean prose" 0 docs/how-to/a.md "Run it with the pinned image."
check "not supported yet" 1 docs/how-to/a.md "Passing it on is Not supported yet." 'docs/how-to/a.md:1: "not supported yet"'
check "not yet supported" 1 README.md "Windows is not yet supported." 'README.md:1: "not supported yet"'
check "in v0.1" 1 docs/reference/a.md "No Windows build in v0.1." '"in v0.1"'
check "in v0.1 mid-sentence" 1 docs/reference/a.md "Fixed in v0.1, kept since." '"in v0.1"'
check "in v0.10 is another release" 0 docs/reference/a.md "Added in v0.10."
check "slice 1.x" 1 docs/how-to/a.md "Unverified (slice 1.7)." '"slice 1.x"'
check "slice-1.x" 1 docs/how-to/a.md "See slice-1.4." '"slice 1.x"'
check "a date without a version" 1 docs/security-posture.md "This page describes main as of 2026-11-14." 'without a version'
check "a date with a version" 0 docs/security-posture.md "This page describes main as of 2026-11-14: the v0.2 line."
check "byward:latest" 1 docs/how-to/a.md "docker pull byward:latest" '"byward:latest"'
check "an ADR keeps its history" 0 docs/adr/0001-x.md "# ADR-0001: broker only in v0.1 (slice 1.2), not supported yet"
check "the archive keeps its history" 0 docs/archive/research.md "As of 2026-11-05, in v0.1."
check "the allow marker" 0 docs/how-to/a.md "Not supported yet. <!-- docs-lint: allow: quoting an error message -->"
check "the docs' image tag" 0 docs/how-to/a.md "docker run ghcr.io/byward-dev/byward:v1.2.3"
check "another image tag" 1 docs/how-to/a.md "docker run ghcr.io/byward-dev/byward:v1.2.2" 'image tag v1.2.2, want v1.2.3'
check "the second tag on a line" 1 docs/how-to/a.md "ghcr.io/byward-dev/byward:v1.2.3 and ghcr.io/byward-dev/byward:v0.9.0" 'image tag v0.9.0'
check "the placeholder" 0 docs/reference/a.md "Tags: ghcr.io/byward-dev/byward:vX.Y.Z"
check "a local snapshot" 0 docs/reference/a.md "Loaded as ghcr.io/byward-dev/byward:snapshot-amd64"
check "a version placeholder in angle brackets" 0 docs/how-to/a.md "COPY --from=ghcr.io/byward-dev/byward:<version> /usr/local/bin/byward"
check "an ADR's image tag" 1 docs/adr/0019-x.md "FROM ghcr.io/byward-dev/byward:v0.1.0" 'image tag v0.1.0'
check "an archived image tag" 0 docs/archive/old.md "FROM ghcr.io/byward-dev/byward:v0.1.0"
check "a worktree is not read" 0 .claude/worktrees/x/a.md "Not supported yet."
for dir in .git build dist node_modules testdata; do
  check "$dir is not read" 0 "$dir/x/a.md" "Not supported yet."
done
check "only Markdown is read" 0 docs/a.txt "Not supported yet."
check "in v0.1 at the line's end" 1 docs/a.md "Shipped in v0.1" '"in v0.1"'
check "the docs' tag mid-line" 0 docs/a.md "Run ghcr.io/byward-dev/byward:v1.2.3 now."
check "in v0x1 is no release" 0 docs/a.md "in v0x1"
check "slice 12 is no slice label" 0 docs/a.md "slice 12 of the cake"
check "as of now has no date" 0 docs/a.md "as of now"
check "a date with only a major version" 1 docs/a.md "as of 2026-11-14 (v2)" 'without a version'
check "a tag ending in snapshot" 1 docs/a.md "ghcr.io/byward-dev/byward:v1-snapshot" 'image tag v1-snapshot'
check "docs/agents is not an ADR" 1 docs/agents/x.md "Not supported yet." '"not supported yet"'
# A VAR=value prefix on a function call may outlive the call in sh, so these set and unset it.
TAGFILE='  v1.2.3  \r\n'
check "a tag file with spaces and CRLF" 0 docs/a.md "ghcr.io/byward-dev/byward:v1.2.3"
TAGFILE='# only a comment\n'
check "a tag file with no tag" 2 docs/a.md "x" 'holds no tag'
unset TAGFILE
ROOT_SUFFIX=/
check "a root with a trailing slash" 0 docs/adr/0001-x.md "in v0.1"
unset ROOT_SUFFIX

repo="$tmp/repo"
rm -rf "$repo" && mkdir -p "$repo/docs"
set +e
out=$(sh "$script" "$repo" 2>&1)
code=$?
set -e
if [ "$code" -ne 2 ] || ! printf '%s\n' "$out" | grep -q 'docs-image-tag is missing'; then
  echo "FAIL missing tag file: exit $code (want 2), output: $out"
  failures=$((failures + 1))
fi

if [ "$failures" -ne 0 ]; then
  echo "docs-lint_test: $failures failure(s)"
  exit 1
fi
echo "docs-lint_test: ok"
