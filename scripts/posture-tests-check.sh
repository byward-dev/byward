#!/bin/sh
# Fails when the security posture's invariants table (docs/security-posture.md, "## Security
# invariants") names a test that no _test.go in the repository defines: every Test… or Fuzz… name
# (as Go names them: what follows Test or Fuzz does not start with a lower-case letter)
# in a row must be a `func` of that name, so a renamed test cannot leave its invariant pointing at
# nothing (#508). Also fails when the section has no rows or its rows name no test, so a reformatted
# table cannot pass by checking nothing. Tests under testdata/ (which go test never builds), .claude
# worktrees and node_modules do not count. Part of `mise run check` (lint:docs).
# Exit 1: a cited test does not exist. Exit 2: the page, the section's rows or their test names are
# missing.
# Usage: sh scripts/posture-tests-check.sh [repository root]
set -eu
root=${1:-.}
posture="$root/docs/security-posture.md"
[ -f "$posture" ] || { echo "posture-tests-check: $posture is missing" >&2; exit 2; }

# "LINE INVARIANT NAME" for each test name in a row of the section.
cited=$(awk '
  { sub(/\r$/, "") } # a page checked out with CRLF line endings reads as with LF
  /^## / { in_section = ($0 == "## Security invariants"); next }
  in_section && /^\| *[0-9]+ *\|/ {
    rows++
    n = $0; sub(/^\| */, "", n); sub(/ *\|.*/, "", n)
    rest = $0
    while (match(rest, /(Test|Fuzz)[A-Z0-9_][A-Za-z0-9_]*/)) {
      print NR, n, substr(rest, RSTART, RLENGTH)
      rest = substr(rest, RSTART + RLENGTH)
    }
  }
  END { if (rows == 0) print "NOROWS" }' "$posture")
case $cited in
  NOROWS) echo "posture-tests-check: no invariant rows under \"## Security invariants\" in $posture" >&2; exit 2 ;;
  '') echo "posture-tests-check: the invariant rows in $posture name no test" >&2; exit 2 ;;
esac

defined=$(find "$root" \( -name .git -o -name .claude -o -name node_modules -o -name testdata \) -prune -o -name '*_test.go' -type f \
  -exec grep -hoE '^func (Test|Fuzz)[A-Za-z0-9_]+\(' {} + | sed 's/^func //; s/($//' | sort -u)

missing=$(printf '%s\n' "$cited" | while read -r line inv name; do
  printf '%s\n' "$defined" | grep -qx "$name" || echo "docs/security-posture.md:$line: invariant $inv names $name, which no _test.go defines"
done)
if [ -n "$missing" ]; then
  printf '%s\n' "$missing"
  echo "posture-tests-check: cite a test that exists: a func Test… or Fuzz… in a _test.go" >&2
  exit 1
fi
