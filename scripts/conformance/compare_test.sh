#!/bin/sh
# Table test for compare.sh on fixture results (no Docker, no network). Each case builds a results
# directory as inside.sh leaves it, runs compare.sh, and checks its exit code and message.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
failures=0
rev=2026-07-28

# scenario <run> <name> <json> [revision]: one scenario's checks.json, in a timestamped directory as the CLI writes.
scenario() {
  d="$out/$1/${4:-$rev}/server-$2-2026-11-06T13-33-42-866Z"
  mkdir -p "$d"
  printf '%s' "$3" > "$d/checks.json"
}
ok='[{"id":"c1","status":"SUCCESS"},{"id":"c2","status":"WARNING"}]'

# setup <case> [revisions]: a passing pair of runs per revision for two scenarios (one named like a
# date), expected lists included.
setup() {
  out="$tmp/$1/results"
  expect="$tmp/$1/expect"
  revs=${2:-$rev}
  mkdir -p "$out" "$expect"
  for r in $revs; do
    printf '# comment\njson-schema-2020-12\ntools-call\n' > "$expect/scenarios-$r.txt"
    for run in direct proxy; do
      scenario "$run" tools-call "$ok" "$r"
      scenario "$run" json-schema-2020-12 "$ok" "$r"
      echo 0 > "$out/$run-$r.exit"
      echo "cli output" > "$out/$run-$r.txt"
    done
  done
}

# expect_in reports a failure unless text (a file, or "-" for compare.sh's last output) contains pattern.
expect_in() { # $1 case name, $2 file or -, $3 grep pattern, $4 what was expected
  if [ "$2" = - ]; then printf '%s\n' "$got"; else cat "$2" 2>/dev/null; fi | grep -q -- "$3" \
    || { echo "FAIL $1: $4"; failures=$((failures + 1)); }
}

check() { # $1 case name, $2 want exit, $3 want output (grep -E), $4 want "same" (yes/no/-)
  set +e
  # shellcheck disable=SC2086 # revs is a word list
  got=$(sh "$here/compare.sh" "$out" "$expect" $revs 2>&1)
  code=$?
  set -e
  if [ "$code" -ne "$2" ] || ! printf '%s\n' "$got" | grep -Eq "$3"; then
    echo "FAIL $1: exit $code (want $2), output: $got"
    failures=$((failures + 1))
  fi
  if [ "$4" != - ] && [ "$(cat "$out/same-$rev" 2>/dev/null)" != "$4" ]; then
    echo "FAIL $1: same-$rev = $(cat "$out/same-$rev" 2>/dev/null), want $4"
    failures=$((failures + 1))
  fi
}

setup identical
check identical 0 '^$' yes
expect_in identical "$out/summary.md" 'All gates passed' "the passed line in a green summary"
expect_in identical "$out/summary.md" '| 2026-07-28 | 2 | 4 | 0 / 2 | 0 / 2 | yes |' "the summary row for two scenarios and four checks"

setup proxy-differs
scenario proxy tools-call '[{"id":"c1","status":"FAILURE"},{"id":"c2","status":"WARNING"}]'
check proxy-differs 1 'differ from direct.*' no

setup dropped-from-both
rm -rf "$tmp/dropped-from-both/results"/*/"$rev"/server-tools-call-*
check dropped-from-both 1 'different set of scenarios' yes
expect_in dropped-from-both "$out/summary.md" 'FAILED' "a FAILED section in the summary of a red run"
expect_in dropped-from-both "$out/summary.md" 'different set of scenarios' "the failure listed in the summary"

setup extra-in-both
for run in direct proxy; do scenario "$run" brand-new "$ok"; done
check extra-in-both 1 'different set of scenarios' yes

# The scenario lists are C-sorted; compare.sh must sort bytewise whatever the caller's locale
# ("Zeta" sorts first bytewise, last under a case-insensitive locale).
setup locale-independent
printf '# comment\nZeta\njson-schema-2020-12\ntools-call\n' > "$expect/scenarios-$rev.txt"
for run in direct proxy; do scenario "$run" Zeta "$ok"; done
set +e
got=$(LC_ALL=en_US.UTF-8 sh "$here/compare.sh" "$out" "$expect" "$rev" 2>&1)
code=$?
set -e
[ "$code" -eq 0 ] || { echo "FAIL locale-independent: exit $code under LC_ALL=en_US.UTF-8: $got"; failures=$((failures + 1)); }

setup missing-on-proxy
rm -rf "$tmp/missing-on-proxy/results/proxy/$rev"/server-tools-call-*
check missing-on-proxy 1 'differ from direct' no

setup unreadable
printf '{broken' > "$(ls -d "$tmp/unreadable/results/proxy/$rev"/server-tools-call-*)/checks.json"
check unreadable 1 'cannot read .*checks.json' -
expect_in unreadable "$out/summary.md" '| 2026-07-28 |' "a summary even when a checks.json is unreadable"

setup direct-failed
echo 1 > "$out/direct-$rev.exit"
echo "Unexpected failures: tools-call" > "$out/direct-$rev.txt"
check direct-failed 1 'direct run exited 1.*' yes
expect_in direct-failed - 'Unexpected failures: tools-call' "the direct CLI output tail"

setup direct-timed-out
echo 124 > "$out/direct-$rev.exit"
check direct-timed-out 1 'direct run timed out' yes

setup proxy-crashed
rm -rf "$tmp/proxy-crashed/results/proxy/$rev"/server-tools-call-*
echo 124 > "$out/proxy-$rev.exit"
echo "Running client scenario tools-call" > "$out/proxy-$rev.txt"
check proxy-crashed 1 'the proxy run timed out' no
expect_in proxy-crashed - 'Running client scenario tools-call' "the proxy CLI output tail"

setup proxy-differs-not-gated
scenario proxy tools-call '[{"id":"c1","status":"FAILURE"},{"id":"c2","status":"WARNING"}]'
echo 1 > "$out/proxy-$rev.exit"
check proxy-differs-not-gated 1 'exit code is not gated' no

setup comments-only
printf '# only comments\n' > "$expect/scenarios-$rev.txt"
check comments-only 1 'different set of scenarios' yes
expect_in comments-only "$out/summary.md" '| 2026-07-28 |' "a summary even with a comment-only scenario list"

# Two revisions: a failure in one must not hide or clobber the other.
setup two-revisions-one-differs "2025-11-25 2026-07-28"
scenario proxy tools-call '[{"id":"c1","status":"FAILURE"}]' 2026-07-28
check two-revisions-one-differs 1 '2026-07-28 results through the proxy differ' -
[ "$(cat "$out/same-2025-11-25")" = yes ] && [ "$(cat "$out/same-2026-07-28")" = no ] \
  || { echo "FAIL two-revisions-one-differs: same = $(cat "$out/same-2025-11-25")/$(cat "$out/same-2026-07-28"), want yes/no"; failures=$((failures + 1)); }
expect_in two-revisions-one-differs "$out/summary.md" '| 2025-11-25 | 2 | 4 | 0 / 2 | 0 / 2 | yes |' "the clean revision's row"
expect_in two-revisions-one-differs "$out/summary.md" '| 2026-07-28 |.*| no |' "the differing revision's row"

setup two-revisions-one-died "2025-11-25 2026-07-28"
echo "reference server down after the proxy run" > "$out/died-2025-11-25"
check two-revisions-one-died 1 'exited during 2025-11-25' -
if printf '%s\n' "$got" | grep -q 'during 2026-07-28'; then echo "FAIL two-revisions-one-died: the clean revision was blamed"; failures=$((failures + 1)); fi

setup direct-no-exit-file
rm -f "$out/direct-$rev.exit"
check direct-no-exit-file 1 'left no exit file' yes

setup server-died
echo "process 12 exited during $rev" > "$out/died-$rev"
check server-died 1 'exited during 2026-07-28' yes

setup no-checks
for run in direct proxy; do rm -rf "$out/$run/$rev"/server-*; scenario "$run" tools-call '[]'; done
check no-checks 1 'produced no checks' -

[ "$failures" -eq 0 ] || { echo "compare_test: $failures case(s) failed" >&2; exit 1; }
echo "compare_test: ok"
