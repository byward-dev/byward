#!/bin/sh
# Table test for posture-tests-check.sh against fixture repositories (no network).
set -eu
# A developer's CDPATH makes cd print the directory, which $(cd ... && pwd) would capture.
unset CDPATH
here="$(cd "$(dirname "$0")" && pwd)"
script="$here/posture-tests-check.sh"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
failures=0

# The posture page's head and the invariants table's header, as the real page has them.
header='| # | Invariant | Enforced in | Tested by |
|---|---|---|---|'
head="# Security posture

## Security invariants

$header"
# row_citing NAME...: invariant 1's row, whose "Tested by" cell cites each NAME in backticks, as the
# real page does. row cites TestTheTokenIsChecked, a test that $defines defines.
row_citing() {
  cell=
  for n in "$@"; do cell="${cell:+$cell, }\`$n\`"; done
  printf "| 1 | A token is checked. | \`x.go\` | %s |" "$cell"
}
row=$(row_citing TestTheTokenIsChecked)

# check NAME WANT_EXIT POSTURE GOFILE GOCONTENT [WANT_OUTPUT]: a fresh repository whose
# docs/security-posture.md holds POSTURE and whose GOFILE holds GOCONTENT; the check must exit
# WANT_EXIT, and its output match WANT_OUTPUT (grep -E) when given. An empty POSTURE writes no page.
check() {
  name=$1 want_code=$2 posture=$3 gofile=$4 gocontent=$5 want=${6:-}
  repo="$tmp/repo"
  rm -rf "$repo"
  mkdir -p "$repo/docs" "$repo/$(dirname "$gofile")"
  if [ -n "$posture" ]; then printf '%s\n' "$posture" >"$repo/docs/security-posture.md"; fi
  printf '%s\n' "$gocontent" >"$repo/$gofile"
  set +e
  out=$(sh "$script" "$repo" 2>&1)
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

defines='package x

func TestTheTokenIsChecked(t *testing.T) {}
func FuzzTheParser(f *testing.F) {}'

check "every named test exists" 0 "$head
$(row_citing TestTheTokenIsChecked FuzzTheParser)" internal/x/x_test.go "$defines"
check "a test that does not exist" 1 "$head
$row
| 15 | Nothing leaks. | \`y.go\` | \`TestNothingLeaks\` |" internal/x/x_test.go "$defines" \
  '^docs/security-posture.md:8: invariant 15 names TestNothingLeaks, which no _test.go defines$'
# Every missing name is reported, not only the first or the last: one case pins each of two.
for gone in TestGoneA TestGoneB; do
  check "every missing name is reported: $gone" 1 "$head
$(row_citing TestGoneA TestGoneB)" internal/x/x_test.go "$defines" "names $gone,"
done
check "a fuzz test that does not exist" 1 "$head
| 3 | Input is parsed. | \`x.go\` | \`FuzzTheLexer\` |" internal/x/x_test.go "$defines" 'invariant 3 names FuzzTheLexer'
# What follows Test or Fuzz may start with an upper-case letter, a digit or an underscore, as in Go,
# and hold digits later; a name of one letter after the prefix counts too.
for t in TestA Test_the_token Test2FA9 Fuzz_the_parser Fuzz2x9; do
  check "a cited $t that exists" 0 "$head
$(row_citing "$t")" internal/x/x_test.go "$defines
func $t(t *testing.T) {}"
  check "a cited ${t}Gone that does not exist" 1 "$head
$(row_citing "${t}Gone")" internal/x/x_test.go "$defines" "names ${t}Gone,"
done
check "a subtest names its test" 0 "$head
$(row_citing TestTheTokenIsChecked/an_expired_one)" internal/x/x_test.go "$defines"
check "a later name in a list that does not exist" 1 "$head
$(row_citing TestTheTokenIsChecked FuzzTheParser TestGone)" internal/x/x_test.go "$defines" 'invariant 1 names TestGone'
check "a commented-out test is no test" 1 "$head
$(row_citing TestGone)" internal/x/x_test.go "$defines
// func TestGone(t *testing.T) {}" 'names TestGone'
check "a name in another cell counts too" 1 "$head
| 1 | A token is checked, see \`TestGone\`. | \`x.go\` | \`TestTheTokenIsChecked\` |" internal/x/x_test.go "$defines" 'invariant 1 names TestGone'
check "a test whose name only starts like the cited one" 1 "$head
$(row_citing TestTheToken)" internal/x/x_test.go "$defines" 'names TestTheToken,'
check "a method is no test" 1 "$head
$(row_citing TestOnAType)" internal/x/x_test.go 'package x

func (s suite) TestOnAType(t *testing.T) {}' 'names TestOnAType'
check "a test in a non-test file is no test" 1 "$head
$row" internal/x/x.go "$defines" 'names TestTheTokenIsChecked'
for dir in .git .claude/worktrees node_modules internal/x/testdata; do
  check "$dir's tests do not count" 1 "$head
$row" "$dir/a/x_test.go" "$defines" 'names TestTheTokenIsChecked'
done
check "Tested, Testing, Fuzzy, a lower-case testGone and other kinds of func are no test names" 0 "$head
| 1 | Tested by hand; Testing helps; Fuzzy edges; testGone, BenchmarkGone and ExampleGone are not cited tests. | \`x.go\` | \`TestTheTokenIsChecked\` |" internal/x/x_test.go "$defines"
check "another section's table is not checked" 0 "$head
$row

## Threats

| 1 | A threat. | \`TestGone\` |" internal/x/x_test.go "$defines"
check "a table before the section is not checked" 0 "# Security posture

## Threats

| 1 | A threat. | \`TestGone\` |

## Security invariants

$header
$row" internal/x/x_test.go "$defines"
check "a page with CRLF line endings" 0 "$(printf '%s\n' "$head" "$row" | sed 's/$/\r/')" internal/x/x_test.go "$defines"
check "a name holding Test later is one name" 0 "$head
$(row_citing TestTheEndOfTheTestReleasesIt)" internal/x/x_test.go "$defines
func TestTheEndOfTheTestReleasesIt(t *testing.T) {}"
check "a subheading does not end the section" 1 "$head

### More

$(row_citing TestGone)" internal/x/x_test.go "$defines" 'names TestGone'
check "a padded number cell is a row" 1 "$head
|  1  | A token is checked. | \`x.go\` | \`TestGone\` |" internal/x/x_test.go "$defines" 'names TestGone'
check "a section with no rows" 2 "$head" internal/x/x_test.go "$defines" 'no invariant rows'
check "a section whose rows name no test" 2 "$head
| 1 | A token is checked. | \`x.go\` | by hand |" internal/x/x_test.go "$defines" 'name no test'
check "no posture page" 2 "" internal/x/x_test.go "$defines" 'security-posture.md is missing'
check "a heading that only starts like the section" 2 "# Security posture

## Security invariants, retired

$(row_citing TestGone)" internal/x/x_test.go "$defines" 'no invariant rows'

if [ "$failures" -ne 0 ]; then
  echo "posture-tests-check_test: $failures failed"
  exit 1
fi
echo "posture-tests-check_test: ok"
