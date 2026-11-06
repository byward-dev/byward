#!/bin/sh
# Table test for test-pins-check.sh against fixture registry responses (no network).
set -eu
here="$(cd "$(dirname "$0")" && pwd)"
script="$here/test-pins-check.sh"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
failures=0
now=1793491200 # 2026-11-01T00:00:00Z; the 14-day cut-off is 2026-10-18T00:00:00Z, inclusive

# npm "time" document: alternating version/date arguments.
npm() {
  printf '{"time":{"created":"2020-01-01T00:00:00.000Z"'
  while [ $# -gt 1 ]; do printf ',"%s":"%s"' "$1" "$2"; shift 2; done
  printf '}}'
}
node() {
  printf '['
  sep=""
  while [ $# -gt 1 ]; do printf '%s{"version":"v%s","date":"%s"}' "$sep" "$1" "$2"; sep=","; shift 2; done
  printf ']'
}

# check NAME WANT_EXIT WANT_OUTPUT...: runs the script in $tmp/repo with the fixtures in $tmp; every
# WANT_OUTPUT (grep -E) must match.
check() {
  name=$1 want_code=$2
  shift 2
  set +e
  out=$(cd "$tmp/repo" && NOW=$now PLAYWRIGHT_JSON="$tmp/pw.json" AXE_JSON="$tmp/axe.json" NODE_JSON="$tmp/node.json" sh "$script" 2>&1)
  code=$?
  set -e
  ok=1
  [ "$code" -eq "$want_code" ] || ok=0
  for want; do printf '%s\n' "$out" | grep -Eq "$want" || ok=0; done
  if [ "$ok" -eq 0 ]; then
    echo "FAIL $name: exit $code (want $want_code), output: $out"
    failures=$((failures + 1))
  fi
}

# run NAME IMAGE PLAYWRIGHT AXE NODE PW_JSON AXE_JSON NODE_JSON WANT_EXIT WANT_OUTPUT...
run() {
  rm -rf "$tmp/repo"
  mkdir -p "$tmp/repo/scripts/ui" "$tmp/repo/scripts/conformance"
  printf 'image=mcr.microsoft.com/playwright:v%s-noble@sha256:00\n' "$2" > "$tmp/repo/scripts/ui/run.sh"
  printf '{"devDependencies":{"@axe-core/playwright":"%s","@playwright/test":"%s"}}\n' "$4" "$3" > "$tmp/repo/scripts/ui/package.json"
  printf 'image=node:%s-slim@sha256:00\n' "$5" > "$tmp/repo/scripts/conformance/run.sh"
  printf '%s' "$6" > "$tmp/pw.json"
  printf '%s' "$7" > "$tmp/axe.json"
  printf '%s' "$8" > "$tmp/node.json"
  name=$1 want_code=$9
  shift 9
  check "$name" "$want_code" "$@"
}

pw=$(npm 1.64.1 2026-10-14T11:58:13.696Z)
axe=$(npm 4.14.0 2026-10-15T13:33:17.706Z)
nd=$(node 24.22.1 2026-10-14)
p="1.64.1 1.64.1 4.14.0 24.22.1" # the current pins: image, @playwright/test, @axe-core/playwright, node

# shellcheck disable=SC2086 # $p is a word list
{
run current-pins-pass             $p "$pw" "$axe" "$nd" 0 'ok'
run playwright-in-cooldown        $p "$(npm 1.64.1 2026-10-14T11:58:13.696Z 1.65.0 2026-10-25T00:00:00.000Z)" "$axe" "$nd" 0 'ok'
run playwright-past-cooldown      $p "$(npm 1.64.1 2026-10-01T00:00:00.000Z 1.65.0 2026-10-10T00:00:00.000Z)" "$axe" "$nd" 1 'NEWER: Playwright 1\.65\.0'
run cutoff-is-inclusive           $p "$(npm 1.64.1 2026-10-01T00:00:00.000Z 1.65.0 2026-10-18T00:00:00.000Z)" "$axe" "$nd" 1 'NEWER: Playwright 1\.65\.0'
run release-after-cutoff-ignored  $p "$(npm 1.64.1 2026-10-01T00:00:00.000Z 1.65.0 2026-10-18T00:00:01.000Z)" "$axe" "$nd" 0 'ok'
run prerelease-ignored            $p "$(npm 1.64.1 2026-10-01T00:00:00.000Z 1.65.0-beta-1 2026-10-02T00:00:00.000Z)" "$axe" "$nd" 0 'ok'
run newer-axe                     $p "$pw" "$(npm 4.14.0 2026-09-01T00:00:00.000Z 4.14.1 2026-10-01T00:00:00.000Z)" "$nd" 1 'NEWER: @axe-core/playwright 4\.14\.1'
run newer-node                    $p "$pw" "$axe" "$(node 24.22.2 2026-10-15 24.22.1 2026-10-01)" 1 'NEWER: Node 24 24\.22\.2'
run node-in-cooldown              $p "$pw" "$axe" "$(node 24.22.2 2026-10-27 24.22.1 2026-10-01)" 0 'ok'
run node-other-major-ignored      $p "$pw" "$axe" "$(node 26.1.0 2026-09-01 24.22.1 2026-10-01)" 0 'ok'
run playwright-registry-empty     $p '{"time":{}}' "$axe" "$nd" 1 'no Playwright release'
run playwright-registry-not-json  $p '<html>' "$axe" "$nd" 1 'no Playwright release'
run axe-registry-not-json         $p "$pw" '<html>' "$nd" 1 'no @axe-core/playwright release'
run node-registry-empty           $p "$pw" "$axe" '[]' 1 'no Node 24 release'
run node-registry-not-json        $p "$pw" "$axe" '<html>' 1 'no Node 24 release'
}
run playwright-1.10-newer-than-1.9 1.9.0 1.9.0 4.14.0 24.22.1 "$(npm 1.9.0 2026-01-01T00:00:00.000Z 1.10.0 2026-02-01T00:00:00.000Z)" "$axe" "$nd" 1 'NEWER: Playwright 1\.10\.0'
# A pin bumped during the cooldown is ahead of the newest release past it: not stale.
run playwright-pinned-ahead 1.65.0 1.65.0 4.14.0 24.22.1 "$(npm 1.64.1 2026-10-01T00:00:00.000Z 1.65.0 2026-10-25T00:00:00.000Z)" "$axe" "$nd" 0 'ok'
run node-pinned-ahead       1.64.1 1.64.1 4.14.0 24.22.2 "$pw" "$axe" "$(node 24.22.2 2026-10-27 24.22.1 2026-10-01)" 0 'ok'
# MISMATCH alone fails the check: nothing is newer than the pinned @playwright/test.
run image-differs-from-playwright-test 1.64.1 1.64.0 4.14.0 24.22.1 "$(npm 1.64.0 2026-10-01T00:00:00.000Z)" "$axe" "$nd" 1 'MISMATCH: .*v1\.64\.1.*1\.64\.0'
# One run reports every problem.
run reports-every-problem 1.64.1 1.64.0 4.14.0 24.22.1 "$(npm 1.64.0 2026-09-01T00:00:00.000Z 1.64.1 2026-09-02T00:00:00.000Z)" "$axe" "$(node 24.22.2 2026-10-01 24.22.1 2026-09-01)" 1 \
  'MISMATCH: .*v1\.64\.1.*1\.64\.0' 'NEWER: Playwright 1\.64\.1' 'NEWER: Node 24 24\.22\.2'
# Each pin must be an exact x.y.z.
run image-not-exact      1.64   1.64.1 4.14.0  24.22.1 "$pw" "$axe" "$nd" 1 'image must be pinned to an exact'
run playwright-not-exact 1.64.1 1.64   4.14.0  24.22.1 "$pw" "$axe" "$nd" 1 '@playwright/test must be pinned to an exact'
run axe-not-exact        1.64.1 1.64.1 ^4.14.0 24.22.1 "$pw" "$axe" "$nd" 1 '@axe-core/playwright must be pinned to an exact'
run node-not-exact       1.64.1 1.64.1 4.14.0  24      "$pw" "$axe" "$nd" 1 'node must be pinned to an exact'
run four-part-version    1.64.1.1 1.64.1 4.14.0 24.22.1 "$pw" "$axe" "$nd" 1 'image must be pinned to an exact'
run leading-dot-version  .64.1  1.64.1 4.14.0 24.22.1 "$pw" "$axe" "$nd" 1 'image must be pinned to an exact'
run trailing-dot-version 1.64.  1.64.1 4.14.0 24.22.1 "$pw" "$axe" "$nd" 1 'image must be pinned to an exact'
run empty-part-version   1..64  1.64.1 4.14.0 24.22.1 "$pw" "$axe" "$nd" 1 'image must be pinned to an exact'
# Two image lines are not one pin (current pins otherwise).
# shellcheck disable=SC2086
run setup $p "$pw" "$axe" "$nd" 0 'ok'
printf 'image=mcr.microsoft.com/playwright:v1.64.1-noble@sha256:00\nimage=mcr.microsoft.com/playwright:v1.64.1-noble@sha256:00\n' > "$tmp/repo/scripts/ui/run.sh"
check two-image-lines 1 'image must be pinned to an exact'
# Outside the repository root the check says so.
# shellcheck disable=SC2086
run setup $p "$pw" "$axe" "$nd" 0 'ok'
rm "$tmp/repo/scripts/conformance/run.sh"
check missing-pin-file 1 'scripts/conformance/run\.sh not found'

# The repository's own pin files parse, and agree: registries that list nothing newer than the pins.
root="$(cd "$here/.." && pwd)"
rm -rf "$tmp/repo" && mkdir -p "$tmp/repo/scripts/ui" "$tmp/repo/scripts/conformance"
cp "$root/scripts/ui/run.sh" "$root/scripts/ui/package.json" "$tmp/repo/scripts/ui/"
cp "$root/scripts/conformance/run.sh" "$tmp/repo/scripts/conformance/"
real_pw=$(jq -r '.devDependencies["@playwright/test"]' "$root/scripts/ui/package.json")
real_axe=$(jq -r '.devDependencies["@axe-core/playwright"]' "$root/scripts/ui/package.json")
real_node=$(sed -n 's/^image=node:\([0-9.]*\)-slim@.*$/\1/p' "$root/scripts/conformance/run.sh")
npm "$real_pw" 2026-01-01T00:00:00.000Z > "$tmp/pw.json"
npm "$real_axe" 2026-01-01T00:00:00.000Z > "$tmp/axe.json"
node "$real_node" 2026-01-01 > "$tmp/node.json"
check repository-pins 0 'ok'

[ "$failures" -eq 0 ] || { echo "test-pins-check_test: $failures case(s) failed" >&2; exit 1; }
echo "test-pins-check_test: ok"
