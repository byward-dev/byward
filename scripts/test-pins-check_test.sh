#!/bin/sh
# Table test for test-pins-check.sh against fixture registry responses (no network).
set -eu
script="$(cd "$(dirname "$0")" && pwd)/test-pins-check.sh"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
failures=0
now=1793404800 # 2026-11-01T00:00:00Z; the cooldown cut-off is 2026-10-18

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

# case | image | @playwright/test | node pin | playwright JSON | axe JSON | node JSON | want exit | want output (grep -E)
run() {
  mkdir -p "$tmp/scripts/ui" "$tmp/scripts/conformance"
  printf 'image=mcr.microsoft.com/playwright:v%s-noble@sha256:00\n' "$2" > "$tmp/scripts/ui/run.sh"
  printf '{"devDependencies":{"@axe-core/playwright":"4.14.0","@playwright/test":"%s"}}\n' "$3" > "$tmp/scripts/ui/package.json"
  printf 'image=node:%s-slim@sha256:00\n' "$4" > "$tmp/scripts/conformance/run.sh"
  printf '%s' "$5" > "$tmp/pw.json"
  printf '%s' "$6" > "$tmp/axe.json"
  printf '%s' "$7" > "$tmp/node.json"
  set +e
  out=$(cd "$tmp" && NOW=$now PLAYWRIGHT_JSON="$tmp/pw.json" AXE_JSON="$tmp/axe.json" NODE_JSON="$tmp/node.json" sh "$script" 2>&1)
  code=$?
  set -e
  if [ "$code" -ne "$8" ] || ! printf '%s\n' "$out" | grep -Eq "$9"; then
    echo "FAIL $1: exit $code (want $8), output: $out"
    failures=$((failures + 1))
  fi
}

pw_cur=$(npm 1.64.1 2026-10-14T11:58:13.696Z)
axe_cur=$(npm 4.14.0 2026-10-15T13:33:17.706Z)
node_cur=$(node 24.22.1 2026-10-14)
run current            1.64.1 1.64.1 24.22.1 "$pw_cur" "$axe_cur" "$node_cur" 0 'ok'
run newer-in-cooldown  1.64.1 1.64.1 24.22.1 "$(npm 1.64.1 2026-10-14T11:58:13.696Z 1.65.0 2026-10-25T00:00:00.000Z)" "$axe_cur" "$node_cur" 0 'ok'
run newer-playwright   1.64.1 1.64.1 24.22.1 "$(npm 1.64.1 2026-10-01T00:00:00.000Z 1.65.0 2026-10-10T00:00:00.000Z)" "$axe_cur" "$node_cur" 1 'NEWER: Playwright 1\.65\.0'
run prerelease-ignored 1.64.1 1.64.1 24.22.1 "$(npm 1.64.1 2026-10-01T00:00:00.000Z 1.65.0-beta-1 2026-10-02T00:00:00.000Z)" "$axe_cur" "$node_cur" 0 'ok'
run two-digit-sort     1.9.0  1.9.0  24.22.1 "$(npm 1.9.0 2026-01-01T00:00:00.000Z 1.10.0 2026-02-01T00:00:00.000Z)" "$axe_cur" "$node_cur" 1 'NEWER: Playwright 1\.10\.0'
run newer-axe          1.64.1 1.64.1 24.22.1 "$pw_cur" "$(npm 4.14.0 2026-09-01T00:00:00.000Z 4.14.1 2026-10-01T00:00:00.000Z)" "$node_cur" 1 'NEWER: @axe-core/playwright 4\.14\.1'
run newer-node         1.64.1 1.64.1 24.22.1 "$pw_cur" "$axe_cur" "$(node 24.22.2 2026-10-15 24.22.1 2026-10-01)" 1 'NEWER: Node 24 24\.22\.2'
run node-other-major   1.64.1 1.64.1 24.22.1 "$pw_cur" "$axe_cur" "$(node 26.1.0 2026-09-01 24.22.1 2026-10-01)" 0 'ok'
run node-in-cooldown   1.64.1 1.64.1 24.22.1 "$pw_cur" "$axe_cur" "$(node 24.22.2 2026-10-27 24.22.1 2026-10-01)" 0 'ok'
run mismatch           1.64.1 1.64.0 24.22.1 "$pw_cur" "$axe_cur" "$node_cur" 1 'MISMATCH: .*v1\.64\.1.*1\.64\.0'
run not-exact          1.64   1.64   24.22.1 "$pw_cur" "$axe_cur" "$node_cur" 1 'exact x\.y\.z'
run empty-registry     1.64.1 1.64.1 24.22.1 '{"time":{}}' "$axe_cur" "$node_cur" 1 'no Playwright release'
run not-json           1.64.1 1.64.1 24.22.1 '<html>' "$axe_cur" "$node_cur" 1 'no Playwright release'
run node-not-json      1.64.1 1.64.1 24.22.1 "$pw_cur" "$axe_cur" '<html>' 1 'no Node 24 release'

[ "$failures" -eq 0 ] || { echo "test-pins-check_test: $failures case(s) failed" >&2; exit 1; }
echo "test-pins-check_test: ok"
