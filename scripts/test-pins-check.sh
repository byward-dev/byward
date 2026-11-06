#!/bin/sh
# Fails when a test-lane pin that Dependabot cannot see has a newer release out for at least the
# Dependabot cooldown (14 days): the Playwright image in scripts/ui/run.sh with @playwright/test and
# @axe-core/playwright in scripts/ui/package.json, and the Node image in scripts/conformance/run.sh.
# Dependabot cannot bump them together (the image's browsers must match @playwright/test), so
# .github/workflows/go-version.yml runs this weekly. Also fails when the image and @playwright/test
# disagree.
# PLAYWRIGHT_JSON, AXE_JSON and NODE_JSON may name local copies of
# https://registry.npmjs.org/@playwright/test, https://registry.npmjs.org/@axe-core/playwright and
# https://nodejs.org/dist/index.json; NOW (epoch seconds) fixes the clock
# (scripts/test-pins-check_test.sh uses them).
set -eu

cooldown_days=14
now=${NOW:-$(date -u +%s)}
cutoff=$((now - cooldown_days * 86400))
fail() { echo "test pins check: FAIL: $*" >&2; exit 1; }

for f in scripts/ui/run.sh scripts/ui/package.json scripts/conformance/run.sh; do
  [ -f "$f" ] || fail "$f not found; run from the repository root"
done
image=$(sed -n 's/^image=mcr\.microsoft\.com\/playwright:v\([0-9.]*\)-noble@.*$/\1/p' scripts/ui/run.sh)
node=$(sed -n 's/^image=node:\([0-9.]*\)-slim@.*$/\1/p' scripts/conformance/run.sh)
pw=$(jq -r '.devDependencies["@playwright/test"] // empty' scripts/ui/package.json)
axe=$(jq -r '.devDependencies["@axe-core/playwright"] // empty' scripts/ui/package.json)
exact() { # one x.y.z of digits, nothing else (not even a second line)
  case $1 in
    *[!0-9.]* | .* | *. | *..* | '') return 1 ;;
    *.*.*.*) return 1 ;;
    *.*.*) return 0 ;;
    *) return 1 ;;
  esac
}
for v in "image:$image" "node:$node" "@playwright/test:$pw" "@axe-core/playwright:$axe"; do
  exact "${v#*:}" || fail "${v%%:*} must be pinned to an exact x.y.z, found '${v#*:}'"
done

status=0
if [ "$image" != "$pw" ]; then
  echo "test pins check: MISMATCH: the Playwright image is v$image but @playwright/test is $pw; they must move together" >&2
  status=1
fi

fetch() { # $1 env override, $2 URL
  if [ -n "$1" ]; then cat "$1"; else curl -fsSL "$2"; fi
}
# newest_npm JSON: the newest x.y.z released on or before the cutoff, from an npm registry document.
newest_npm() {
  printf '%s' "$1" | jq -r --argjson cutoff "$cutoff" '
    .time | to_entries
    | map(select((.key | test("^[0-9]+\\.[0-9]+\\.[0-9]+$"))
        and ((.value | sub("\\.[0-9]+Z$"; "Z") | fromdateiso8601) <= $cutoff)))
    | map(.key) | sort_by(split(".") | map(tonumber)) | last // empty'
}
# newest_node JSON MAJOR: the newest vMAJOR.y.z released on or before the cutoff.
newest_node() {
  printf '%s' "$1" | jq -r --argjson cutoff "$cutoff" --arg major "$2" '
    map(select((.version | test("^v" + $major + "\\.[0-9]+\\.[0-9]+$"))
        and ((.date + "T00:00:00Z" | fromdateiso8601) <= $cutoff)))
    | map(.version | ltrimstr("v")) | sort_by(split(".") | map(tonumber)) | last // empty'
}
newer() { # $1 newer than $2?
  [ "$1" != "$2" ] && [ "$(printf '%s\n%s\n' "$1" "$2" | sort -t. -k1,1nr -k2,2nr -k3,3nr | head -n1)" = "$1" ]
}
report() { # $1 name, $2 pinned, $3 newest past the cooldown, $4 what to bump
  if [ -z "$3" ]; then
    echo "test pins check: FAIL: no $1 release found in the registry response" >&2
    status=1
  elif newer "$3" "$2"; then
    echo "test pins check: NEWER: $1 $3 is out (pinned $2); bump $4"
    status=1
  fi
}

# An unreadable response yields no release, which is reported as a failure below.
latest=$(newest_npm "$(fetch "${PLAYWRIGHT_JSON:-}" https://registry.npmjs.org/@playwright/test)" 2>/dev/null) || latest=""
report "Playwright" "$pw" "$latest" "the image tag and digest in scripts/ui/run.sh with @playwright/test, then npm install --package-lock-only"
latest=$(newest_npm "$(fetch "${AXE_JSON:-}" https://registry.npmjs.org/@axe-core/playwright)" 2>/dev/null) || latest=""
report "@axe-core/playwright" "$axe" "$latest" "scripts/ui/package.json, then npm install --package-lock-only"
latest=$(newest_node "$(fetch "${NODE_JSON:-}" https://nodejs.org/dist/index.json)" "${node%%.*}" 2>/dev/null) || latest=""
report "Node ${node%%.*}" "$node" "$latest" "the image tag and digest in scripts/conformance/run.sh"

[ "$status" -ne 0 ] || echo "test pins check: ok (Playwright $pw, @axe-core/playwright $axe, Node $node; nothing newer for $cooldown_days days)"
exit "$status"
