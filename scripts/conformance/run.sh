#!/bin/sh
# MCP conformance lane (ADR-0024 §4a, ADR-0027). Runs the conformance `server` suite for both spec
# revisions against the reference server directly and through mcp-authproxy --insecure-no-auth.
# The per-check results must be identical. The direct run is gated by baseline-<revision>.yml, and a
# stale entry fails it, so the baseline lists exactly the checks the reference server itself fails.
# All external code runs in a pinned node container; only build/conformance is mounted.
set -eu

# Pins. @modelcontextprotocol/conformance 0.2.0-alpha.12 (npm, 2026-10-01) is this commit. The npm
# tarball lacks the reference server, so both come from git and are installed from their lockfiles.
sha=c37eec888e1c6ff140af79987a40008548b7cc5f
cli_lock_sha256=e9d0405b0fbc905c962af951382780743a28dffa6ce9999eb9ec5cc86b28b348
server_lock_sha256=08117d35f1e72224414799eba0c93be820c590b54d5201b34dc574f70e111f41
image=node:24.22.1-slim@sha256:be8204d4bd327363357f532187b752ff62759c31bedf98e9e18fc08c9cbd605c
revisions="2025-11-25 2026-07-28"

here=$(cd "$(dirname "$0")" && pwd)
work=build/conformance
src=$work/src
out=$work/results
fail() { echo "conformance: FAIL: $*" >&2; exit 1; }
mkdir -p "$work"
work_abs=$(cd "$work" && pwd)

# 1. Fetch the pinned commit and verify the lockfiles (fetching only; nothing from it runs on the host).
if [ "$(git -C "$src" rev-parse HEAD 2>/dev/null || true)" != "$sha" ]; then
  rm -rf "$src"
  git init -q "$src"
  git -C "$src" fetch -q --depth 1 https://github.com/modelcontextprotocol/conformance.git "$sha"
  git -C "$src" checkout -q --detach FETCH_HEAD
fi
[ "$(git -C "$src" rev-parse HEAD)" = "$sha" ] || fail "fetched commit is not $sha"
check_lock() {
  got=$(shasum -a 256 "$1" | cut -d' ' -f1)
  [ "$got" = "$2" ] || fail "$1 sha256 is $got, want $2"
}
check_lock "$src/package-lock.json" "$cli_lock_sha256"
check_lock "$src/examples/servers/typescript/package-lock.json" "$server_lock_sha256"

# 2. Our binary for the container's platform, plus the in-container script and baselines.
arch=$(docker version --format '{{.Server.Arch}}')
GOOS=linux GOARCH=$arch CGO_ENABLED=0 go build -trimpath -o "$work/mcp-authproxy" ./cmd/mcp-authproxy
cp "$here/inside.sh" "$here"/baseline-*.yml "$work/"

# 3. Containers: run as the invoking user, mount only build/conformance, no host credentials, removed on exit.
name=mcp-authproxy-conformance-$$
# shellcheck disable=SC2329 # invoked by the EXIT trap
cleanup() { docker rm -f "$name-install" "$name-run" >/dev/null 2>&1 || true; }
trap cleanup EXIT
in_node() { # $1 container name, $2 network, rest: command
  n=$1 net=$2; shift 2
  docker run --rm --name "$n" --network "$net" --user "$(id -u):$(id -g)" \
    -e HOME=/work/home -e npm_config_cache=/work/npm-cache -e npm_config_update_notifier=false \
    -v "$work_abs:/work" -w /work "$image" "$@"
}
# Install needs the registry; install scripts are off (esbuild ships per-platform binaries as optional deps).
in_node "$name-install" bridge sh -c '
  set -eu
  cd /work/src && npm ci --ignore-scripts --no-audit --no-fund >/dev/null && npm run build >/dev/null
  cd examples/servers/typescript && npm ci --ignore-scripts --no-audit --no-fund >/dev/null'
# The run needs only loopback.
# shellcheck disable=SC2086 # revisions is a word list
in_node "$name-run" none sh /work/inside.sh $revisions

# 4. Compare direct with proxy, check by check. Timestamps, logs and messages (which name ports) are dropped.
normalise() {
  for f in "$1"/server-*/checks.json; do
    [ -f "$f" ] || continue
    scenario=$(basename "$(dirname "$f")" | sed -E 's/^server-//; s/-[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9-]+Z$//')
    jq -r --arg s "$scenario" '.[] | [$s, .id, .status] | @tsv' "$f"
  done | sort
}
status=0
for rev in $revisions; do
  [ "$(cat "$out/direct-$rev.exit")" = 0 ] \
    || { echo "conformance: FAIL: $rev direct run does not match baseline-$rev.yml (see $out/direct-$rev.txt)" >&2; status=1; }
  normalise "$out/direct/$rev" > "$out/direct-$rev.tsv"
  normalise "$out/proxy/$rev" > "$out/proxy-$rev.tsv"
  [ -s "$out/direct-$rev.tsv" ] || { echo "conformance: FAIL: $rev produced no checks" >&2; status=1; }
  if ! diff "$out/direct-$rev.tsv" "$out/proxy-$rev.tsv" > "$out/diff-$rev.txt"; then
    echo "conformance: FAIL: $rev results through the proxy differ from direct (< direct, > proxy):" >&2
    cat "$out/diff-$rev.txt" >&2
    status=1
  fi
done

# 5. Pass/fail matrix for the PR and the CI job summary.
counts() { printf '%s / %s' "$(grep -c '	FAILURE$' "$1" || true)" "$(grep -c '	WARNING$' "$1" || true)"; }
{
  echo "| Revision | Scenarios | Checks | FAILURE / WARNING (direct) | FAILURE / WARNING (proxy) | Proxy = direct |"
  echo "|---|---|---|---|---|---|"
  for rev in $revisions; do
    same=yes; [ -s "$out/diff-$rev.txt" ] && same=no
    printf '| %s | %s | %s | %s | %s | %s |\n' "$rev" \
      "$(cut -f1 "$out/direct-$rev.tsv" | sort -u | wc -l | tr -d ' ')" "$(wc -l < "$out/direct-$rev.tsv" | tr -d ' ')" \
      "$(counts "$out/direct-$rev.tsv")" "$(counts "$out/proxy-$rev.tsv")" "$same"
  done
} > "$out/summary.md"
cat "$out/summary.md"
[ -z "${GITHUB_STEP_SUMMARY:-}" ] || cat "$out/summary.md" >> "$GITHUB_STEP_SUMMARY"
exit "$status"
