#!/bin/sh
# MCP conformance lane (ADR-0024 §4a, ADR-0027). Runs the conformance `server` suite for both spec
# revisions against the reference server directly and through byward --insecure-no-auth.
# The per-check results must be identical. The direct run is gated by baseline-<revision>.yml, and a
# stale entry fails it, so the baseline lists exactly the checks the reference server itself fails.
# All external code runs in a pinned node container; only build/conformance is mounted.
set -eu
# --install-only stops after the pinned CLI is fetched, verified, installed and built in
# build/conformance/src, for the `authorization` suite in the Go integration lane (ADR-0024 §4b).
install_only=false
[ "${1:-}" != "--install-only" ] || install_only=true

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
# Every revision needs its baseline and its scenario list, before anything is fetched or built.
for rev in $revisions; do
  for f in "baseline-$rev.yml" "scenarios-$rev.txt"; do
    [ -f "$here/$f" ] || fail "missing scripts/conformance/$f for revision $rev"
  done
done
mkdir -p "$work"
work_abs=$(cd "$work" && pwd)
# Logs from an earlier local run must not be shown for a failure that never reached them.
rm -f "$work/install.log" "$work/reference.log" "$work/proxy.log"

# 1. Fetch the pinned commit and verify the lockfiles (fetching only; nothing from it runs on the host).
# A cached checkout is reset to the pinned commit: an earlier run's containers wrote into it.
if [ "$(git -C "$src" rev-parse HEAD 2>/dev/null || true)" != "$sha" ]; then
  rm -rf "$src"
  git init -q "$src"
  # Up to three tries: a transient GitHub error should not fail the lane.
  for try in 1 2 3; do
    git -C "$src" fetch -q --depth 1 https://github.com/modelcontextprotocol/conformance.git "$sha" && break
    [ "$try" -lt 3 ] || fail "fetching conformance $sha failed three times"
    sleep 5
  done
  git -C "$src" checkout -q --detach FETCH_HEAD
fi
[ "$(git -C "$src" rev-parse HEAD)" = "$sha" ] || fail "fetched commit is not $sha"
git -C "$src" reset -q --hard "$sha"
git -C "$src" clean -qfdx
check_lock() {
  got=$(shasum -a 256 "$1" | cut -d' ' -f1)
  [ "$got" = "$2" ] || fail "$1 sha256 is $got, want $2"
}
check_lock "$src/package-lock.json" "$cli_lock_sha256"
check_lock "$src/examples/servers/typescript/package-lock.json" "$server_lock_sha256"

# 2. The container's platform; the binary, script and baselines are placed only after the install, so
#    code run by the install (which has network) cannot touch what the network-less run trusts.
arch=$(docker version --format '{{.Server.Arch}}')
rm -f "$work/byward" "$work/inside.sh" "$work"/baseline-*.yml

# 3. Containers: run as the invoking user, mount only build/conformance, no host credentials, removed on exit.
name=byward-conformance-$$
# shellcheck disable=SC2329 # invoked by the EXIT trap
cleanup() { docker rm -f "$name-install" "$name-run" >/dev/null 2>&1 || true; }
trap cleanup EXIT
# The container's platform is the binary's, so a host whose Docker defaults to another platform
# (DOCKER_DEFAULT_PLATFORM) cannot hand the proxy an image it cannot execute.
in_node() { # $1 container name, $2 network, rest: command
  n=$1 net=$2; shift 2
  docker run --rm --name "$n" --network "$net" --platform "linux/$arch" --user "$(id -u):$(id -g)" \
    -e HOME=/work/home -e npm_config_cache=/work/npm-cache -e npm_config_update_notifier=false \
    -e npm_config_fetch_retries=5 -e npm_config_fetch_retry_mintimeout=2000 \
    -v "$work_abs:/work" -w /work "$image" "$@"
}
# Install needs the registry; install scripts are off (esbuild ships per-platform binaries as optional deps).
# Pull the pinned image first, with retries, so a registry error is reported as one (not as npm's).
for try in 1 2 3; do
  docker pull -q --platform "linux/$arch" "$image" > /dev/null && break
  [ "$try" -lt 3 ] || fail "pulling $image failed three times"
  sleep 5
done
# One command per line: set -e does not stop at a failure inside an && list. The reference server is
# installed only for the server suite: --install-only serves the authorization suite, which runs the
# CLI against byward and never starts it.
# shellcheck disable=SC2016 # $1 is expanded by the container's shell
in_node "$name-install" bridge sh -c '
  set -eu
  cd /work/src
  npm ci --ignore-scripts --no-audit --no-fund > /work/install.log 2>&1
  npm run build >> /work/install.log 2>&1
  [ "$1" = true ] && exit 0
  cd examples/servers/typescript
  npm ci --ignore-scripts --no-audit --no-fund >> /work/install.log 2>&1' sh "$install_only" \
  || { tail -n 30 "$work/install.log" >&2 || true; fail "installing the conformance CLI or reference server failed (log above, full log $work/install.log)"; }
if $install_only; then
  echo "conformance: CLI installed and built in $src"
  exit 0
fi
# Our binary for the container's platform, the in-container script and the baselines, after the install.
GOOS=linux GOARCH=$arch CGO_ENABLED=0 go build -trimpath -o "$work/byward" ./cmd/byward
cp "$here/inside.sh" "$here"/baseline-*.yml "$work/"
# The run needs only loopback.
# shellcheck disable=SC2086 # revisions is a word list
in_node "$name-run" none sh /work/inside.sh $revisions || {
  for log in reference proxy; do echo "--- $work/$log.log" >&2; tail -n 30 "$work/$log.log" >&2 || true; done
  fail "the run container failed before the comparison (logs above)"
}

# 4. Compare direct with proxy, and check the scenarios against scenarios-<revision>.txt.
status=0
# shellcheck disable=SC2086 # revisions is a word list
sh "$here/compare.sh" "$out" "$here" $revisions || {
  status=$?
  for log in reference proxy; do echo "--- last lines of $work/$log.log" >&2; tail -n 20 "$work/$log.log" >&2 || true; done
}
cat "$out/summary.md"
[ -z "${GITHUB_STEP_SUMMARY:-}" ] || cat "$out/summary.md" >> "$GITHUB_STEP_SUMMARY"
exit "$status"
