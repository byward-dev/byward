#!/bin/sh
# Browser lane (ADR-0010, ADR-0024): the consent and error pages in Chromium, checked with axe
# (WCAG 2.2 AA) and Playwright, screenshots saved to build/ui/screenshots for review. The page
# server (internal/testutil/pageserver: stub IdP, fixed clients) runs inside the container on
# loopback; the run has no network. Only build/ui is mounted.
set -eu

# Pins. The image's browsers match @playwright/test 1.64.1 (package.json, package-lock.json).
image=mcr.microsoft.com/playwright:v1.64.1-noble@sha256:2f05f8a734509a7b3f26a912639488ee08f58a7b292d14d62271bcff9038768f

here=$(cd "$(dirname "$0")" && pwd)
work=build/ui
fail() { echo "ui: FAIL: $*" >&2; exit 1; }
rm -rf "$work/screenshots" "$work/test-results"
mkdir -p "$work/screenshots"
work_abs=$(cd "$work" && pwd)

arch=$(docker version --format '{{.Server.Arch}}')
GOOS=linux GOARCH=$arch CGO_ENABLED=0 go build -trimpath -o "$work/pageserver" ./internal/testutil/pageserver
cp "$here/package.json" "$here/package-lock.json" "$here/playwright.config.js" "$here/pages.spec.js" "$work/"

name=mcp-authproxy-ui-$$
# shellcheck disable=SC2329 # invoked by the EXIT trap
cleanup() { docker rm -f "$name-install" "$name-run" >/dev/null 2>&1 || true; }
trap cleanup EXIT
in_image() { # $1 container name, $2 network, rest: command
  n=$1 net=$2; shift 2
  docker run --rm --name "$n" --network "$net" --user "$(id -u):$(id -g)" --ipc=host \
    -e HOME=/work/home -e npm_config_cache=/work/npm-cache -e npm_config_update_notifier=false \
    -e PLAYWRIGHT_BROWSERS_PATH=/ms-playwright \
    -v "$work_abs:/work" -w /work "$image" "$@"
}
in_image "$name-install" bridge sh -c 'npm ci --ignore-scripts --no-audit --no-fund > /work/install.log 2>&1' \
  || fail "npm ci failed (see $work/install.log)"
in_image "$name-run" none npx playwright test || fail "browser checks failed (see $work/test-results)"
echo "ui: OK; screenshots in $work/screenshots"
