#!/bin/sh
# Identity assertion contract lane (ADR-0016 §8, ADR-0024): the TypeScript SDK's requireBearerAuth
# and FastMCP's JWTVerifier, each configured as docs/reference/identity-assertion.md shows, must
# accept an assertion minted by the proxy's code and refuse one for another audience, an expired
# one and one signed with another key. (The go-sdk contract runs in `test`.)
# External code runs only in pinned containers: an install step with network, then the verifier
# with no network and read-only mounts.
set -eu

# Pins: the conformance lane's Node image (read from scripts/conformance/run.sh, so the two never
# differ; test-pins-check.sh keeps it current); Python 3.13 slim; the package versions are in
# scripts/assertion/ts/package-lock.json and scripts/assertion/py/requirements.txt (hashed), which
# Dependabot updates.
py_image=python:3.13-slim@sha256:09a17cad02668ae61ece136b4fd36ac3849e14f670ebedb637ea3e15580525bc

here=$(cd "$(dirname "$0")" && pwd)
work=build/assertion
fail() { echo "assertion contract: FAIL: $*" >&2; exit 1; }
[ -f go.mod ] || fail "run from the repository root"
node_image=$(sed -n 's/^image=\(node:.*@sha256:[0-9a-f]*\)$/\1/p' scripts/conformance/run.sh)
[ -n "$node_image" ] || fail "no pinned node image in scripts/conformance/run.sh"

rm -rf "$work"
mkdir -p "$work/home"
work_abs=$(cd "$work" && pwd)
arch=$(docker version --format '{{.Server.Arch}}')

# 1. Fixture: the JWKS and the assertions, from the proxy's own code.
go run ./internal/testutil/assertionfixture "$work/fixture" || fail "writing the fixture"

pull() {
  for try in 1 2 3; do
    docker pull -q --platform "linux/$arch" "$1" >/dev/null && return 0
    [ "$try" -lt 3 ] || fail "pulling $1 failed three times"
    sleep 5
  done
}
in_container() { # network, image, then the command; /work is the lane's directory
  net=$1 image=$2
  shift 2
  docker run --rm --network "$net" --platform "linux/$arch" --user "$(id -u):$(id -g)" \
    -e HOME=/work/home -e npm_config_cache=/work/home/npm -e npm_config_update_notifier=false \
    -e PIP_CACHE_DIR=/work/home/pip -e PIP_DISABLE_PIP_VERSION_CHECK=1 \
    -v "$work_abs:/work" -w /work "$image" "$@"
}
verify() { # image, then the command; no network, and nothing writable
  image=$1
  shift
  docker run --rm --network none --platform "linux/$arch" --user "$(id -u):$(id -g)" --read-only \
    -v "$work_abs:/work:ro" -w /work "$image" "$@"
}

# 2. TypeScript SDK: install from the lockfile, install scripts off.
cp -R "$here/ts" "$work/ts"
pull "$node_image"
in_container bridge "$node_image" sh -c 'cd ts && npm ci --ignore-scripts --no-audit --no-fund --loglevel=error' ||
  fail "npm ci (scripts/assertion/ts/package-lock.json)"
echo "TypeScript SDK (requireBearerAuth):"
verify "$node_image" sh -c 'cd ts && node verify.mjs /work/fixture' || fail "the TypeScript SDK verifier"

# 3. FastMCP: install into a venv, every package's hash checked.
cp -R "$here/py" "$work/py"
pull "$py_image"
in_container bridge "$py_image" sh -c 'python -m venv /work/py/venv && /work/py/venv/bin/pip install -q --require-hashes --no-deps -r py/requirements.txt' ||
  fail "pip install (scripts/assertion/py/requirements.txt)"
echo "FastMCP (JWTVerifier):"
verify "$py_image" /work/py/venv/bin/python py/verify.py /work/fixture || fail "the FastMCP verifier"

echo "assertion contract: ok"
