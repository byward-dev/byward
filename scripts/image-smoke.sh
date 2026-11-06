#!/bin/sh
# Smoke test for the snapshot image built by `mise run release:snapshot` (ADR-0019, ADR-0024).
set -eu

arch=$(docker version --format '{{.Server.Arch}}')
image="ghcr.io/corker/mcp-authproxy:snapshot-$arch"
fail() { echo "image smoke: FAIL: $*" >&2; exit 1; }

user=$(docker image inspect --format '{{.Config.User}}' "$image")
[ "$user" = "65532:65532" ] || fail "Config.User is '$user', want 65532:65532"

# The binary must start (any exit code from the program itself, not 125-127 from docker/exec).
set +e
docker run --rm "$image" >/dev/null 2>&1
code=$?
set -e
[ "$code" -lt 125 ] || fail "binary did not start (docker run exit $code)"

tmp=$(mktemp -d)
ctr=$(docker create "$image")
trap 'docker rm -f "$ctr" >/dev/null; rm -rf "$tmp"' EXIT
listing="$tmp/listing"
docker export "$ctr" | tar -tvf - --numeric-owner > "$listing"
grep -Eq '^-r-xr-xr-x .* usr/local/bin/mcp-authproxy$' "$listing" || fail "binary missing, or writable"
grep -Eq '^drwx.* 65532[ /]+65532 .* var/lib/mcp-authproxy/?$' "$listing" || fail "state dir not owned by 65532"
for f in LICENSE NOTICE third_party/go.dev/LICENSE; do
  grep -q "usr/share/doc/mcp-authproxy/$f\$" "$listing" || fail "missing /usr/share/doc/mcp-authproxy/$f"
done

docker build --quiet --build-arg "MCP_AUTHPROXY_IMAGE=$image" -t mcp-authproxy-smoke-node docs/examples/stdio-node >/dev/null
set +e
docker run --rm --entrypoint /usr/local/bin/mcp-authproxy mcp-authproxy-smoke-node >/dev/null 2>&1
code=$?
set -e
[ "$code" -lt 125 ] || fail "binary did not start in the FROM node example (docker run exit $code)"
docker image rm mcp-authproxy-smoke-node >/dev/null

echo "image smoke: ok ($image)"
