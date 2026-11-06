#!/bin/sh
# Smoke test for the snapshot image built by `mise run release:snapshot` (ADR-0019, ADR-0024).
set -eu

arch=$(docker version --format '{{.Server.Arch}}')
# Tag contract with .goreleaser.yaml: snapshots are tagged "snapshot", dockers_v2 adds "-<arch>".
image="ghcr.io/corker/mcp-authproxy:snapshot-$arch"
node_image="mcp-authproxy-smoke-node:$$"
fail() { echo "image smoke: FAIL: $*" >&2; exit 1; }

tmp=$(mktemp -d)
ctr=
trap 'if [ -n "$ctr" ]; then docker rm -f "$ctr" >/dev/null 2>&1 || true; fi; docker image rm -f "$node_image" >/dev/null 2>&1 || true; rm -rf "$tmp"' EXIT

# release.yml reads the image digest the same way.
sh scripts/image-digest.sh "$image" >/dev/null || fail "no well-formed digest for $image in dist/artifacts.json"

user=$(docker image inspect --format '{{.Config.User}}' "$image")
[ "$user" = "65532:65532" ] || fail "image must run as 65532:65532, Config.User is '$user'"
for label in "org.opencontainers.image.licenses=Apache-2.0" "org.opencontainers.image.source=https://github.com/corker/mcp-authproxy"; do
  key=${label%%=*}
  got=$(docker image inspect --format "{{index .Config.Labels \"$key\"}}" "$image")
  [ "$got" = "${label#*=}" ] || fail "label $key is '$got', want '${label#*=}'"
done
# OCI annotations (index scope) and buildx provenance exist only on pushed releases, not on snapshots.

# The binary must start: any exit code from the program itself passes, 125-127 (docker/exec errors) fail.
# --version so a real server never blocks the test.
set +e
docker run --rm "$image" --version >/dev/null 2>&1
code=$?
set -e
[ "$code" -lt 125 ] || fail "binary did not start (docker run exit $code)"

ctr=$(docker create "$image")
listing="$tmp/listing"
docker export "$ctr" | tar -tvf - --numeric-owner > "$listing"
grep -Eq '^-r-xr-xr-x .* usr/local/bin/mcp-authproxy$' "$listing" \
  || fail "/usr/local/bin/mcp-authproxy must exist with mode r-xr-xr-x (not writable)"
grep -Eq '^drwx.* 65532[ /]+65532 .* var/lib/mcp-authproxy/?$' "$listing" \
  || fail "/var/lib/mcp-authproxy must be a directory owned by 65532:65532"
for f in LICENSE NOTICE third_party/go.dev/LICENSE; do
  rm -f "$tmp/licence"
  docker cp "$ctr:/usr/share/doc/mcp-authproxy/$f" "$tmp/licence" >/dev/null 2>&1 || true
  [ -f "$tmp/licence" ] && [ -s "$tmp/licence" ] \
    || fail "image lacks a non-empty /usr/share/doc/mcp-authproxy/$f (licence texts must ship in the image)"
done

# The current context's docker-driver builder (named after the context) sees images loaded into the local store;
# a docker-container builder such as the one setup-buildx-action selects would try to pull them.
docker buildx build --builder "$(docker context show)" --load --quiet --build-arg "MCP_AUTHPROXY_IMAGE=$image" \
  -t "$node_image" docs/examples/stdio-node >/dev/null
set +e
docker run --rm --entrypoint /usr/local/bin/mcp-authproxy "$node_image" --version >/dev/null 2>&1
code=$?
set -e
[ "$code" -lt 125 ] || fail "binary did not start in the FROM node example (docker run exit $code)"
docker run --rm --entrypoint sh "$node_image" -c 'touch /var/lib/mcp-authproxy/.write-test' >/dev/null 2>&1 \
  || fail "/var/lib/mcp-authproxy is not writable by the FROM node example's non-root user"

echo "image smoke: ok ($image)"
