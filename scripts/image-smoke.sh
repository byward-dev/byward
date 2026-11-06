#!/bin/sh
# Smoke test for the snapshot image built by `mise run release:snapshot` (ADR-0019, ADR-0024).
set -eu

arch=$(docker version --format '{{.Server.Arch}}')
# Tag contract with .goreleaser.yaml: snapshots are tagged "snapshot", dockers_v2 adds "-<arch>".
image="ghcr.io/byward-dev/byward:snapshot-$arch"
node_image="byward-smoke-node:$$"
fail() { echo "image smoke: FAIL: $*" >&2; exit 1; }

tmp=$(mktemp -d)
ctr=
trap 'if [ -n "$ctr" ]; then docker rm -f "$ctr" >/dev/null 2>&1 || true; fi; docker image rm -f "$node_image" >/dev/null 2>&1 || true; rm -rf "$tmp"' EXIT

# release.yml reads the image digest the same way.
sh scripts/image-digest.sh "$image" >/dev/null || fail "no well-formed digest for $image in dist/artifacts.json"

user=$(docker image inspect --format '{{.Config.User}}' "$image")
[ "$user" = "65532:65532" ] || fail "image must run as 65532:65532, Config.User is '$user'"
for label in "org.opencontainers.image.licenses=Apache-2.0" "org.opencontainers.image.source=https://github.com/byward-dev/byward"; do
  key=${label%%=*}
  got=$(docker image inspect --format "{{index .Config.Labels \"$key\"}}" "$image")
  [ "$got" = "${label#*=}" ] || fail "label $key is '$got', want '${label#*=}'"
done
# OCI annotations (index scope) and buildx provenance exist only on pushed releases, not on snapshots.

# --version must exit 0 with output; it never starts a server, so it cannot block the test.
version=$(docker run --rm "$image" --version) || fail "'byward --version' failed in the image"
[ -n "$version" ] || fail "'byward --version' printed nothing in the image"

ctr=$(docker create "$image")
listing="$tmp/listing"
docker export "$ctr" | tar -tvf - --numeric-owner > "$listing"
grep -Eq '^-r-xr-xr-x .* usr/local/bin/byward$' "$listing" \
  || fail "/usr/local/bin/byward must exist with mode r-xr-xr-x (not writable)"
grep -Eq '^drwx.* 65532[ /]+65532 .* var/lib/byward/?$' "$listing" \
  || fail "/var/lib/byward must be a directory owned by 65532:65532"
for f in LICENSE third_party/go.dev/LICENSE; do
  rm -f "$tmp/licence"
  docker cp "$ctr:/usr/share/doc/byward/$f" "$tmp/licence" >/dev/null 2>&1 || true
  [ -f "$tmp/licence" ] && [ -s "$tmp/licence" ] \
    || fail "image lacks a non-empty /usr/share/doc/byward/$f (licence texts must ship in the image)"
done

# The current context's docker-driver builder (named after the context) sees images loaded into the local store;
# a docker-container builder such as the one setup-buildx-action selects would try to pull them.
docker buildx build --builder "$(docker context show)" --load --quiet --build-arg "BYWARD_IMAGE=$image" \
  -t "$node_image" docs/examples/stdio-node >/dev/null
docker run --rm --entrypoint /usr/local/bin/byward "$node_image" --version >/dev/null \
  || fail "'byward --version' failed in the FROM node example"
docker run --rm --entrypoint sh "$node_image" -c 'touch /var/lib/byward/.write-test' >/dev/null 2>&1 \
  || fail "/var/lib/byward is not writable by the FROM node example's non-root user"

echo "image smoke: ok ($image)"
