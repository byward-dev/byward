#!/bin/sh
# Smoke test for the snapshot images built by `mise run release:snapshot` (ADR-0019, ADR-0024): one
# per release architecture. The host's own runs natively; the other runs under emulation (QEMU in
# CI through setup-qemu-action, built into Docker Desktop), so a broken image of either fails here.
set -eu

host_arch=$(docker version --format '{{.Server.Arch}}')
node_image="byward-smoke-node:$$"
fail() { echo "image smoke: FAIL: $*" >&2; exit 1; }

tmp=$(mktemp -d)
ctr=
trap 'if [ -n "$ctr" ]; then docker rm -f "$ctr" >/dev/null 2>&1 || true; fi; docker image rm -f "$node_image" >/dev/null 2>&1 || true; rm -rf "$tmp"' EXIT

# smoke checks the snapshot image of one architecture (amd64 or arm64).
smoke() {
  arch=$1
  # Tag contract with .goreleaser.yaml: snapshots are tagged "snapshot", dockers_v2 adds "-<arch>".
  image="ghcr.io/byward-dev/byward:snapshot-$arch"

  # release.yml reads the image digest the same way.
  sh scripts/image-digest.sh "$image" >/dev/null || fail "no well-formed digest for $image in dist/artifacts.json"

  platform=$(docker image inspect --format '{{.Os}}/{{.Architecture}}' "$image")
  [ "$platform" = "linux/$arch" ] || fail "$image is for $platform, want linux/$arch"
  user=$(docker image inspect --format '{{.Config.User}}' "$image")
  [ "$user" = "65532:65532" ] || fail "$image must run as 65532:65532, Config.User is '$user'"
  # A setting baked into the image would apply to every deployment unseen (BYWARD_DEV=true, say).
  docker image inspect --format '{{range .Config.Env}}{{println .}}{{end}}' "$image" | grep -q '^BYWARD_' \
    && fail "$image sets BYWARD_ environment variables; settings belong to the deployment"
  for label in "org.opencontainers.image.licenses=Apache-2.0" "org.opencontainers.image.source=https://github.com/byward-dev/byward"; do
    key=${label%%=*}
    got=$(docker image inspect --format "{{index .Config.Labels \"$key\"}}" "$image")
    [ "$got" = "${label#*=}" ] || fail "$image: label $key is '$got', want '${label#*=}'"
  done
  # OCI annotations (index scope) and buildx provenance exist only on pushed releases, not on snapshots.

  # --version must exit 0 with output; it never starts a server, so it cannot block the test. An
  # image of another architecture needs emulation: QEMU's binfmt handlers, or Docker Desktop's.
  version=$(docker run --rm --platform "linux/$arch" "$image" --version) \
    || fail "'byward --version' failed in $image (for an architecture other than the host's, is emulation installed?)"
  [ -n "$version" ] || fail "'byward --version' printed nothing in $image"

  ctr=$(docker create --platform "linux/$arch" "$image")
  listing="$tmp/listing"
  docker export "$ctr" | tar -tvf - --numeric-owner > "$listing"
  grep -Eq '^-r-xr-xr-x .* usr/local/bin/byward$' "$listing" \
    || fail "$image: /usr/local/bin/byward must exist with mode r-xr-xr-x (not writable)"
  grep -Eq '^drwx.* 65532[ /]+65532 .* var/lib/byward/?$' "$listing" \
    || fail "$image: /var/lib/byward must be a directory owned by 65532:65532"
  # The binary's own architecture, from its ELF header's e_machine (offset 18): on an amd64 host an
  # amd64 binary in the arm64 image would run natively and pass every check above.
  rm -f "$tmp/byward"
  docker cp "$ctr:/usr/local/bin/byward" "$tmp/byward" >/dev/null
  machine=$(od -An -tx1 -j18 -N2 "$tmp/byward" | tr -d ' \n')
  case "$arch:$machine" in
    amd64:3e00 | arm64:b700) ;;
    *) fail "$image: /usr/local/bin/byward is built for ELF machine $machine, not $arch" ;;
  esac
  # The serving check below trusts its fake IdP through SSL_CERT_DIR, which Go reads beside this
  # bundle; a real IdP needs the bundle itself.
  # 100 is well under the bundle's ~150 certificates and well over a stub's.
  rm -f "$tmp/ca"
  docker cp "$ctr:/etc/ssl/certs/ca-certificates.crt" "$tmp/ca" >/dev/null 2>&1 || true
  certs=$( (grep -c 'BEGIN CERTIFICATE' "$tmp/ca" 2>/dev/null) || true)
  [ "${certs:-0}" -ge 100 ] \
    || fail "$image: /etc/ssl/certs/ca-certificates.crt holds ${certs:-no} certificates, want the CA bundle a real IdP's TLS needs"
  for f in LICENSE third_party/go.dev/LICENSE; do
    rm -f "$tmp/licence"
    docker cp "$ctr:/usr/share/doc/byward/$f" "$tmp/licence" >/dev/null 2>&1 || true
    [ -f "$tmp/licence" ] && [ -s "$tmp/licence" ] \
      || fail "$image lacks a non-empty /usr/share/doc/byward/$f (licence texts must ship in the image)"
  done
  docker rm -f "$ctr" >/dev/null
  ctr=

  # The image serves: run as the README does, it answers /readyz, challenges an unauthenticated MCP
  # request, signs a user in through a fake IdP and relays an MCP request with the identity
  # assertion (internal/server/image_test.go). The fakes listen on loopback, which the container
  # reaches on a Linux host network only. The test binary runs natively; only the image is emulated.
  # go test passes with nothing run when the pattern matches no test, or the test skips: require
  # the PASS line.
  if [ "$(uname -s)" = Linux ]; then
    serve_log="$tmp/serve-$arch.log"
    BYWARD_IMAGE="$image" go test -v -timeout 3m -tags integration -count=1 -run '^TestIntegrationTheReleaseImageServes$' ./internal/server/ >"$serve_log" 2>&1 \
      || { cat "$serve_log" >&2; fail "$image does not serve (see the test output above)"; }
    grep -q '^--- PASS: TestIntegrationTheReleaseImageServes ' "$serve_log" \
      || { cat "$serve_log" >&2; fail "the serving test did not run for $image (renamed, skipped or not built)"; }
  else
    echo "image smoke: skipped the serving check of $image, which needs a Linux host network (CI runs it)" >&2
  fi
  echo "image smoke: ok ($image)"
}

# Every snapshot image goreleaser built (.goreleaser.yaml dockers_v2 platforms), so an architecture
# added there is smoked too; the ELF check fails one it does not know.
arches=$(jq -r '.[] | select(.type == "Docker Image") | .name | capture("byward:snapshot-(?<a>[a-z0-9]+)$").a' dist/artifacts.json | sort -u)
[ -n "$arches" ] || fail "dist/artifacts.json lists no snapshot images"
for arch in $arches; do
  smoke "$arch"
done

# The FROM node example builds on the host's own image: building it on the other would run its
# RUN steps under emulation, which tests the emulator, not the image.
image="ghcr.io/byward-dev/byward:snapshot-$host_arch"
# The current context's docker-driver builder (named after the context) sees images loaded into the local store;
# a docker-container builder such as the one setup-buildx-action selects would try to pull them.
docker buildx build --builder "$(docker context show)" --load --quiet --build-arg "BYWARD_IMAGE=$image" \
  -t "$node_image" docs/examples/stdio-node >/dev/null
docker run --rm --entrypoint /usr/local/bin/byward "$node_image" --version >/dev/null \
  || fail "'byward --version' failed in the FROM node example"
docker run --rm --entrypoint sh "$node_image" -c 'touch /var/lib/byward/.write-test' >/dev/null 2>&1 \
  || fail "/var/lib/byward is not writable by the FROM node example's non-root user"

echo "image smoke: ok (FROM node example on $image)"
