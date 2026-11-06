#!/bin/sh
# Build twice (the second time from a copy elsewhere with an empty Go cache) and compare sha256 of the
# binaries and archives. Same goreleaser config as release:snapshot, minus signing, images and SBOMs.
set -eu
build() { goreleaser release --snapshot --clean --skip=sign,docker,sbom >/dev/null; }
sums() { (cd "$1/dist" && find . -type f \( -name '*.tar.gz' -o -name byward \) -exec shasum -a 256 {} + | sort -k2); }
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
build
sums . > "$tmp/first"
[ -s "$tmp/first" ] || { echo "reproducible: FAIL: no binaries or archives found in dist/" >&2; exit 1; }
mkdir "$tmp/src"
tar --exclude=./dist -cf - . | tar -C "$tmp/src" -xf -
(cd "$tmp/src" && GOCACHE="$tmp/gocache" build)
sums "$tmp/src" > "$tmp/second"
diff "$tmp/first" "$tmp/second" || {
  echo "reproducible: FAIL: a rebuild from a copy with an empty Go cache gave different bytes (< first, > rebuild)" >&2
  exit 1
}
echo "reproducible: $(wc -l < "$tmp/first" | tr -d ' ') files identical"
