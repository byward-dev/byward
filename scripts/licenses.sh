#!/bin/sh
# Dependency licence check and third-party licence texts (ADR-0019).
# Usage: licenses.sh check | save. Runs per release GOOS, since build constraints change the dependency set.
set -eu
self=github.com/byward-dev/byward
allowed=Apache-2.0,BSD-2-Clause,BSD-3-Clause,MIT,ISC
oses="linux darwin" # keep in sync with builds.goos in .goreleaser.yaml

case "${1:-}" in
  check)
    for os in $oses; do
      GOOS=$os go-licenses check ./... --include_tests --ignore "$self" --allowed_licenses="$allowed"
    done
    ;;
  save)
    rm -rf build/licenses build/licenses-by-os
    mkdir -p build/licenses/go.dev
    for os in $oses; do
      GOOS=$os go-licenses save ./... --ignore "$self" --save_path="build/licenses-by-os/$os"
      # go-licenses writes read-only files; make them writable so the next OS can overwrite identical texts.
      if [ -d "build/licenses-by-os/$os" ]; then chmod -R u+w "build/licenses-by-os/$os" && cp -Rf "build/licenses-by-os/$os/." build/licenses/; fi
    done
    rm -rf build/licenses-by-os
    # The Go standard library and runtime are compiled into the binary.
    cp "$(go env GOROOT)/LICENSE" build/licenses/go.dev/LICENSE
    ;;
  *) echo "usage: licenses.sh check | save" >&2; exit 2 ;;
esac
