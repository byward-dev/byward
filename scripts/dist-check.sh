#!/bin/sh
# Checks dist/ from `mise run release:snapshot`: every archive, its contents, SBOMs and checksums (ADR-0019).
set -eu
fail() { echo "dist check: FAIL: $*" >&2; exit 1; }
cd dist

for target in linux_amd64 linux_arm64 darwin_amd64 darwin_arm64; do
  set -- mcp-authproxy_*_"$target".tar.gz
  [ -f "$1" ] || fail "no archive for $target"
  archive=$1
  contents=$(tar -tzf "$archive")
  for f in mcp-authproxy LICENSE NOTICE README.md third_party/go.dev/LICENSE; do
    printf '%s\n' "$contents" | grep -qx "$f" || fail "$archive lacks $f"
  done
  [ -s "$archive.sbom.json" ] || fail "$archive has no SBOM ($archive.sbom.json)"
done

[ -s checksums.txt ] || fail "checksums.txt missing or empty"
shasum -a 256 -c checksums.txt >/dev/null || fail "checksums.txt does not match the files in dist/"
echo "dist check: ok"
