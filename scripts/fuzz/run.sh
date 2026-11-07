#!/bin/sh
# Nightly fuzz lane (ADR-0024 §1, §9): every `func Fuzz*` in the module, FUZZTIME each (2 minutes in
# the scheduled workflow). Targets are found with `go test -list`, so a new one is fuzzed without
# editing the workflow. Every target runs even after one fails; a failing input Go wrote under a
# package's testdata/fuzz/ is copied to build/fuzz/crashers/<package path>/ for the workflow to
# upload, and the lane fails.
#   FUZZTIME=2m sh scripts/fuzz/run.sh        (mise run test:fuzz)
set -eu

fail() {
  echo "fuzz lane: FAIL: $*" >&2
  exit 1
}
[ -f go.mod ] || fail "run from the repository root"
fuzztime=${FUZZTIME:-2m}
out=build/fuzz/crashers
mkdir -p build/fuzz
rm -rf "$out"
mkdir -p "$out"

# "package target" lines: go test -list prints a package's matching names, then its "ok" line.
go test -list '^Fuzz' ./... >build/fuzz/list || fail "listing the fuzz targets"
targets=$(awk '
  /^ok[ \t]/ { for (i = 1; i <= n; i++) print $2, names[i]; n = 0; next }
  /^Fuzz/    { names[++n] = $1 }
' build/fuzz/list)
[ -n "$targets" ] || fail "no fuzz targets found"

module=$(go list -m)
failed=0
total=0
printf '%s\n' "$targets" >"build/fuzz/targets"
while read -r pkg name; do
  total=$((total + 1))
  dir=".${pkg#"$module"}"
  echo "== $pkg $name ($fuzztime)"
  if ! go test -run '^$' -fuzz "^${name}\$" -fuzztime "$fuzztime" "$pkg" </dev/null; then
    failed=$((failed + 1))
    echo "fuzz lane: $pkg $name failed"
    # The failing input Go wrote: untracked files in this target's corpus.
    git ls-files --others --exclude-standard -- "$dir/testdata/fuzz/$name" | while read -r f; do
      mkdir -p "$out/$(dirname "$f")"
      cp "$f" "$out/$f"
      echo "fuzz lane: crasher $f"
    done
  fi
done <"build/fuzz/targets"

if [ "$failed" -ne 0 ]; then
  fail "$failed of $total targets failed; their inputs are in $out"
fi
echo "fuzz lane: ok ($total targets, $fuzztime each)"
