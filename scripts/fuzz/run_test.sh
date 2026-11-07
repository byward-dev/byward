#!/bin/sh
# Table test for run.sh with a stub `go` first on PATH (no fuzzing, no network). The stub lists
# fixture targets, records each run's -run, -fuzz, -fuzztime and package exactly as given, and for
# the targets a case marks failing exits 1, as Go does, writing a failing input under
# testdata/fuzz/<Target>/ unless the case says it writes none. Each case runs in its own git
# repository, so git ls-files finds new inputs as run.sh would.
set -eu
script="$(cd "$(dirname "$0")" && pwd)/run.sh"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
failures=0

mkdir -p "$tmp/bin"
cat >"$tmp/bin/go" <<EOF
#!/bin/sh
case "\$1 \$2" in
"list -m") echo example.com/m; exit 0 ;;
"test -list")
  case \$(cat "$tmp/list") in
  fails) exit 1 ;;
  empty) printf 'ok  \texample.com/m/a\t0.1s\n?   \texample.com/m/none\t[no test files]\n'; exit 0 ;;
  esac
  printf 'FuzzA\nFuzzB\nok  \texample.com/m/a\t0.1s\n?   \texample.com/m/none\t[no test files]\nFuzzC\nok  \texample.com/m/c/d\t0.1s\n'
  exit 0 ;;
esac
shift # test
while [ \$# -gt 1 ]; do
  case \$1 in
  -run) run=\$2; shift ;;
  -fuzz) fuzz=\$2; shift ;;
  -fuzztime) time=\$2; shift ;;
  esac
  shift
done
pkg=\$1
printf '%s %s %s %s\n' "\$run" "\$fuzz" "\$time" "\$pkg" >>"$tmp/ran"
name=\${fuzz#^}
name=\${name%\\\$}
case " \$(cat "$tmp/no-input") " in *" \$name "*) exit 1 ;; esac
case " \$(cat "$tmp/failing") " in
*" \$name "*)
  dir=".\${pkg#example.com/m}/testdata/fuzz/\$name"
  mkdir -p "\$dir"
  echo 'go test fuzz v1' >"\$dir/0123abcd"
  exit 1 ;;
esac
exit 0
EOF
chmod +x "$tmp/bin/go"

all="^\$ ^FuzzA\$ 1s example.com/m/a;^\$ ^FuzzB\$ 1s example.com/m/a;^\$ ^FuzzC\$ 1s example.com/m/c/d"

# case name | listing (ok, fails, empty) | targets failing with an input | targets failing without
# one | want exit | want output (grep -E) | want crashers (space-separated) | want runs (;-separated)
run() {
  repo="$tmp/repo-$1"
  mkdir -p "$repo/a/testdata/fuzz/FuzzA"
  : >"$repo/go.mod"
  echo 'go test fuzz v1' >"$repo/a/testdata/fuzz/FuzzA/seed" # a seed in the index is no crasher
  # No commit: a file in the index is not untracked, and a commit would read the developer's git
  # config (signing, hooks).
  git -C "$repo" init -q && git -C "$repo" add -A
  mkdir -p "$repo/build/fuzz/crashers" && : >"$repo/build/fuzz/crashers/stale" # a previous run's
  printf '%s' "$2" >"$tmp/list"
  printf '%s' "$3" >"$tmp/failing"
  printf '%s' "$4" >"$tmp/no-input"
  : >"$tmp/ran"
  set +e
  out=$(cd "$repo" && PATH="$tmp/bin:$PATH" FUZZTIME=1s sh "$script" 2>&1)
  code=$?
  set -e
  crashers=$(cd "$repo" && find build/fuzz/crashers -type f 2>/dev/null | sed 's|^build/fuzz/crashers/||' | sort | tr '\n' ' ' | sed 's/ $//')
  ran=$(tr '\n' ';' <"$tmp/ran" | sed 's/;$//')
  if [ "$code" -ne "$5" ] || ! printf '%s\n' "$out" | grep -Eq "$6" || [ "$crashers" != "$7" ] || [ "$ran" != "$8" ]; then
    echo "FAIL $1: exit $code (want $5), crashers [$crashers] (want [$7]), ran [$ran] (want [$8]), output: $out"
    failures=$((failures + 1))
  fi
}

run all-pass-and-stale-crashers-are-cleared ok "" "" 0 'fuzz lane: ok \(3 targets, 1s each\)' "" "$all"
run one-fails-and-the-rest-still-run ok "FuzzB" "" 1 'FAIL: 1 of 3 targets failed' "a/testdata/fuzz/FuzzB/0123abcd" "$all"
run keeps-only-new-inputs-not-committed-seeds ok "FuzzA FuzzC" "" 1 'FAIL: 2 of 3 targets failed' \
  "a/testdata/fuzz/FuzzA/0123abcd c/d/testdata/fuzz/FuzzC/0123abcd" "$all"
run a-failure-without-an-input-says-so ok "" "FuzzC" 1 'example.com/m/c/d FuzzC wrote no input' "" "$all"
run a-failed-listing-runs-nothing fails "" "" 1 'FAIL: listing the fuzz targets' "" ""
run no-targets-is-a-failure empty "" "" 1 'FAIL: no fuzz targets found' "" ""

if [ "$failures" -ne 0 ]; then
  echo "fuzz run.sh: $failures failure(s)"
  exit 1
fi
echo "fuzz run.sh: ok"
