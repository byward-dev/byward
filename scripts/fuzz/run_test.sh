#!/bin/sh
# Table test for run.sh with a stub `go` first on PATH (no fuzzing, no network): it lists fixture
# targets, records each `-fuzz` run, and for the targets a case marks failing writes a failing input
# under testdata/fuzz/<Target>/ and exits 1, as Go does. Each case runs in its own git repository,
# so git ls-files finds the new input as run.sh would.
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
  [ -f "$tmp/list-fails" ] && exit 1
  printf 'FuzzA\nFuzzB\nok  \texample.com/m/a\t0.1s\n?   \texample.com/m/none\t[no test files]\nFuzzC\nok  \texample.com/m/c/d\t0.1s\n'
  exit 0 ;;
esac
# go test -run ^\$ -fuzz ^Name\$ -fuzztime T <package>
name=\$(printf '%s' "\$5" | tr -d '^\$')
pkg=\$8
printf '%s %s %s\n' "\$pkg" "\$name" "\$7" >>"$tmp/ran"
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

# case name | failing targets ("" for none) | list fails (yes/no) | want exit | want output (grep -E) |
# want crashers (files under build/fuzz/crashers, space-separated)
run() {
  repo="$tmp/repo-$1"
  mkdir -p "$repo/a/testdata/fuzz/FuzzA"
  : >"$repo/go.mod"
  echo 'go test fuzz v1' >"$repo/a/testdata/fuzz/FuzzA/seed" # a committed seed is no crasher
  git -C "$repo" init -q && git -C "$repo" add -A && git -C "$repo" -c user.email=t@t.example -c user.name=t commit -qm seed
  printf '%s' "$2" >"$tmp/failing"
  rm -f "$tmp/ran" "$tmp/list-fails"
  [ "$3" = yes ] && : >"$tmp/list-fails"
  set +e
  out=$(cd "$repo" && PATH="$tmp/bin:$PATH" FUZZTIME=1s sh "$script" 2>&1)
  code=$?
  set -e
  got=$(cd "$repo" && find build/fuzz/crashers -type f 2>/dev/null | sed 's|^build/fuzz/crashers/||' | sort | tr '\n' ' ' | sed 's/ $//')
  if [ "$code" -ne "$4" ] || ! printf '%s\n' "$out" | grep -Eq "$5" || [ "$got" != "$6" ]; then
    echo "FAIL $1: exit $code (want $4), crashers [$got] (want [$6]), output: $out"
    failures=$((failures + 1))
  fi
}

run all-pass     ""            no  0 'fuzz lane: ok \(3 targets, 1s each\)' ""
run one-fails    "FuzzB"       no  1 'FAIL: 1 of 3 targets failed'          "a/testdata/fuzz/FuzzB/0123abcd"
run two-fail     "FuzzA FuzzC" no  1 'FAIL: 2 of 3 targets failed'          "a/testdata/fuzz/FuzzA/0123abcd c/d/testdata/fuzz/FuzzC/0123abcd"
run list-fails   ""            yes 1 'FAIL: listing the fuzz targets'      ""

# Every target runs, with its own package and the fuzz time, even after one fails.
run every-target "FuzzA" no 1 'crasher \./a/testdata/fuzz/FuzzA/0123abcd|crasher a/testdata/fuzz/FuzzA/0123abcd' "a/testdata/fuzz/FuzzA/0123abcd"
want="example.com/m/a FuzzA 1s
example.com/m/a FuzzB 1s
example.com/m/c/d FuzzC 1s"
if [ "$(cat "$tmp/ran")" != "$want" ]; then
  echo "FAIL every-target: ran $(cat "$tmp/ran")"
  failures=$((failures + 1))
fi

if [ "$failures" -ne 0 ]; then
  echo "fuzz run.sh: $failures failure(s)"
  exit 1
fi
echo "fuzz run.sh: ok"
