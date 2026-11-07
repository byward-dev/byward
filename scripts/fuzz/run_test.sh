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
# The developer's git config (hooks, excludes, signing) must not reach the test repositories. The
# default excludes file sits under XDG_CONFIG_HOME or HOME even without a global config.
export GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_NOSYSTEM=1 HOME="$tmp" XDG_CONFIG_HOME="$tmp"
# Inherited repository variables (git exports them to hooks) would point git at the outer repository.
unset GIT_CONFIG_COUNT GIT_CONFIG_PARAMETERS GIT_DIR GIT_WORK_TREE GIT_INDEX_FILE GIT_OBJECT_DIRECTORY GIT_COMMON_DIR \
  GIT_TEMPLATE_DIR
failures=0

mkdir -p "$tmp/bin"
cat >"$tmp/bin/go" <<EOF
#!/bin/sh
case "\$1 \$2" in
"list -m") echo example.com/m; exit 0 ;;
"test -list")
  case \$(cat "$tmp/list") in
  fails) # a partial listing: one package listed, another that did not build
    printf 'FuzzA\nok  \texample.com/m/a\t0.1s\nFAIL\texample.com/m/b [setup failed]\n'
    exit 1 ;;
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
cat >/dev/null # as a test binary may: a run must not consume the list of targets still to run
printf '%s %s %s %s\n' "\$run" "\$fuzz" "\$time" "\$pkg" >>"$tmp/ran"
name=\${fuzz#^}
name=\${name%\\\$}
case " \$(cat "$tmp/no-input") " in *" \$name "*) exit 1 ;; esac
case " \$(cat "$tmp/failing") " in
*" \$name "*)
  dir=".\${pkg#example.com/m}/testdata/fuzz/\$name"
  mkdir -p "\$dir"
  printf 'go test fuzz v1\nstring(%s)\n' "\$name" >"\$dir/0123abcd" # its own content, to compare
  exit 1 ;;
esac
exit 0
EOF
chmod +x "$tmp/bin/go"

all="^\$ ^FuzzA\$ 1s example.com/m/a;^\$ ^FuzzB\$ 1s example.com/m/a;^\$ ^FuzzC\$ 1s example.com/m/c/d"
fuzztime=1s # FUZZTIME for the next rows; empty leaves it unset

# case name | listing (ok, fails, empty) | targets failing with an input | targets failing without
# one | want exit | want output (grep -E patterns, ;-separated, each required) | want crashers (space-separated) | want runs (;-separated) |
# output that must not appear (grep -E, optional)
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
  out=$(
    cd "$repo" || exit
    if [ -n "$fuzztime" ]; then export FUZZTIME="$fuzztime"; else unset FUZZTIME; fi
    PATH="$tmp/bin:$PATH" sh "$script" 2>&1
  )
  code=$?
  set -e
  crashers=$(cd "$repo" && find build/fuzz/crashers -type f 2>/dev/null | sed 's|^build/fuzz/crashers/||' | sort | tr '\n' ' ' | sed 's/ $//')
  ran=$(tr '\n' ';' <"$tmp/ran" | sed 's/;$//')
  # Each crasher must be a copy of the input Go wrote, which is what a developer replays.
  for f in $crashers; do
    cmp -s "$repo/$f" "$repo/build/fuzz/crashers/$f" || crashers="$crashers (differs: $f)"
  done
  unwanted=${9:-}
  missing=""
  old_ifs=$IFS
  IFS=';'
  for want in $6; do
    printf '%s\n' "$out" | grep -Eq "$want" || missing="$missing [$want]"
  done
  IFS=$old_ifs
  if [ "$code" -ne "$5" ] || [ -n "$missing" ] || [ "$crashers" != "$7" ] || [ "$ran" != "$8" ] ||
    { [ -n "$unwanted" ] && printf '%s\n' "$out" | grep -Eq "$unwanted"; }; then
    echo "FAIL $1: exit $code (want $5), crashers [$crashers] (want [$7]), ran [$ran] (want [$8]), output: $out"
    failures=$((failures + 1))
  fi
}

run all-pass-and-stale-crashers-are-cleared ok "" "" 0 'fuzz lane: ok \(3 targets, 1s each\)' "" "$all"
run one-fails-and-the-rest-still-run ok "FuzzB" "" 1 'FAIL: 1 of 3 targets failed' "a/testdata/fuzz/FuzzB/0123abcd" "$all" 'wrote no input'
run keeps-only-new-inputs-not-tracked-seeds ok "FuzzA FuzzC" "" 1 'FAIL: 2 of 3 targets failed' \
  "a/testdata/fuzz/FuzzA/0123abcd c/d/testdata/fuzz/FuzzC/0123abcd" "$all"
# FuzzA's input sits beside FuzzB's empty corpus: each target gets only its own.
run a-failure-without-an-input-says-so ok "FuzzA" "FuzzB" 1 'example.com/m/a FuzzB wrote no input;FAIL: 2 of 3 targets failed' "a/testdata/fuzz/FuzzA/0123abcd" "$all"
run a-failed-listing-shows-why-and-runs-nothing fails "" "" 1 'example.com/m/b \[setup failed\];FAIL: listing the fuzz targets' "" "" 'no fuzz targets found'
run no-targets-is-a-failure empty "" "" 1 'FAIL: no fuzz targets found' "" ""
fuzztime=""
run without-fuzztime-each-target-gets-2m ok "" "" 0 'fuzz lane: ok \(3 targets, 2m each\)' "" "$(printf '%s' "$all" | sed 's/ 1s / 2m /g')"
fuzztime=1s

# Outside the repository root the lane refuses to run, before it lists or deletes anything.
mkdir -p "$tmp/not-root/build/fuzz/crashers" && : >"$tmp/not-root/build/fuzz/crashers/kept"
: >"$tmp/ran"
set +e
out=$(cd "$tmp/not-root" && PATH="$tmp/bin:$PATH" sh "$script" 2>&1)
code=$?
set -e
if [ "$code" -ne 1 ] || ! printf '%s\n' "$out" | grep -q 'FAIL: run from the repository root' ||
  [ ! -f "$tmp/not-root/build/fuzz/crashers/kept" ] || [ -s "$tmp/ran" ]; then
  echo "FAIL outside-the-repository-root-it-refuses: exit $code (want 1), output: $out"
  failures=$((failures + 1))
fi

if [ "$failures" -ne 0 ]; then
  echo "fuzz run.sh: $failures failure(s)"
  exit 1
fi
echo "fuzz run.sh: ok"
