#!/bin/sh
# Table test for go-version-check.sh against fixture go.dev responses (no network).
set -eu
script="$(cd "$(dirname "$0")" && pwd)/go-version-check.sh"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
failures=0

# case name | pinned | go.mod | go.dev JSON | want exit | want output (grep -E)
run() {
  printf 'go = "%s"\n' "$2" > "$tmp/mise.toml"
  printf 'module example.com/x\n\ngo %s\n' "$3" > "$tmp/go.mod"
  printf '%s' "$4" > "$tmp/dl.json"
  set +e
  out=$(cd "$tmp" && GO_DL_JSON="$tmp/dl.json" sh "$script" 2>&1)
  code=$?
  set -e
  if [ "$code" -ne "$5" ] || ! printf '%s\n' "$out" | grep -Eq "$6"; then
    echo "FAIL $1: exit $code (want $5), output: $out"
    failures=$((failures + 1))
  fi
}

s() { printf '{"version":"go%s","stable":%s}' "$1" "${2:-true}"; }
run current        1.27.3 1.27.3 "[$(s 1.27.3),$(s 1.26.10)]"            0 'ok'
run newer-patch    1.27.3 1.27.3 "[$(s 1.27.4),$(s 1.26.11)]"            1 'NEWER PATCH: go1\.27\.4'
run two-digit      1.27.3 1.27.3 "[$(s 1.27.10)]"                         1 'NEWER PATCH: go1\.27\.10'
run newer-minor    1.27.3 1.27.3 "[$(s 1.28.0),$(s 1.27.3)]"              1 'NEWER MINOR: go1\.28\.0'
run both           1.27.3 1.27.3 "[$(s 1.28.1),$(s 1.27.10)]"             1 'NEWER PATCH.*'
run both-minor     1.27.3 1.27.3 "[$(s 1.28.1),$(s 1.27.10)]"             1 'NEWER MINOR: go1\.28\.1'
run rc-ignored     1.27.3 1.27.3 "[$(s 1.28rc1 false),$(s 1.27.3)]"       0 'ok'
run unsupported    1.27.3 1.27.3 "[$(s 1.29.0),$(s 1.28.4)]"              1 'MINOR UNSUPPORTED: .*go1\.27'
run empty          1.27.3 1.27.3 "[]"                                     1 'no stable releases'
run not-json       1.27.3 1.27.3 "<html>"                                 1 '.'
run minor-pin      1.27   1.27.3 "[$(s 1.27.3)]"                          1 'exact patch'
run gomod-ahead    1.27.3 1.27.4 "[$(s 1.27.3)]"                          1 'go\.mod requires go1\.27\.4'
run gomod-behind   1.27.3 1.27.0 "[$(s 1.27.3)]"                          0 'ok'

: > "$tmp/mise.toml"
set +e; (cd "$tmp" && GO_DL_JSON="$tmp/dl.json" sh "$script" >/dev/null 2>&1); code=$?; set -e
[ "$code" -eq 1 ] || { echo "FAIL no-pin: exit $code (want 1)"; failures=$((failures + 1)); }

[ "$failures" -eq 0 ] || { echo "go-version-check_test: $failures case(s) failed" >&2; exit 1; }
echo "go-version-check_test: ok"
