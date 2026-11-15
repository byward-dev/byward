#!/bin/sh
# Table test for ci-docs-only.sh: which changes count as docs-only (no network, no git for the
# table; one git repository for the diff mode).
set -eu
script="$(cd "$(dirname "$0")" && pwd)/ci-docs-only.sh"
failures=0

# case name | changed paths, one per line | want
run() {
  got=$(printf '%s' "$2" | sh "$script" --classify)
  if [ "$got" != "docs-only=$3" ]; then
    echo "FAIL $1: $got (want docs-only=$3)"
    failures=$((failures + 1))
  fi
}

nl='
'
run how-to          "docs/how-to/tls.md"                                   true
run root-markdown   "README.md${nl}CONTRIBUTING.md"                         true
run adr-and-image   "docs/adr/0001-scope.md${nl}docs/img/flow.svg"          true
run nested-readme   "deploy/README.md"                                     true
run go-code         "docs/how-to/tls.md${nl}internal/server/tls.go"         false
run markdown-in-internal "internal/config/README.md"                       false
run testdata-md     "docs/testdata/case.md"                                false
run workflow        ".github/workflows/ci.yml"                             false
run workflow-md     ".github/PULL_REQUEST_TEMPLATE.md"                     false
run mise            "mise.toml"                                            false
run go-mod          "go.mod"                                               false
run go-sum          "go.sum"                                               false
run cmd             "cmd/byward/main.go"                                   false
run scripts         "scripts/docs-lint.sh"                                 false
run scripts-md      "scripts/conformance/README.md"                        false
run example-docker  "docs/examples/stdio-node/Dockerfile"                  false
run example-md      "docs/examples/stdio-node/README.md"                   false
run other-docs-file "docs/reference/settings.json"                         false
run root-other      "LICENSE"                                              false
run nothing         ""                                                     false

# The diff mode: base...head in a real repository, and no base or head at all.
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
(
  cd "$tmp"
  git init -q
  git config user.email t@example.com
  git config user.name t
  echo a > a.go && git add a.go && git commit -qm base
  git checkout -qb docs && echo b > b.md && git add b.md && git commit -qm docs
  git checkout -q - && git checkout -qb code && echo c > c.go && git add c.go && git commit -qm code
) >/dev/null 2>&1
diff_case() {
  got=$(cd "$tmp" && sh "$script" "$2" "$3" 2>/dev/null)
  if [ "$got" != "docs-only=$4" ]; then
    echo "FAIL $1: $got (want docs-only=$4)"
    failures=$((failures + 1))
  fi
}
base=$(cd "$tmp" && git rev-parse docs~1)
diff_case diff-docs   "$base" "$(cd "$tmp" && git rev-parse docs)" true
diff_case diff-code   "$base" "$(cd "$tmp" && git rev-parse code)" false
diff_case no-base     ""      "$(cd "$tmp" && git rev-parse docs)" false
diff_case no-head     "$base" ""                                   false
diff_case unknown-sha "$base" 0000000000000000000000000000000000000000 false

[ "$failures" -eq 0 ] || { echo "ci-docs-only_test: $failures case(s) failed" >&2; exit 1; }
echo "ci-docs-only_test: ok"
