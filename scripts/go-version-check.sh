#!/bin/sh
# Fails when go.dev lists a Go release newer than the toolchain pinned in mise.toml.
# Dependabot cannot bump mise.toml, so .github/workflows/go-version.yml runs this weekly.
# GO_DL_JSON may name a local copy of https://go.dev/dl/?mode=json (scripts/go-version-check_test.sh uses it).
set -eu

pinned=$(sed -n 's/^go = "\([^"]*\)".*$/\1/p' mise.toml)
[ -n "$pinned" ] || { echo "go version check: FAIL: no 'go = \"x.y.z\"' line in mise.toml [tools]" >&2; exit 1; }
printf '%s' "$pinned" | grep -Eqx '[0-9]+\.[0-9]+\.[0-9]+' \
  || { echo "go version check: FAIL: mise.toml must pin go to an exact patch, found '$pinned'" >&2; exit 1; }
minor=${pinned%.*}

if [ -n "${GO_DL_JSON:-}" ]; then json=$(cat "$GO_DL_JSON"); else json=$(curl -fsSL 'https://go.dev/dl/?mode=json'); fi
# Stable releases as plain x.y.z, newest first.
releases=$(printf '%s' "$json" | jq -r '.[] | select(.stable) | .version | ltrimstr("go")' | sort -t. -k1,1nr -k2,2nr -k3,3nr)
[ -n "$releases" ] || { echo "go version check: FAIL: no stable releases in the go.dev response" >&2; exit 1; }

newer() { # $1 newer than $2?
  [ "$1" != "$2" ] && [ "$(printf '%s\n%s\n' "$1" "$2" | sort -t. -k1,1nr -k2,2nr -k3,3nr | head -n1)" = "$1" ]
}

status=0
# go.mod's go line is the minimum language version; it must not exceed the pinned toolchain.
gomod=$(sed -n 's/^go \([0-9][0-9.]*\)$/\1/p' go.mod)
if [ -n "$gomod" ] && newer "$gomod" "$pinned"; then
  echo "go version check: FAIL: go.mod requires go$gomod, newer than the go$pinned pinned in mise.toml" >&2
  status=1
fi
latest_patch=$(printf '%s\n' "$releases" | grep -E "^$(printf '%s' "$minor" | sed 's/\./\\./')\.[0-9]+$" | head -n1 || true)
if [ -z "$latest_patch" ]; then
  echo "go version check: MINOR UNSUPPORTED: go.dev no longer lists go$minor; move to a supported minor"
  status=1
elif newer "$latest_patch" "$pinned"; then
  echo "go version check: NEWER PATCH: go$latest_patch is out (pinned go$pinned); bump go in mise.toml"
  status=1
fi
latest=$(printf '%s\n' "$releases" | head -n1)
if [ "${latest%.*}" != "$minor" ] && newer "$latest" "$pinned"; then
  echo "go version check: NEWER MINOR: go$latest is out (pinned go$pinned); plan the upgrade"
  status=1
fi
[ "$status" -ne 0 ] || echo "go version check: ok (go$pinned is the latest patch, and go$minor is the newest minor)"
exit "$status"
