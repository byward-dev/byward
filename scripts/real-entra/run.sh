#!/bin/sh
# Scheduled real-Entra lane (ADR-0024 §1, §12; docs/maintainers/real-entra-lane.md): byward against the
# maintainer's real tenant, with no stored secret. GitHub's OIDC token for this run is the Entra
# app's federated credential (ADR-0012 §5). It is masked as soon as it is fetched, kept only in a
# 0600 file, and never printed; the lane fails closed without it, with no other credential to use.
#
# GitHub Actions only, in a job with `permissions: id-token: write` and the real-entra environment:
#   BYWARD_CI_ENTRA_TENANT, BYWARD_CI_ENTRA_CLIENT_ID   the CI app (environment variables, not secrets)
set -eu

fail() {
  echo "real-entra lane: FAIL: $*" >&2
  exit 1
}
[ -f go.mod ] || fail "run from the repository root"
[ -n "${ACTIONS_ID_TOKEN_REQUEST_URL:-}" ] && [ -n "${ACTIONS_ID_TOKEN_REQUEST_TOKEN:-}" ] ||
  fail "no GitHub OIDC token can be requested: the job needs permissions: id-token: write"
[ -n "${BYWARD_CI_ENTRA_TENANT:-}" ] || fail "set the real-entra environment variable BYWARD_CI_ENTRA_TENANT"
[ -n "${BYWARD_CI_ENTRA_CLIENT_ID:-}" ] || fail "set the real-entra environment variable BYWARD_CI_ENTRA_CLIENT_ID"

work=$(mktemp -d "${RUNNER_TEMP:-${TMPDIR:-/tmp}}/real-entra.XXXXXX")
token="$work/federated-token"
pid=""
cleanup() {
  if [ -n "$pid" ]; then kill "$pid" 2>/dev/null || true; fi
  rm -rf "$work"
}
trap cleanup EXIT

# fetch_token writes a fresh GitHub OIDC token, audience api://AzureADTokenExchange, to $token.
# Nothing is printed before the mask; any failure stops the lane.
fetch_token() {
  resp=$(curl -fsS --retry 3 --max-time 30 -H "Authorization: bearer $ACTIONS_ID_TOKEN_REQUEST_TOKEN" \
    "$ACTIONS_ID_TOKEN_REQUEST_URL&audience=api://AzureADTokenExchange") || fail "fetching the GitHub OIDC token"
  jwt=$(printf '%s' "$resp" | jq -r '.value // empty') || fail "reading the GitHub OIDC response"
  resp=""
  [ -n "$jwt" ] || fail "the GitHub OIDC response holds no token"
  echo "::add-mask::$jwt"
  (umask 077 && printf '%s' "$jwt" >"$token") || fail "writing the token file"
  jwt=""
  [ -s "$token" ] || fail "the token file is empty"
}

fetch_token
# The claims Entra matches, never the token: the first run's sub goes into the app's federated
# identity credential (docs/maintainers/real-entra-lane.md step 3).
claims=$(cut -d. -f2 <"$token" | tr '_-' '/+' |
  awk '{ n = length($0) % 4; if (n == 2) $0 = $0 "=="; else if (n == 3) $0 = $0 "="; print }' |
  base64 -d | jq -c '{iss, sub, aud}') || fail "decoding the token's claims"
echo "GitHub OIDC claims for the federated credential: $claims"

# A proxy of our own, on loopback, with keys made for this run only.
data="$work/data"
install -d -m 0700 "$data" "$data/keys" "$data/assertion-keys"
(umask 077 && openssl rand -base64 32 >"$data/keys/k1" &&
  openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$data/assertion-keys/k1" 2>/dev/null) ||
  fail "creating this run's keys"
go build -o "$work/byward" ./cmd/byward || fail "building byward"

# proxy runs byward with the lane's settings and nothing else from this environment. It execs, so
# call it in a subshell; in the background, $! is then byward itself and cleanup can stop it.
proxy() {
  exec env -i PATH="$PATH" HOME="$work" BYWARD_DEV=true BYWARD_LOG_FORMAT=text \
    BYWARD_PUBLIC_URL=http://127.0.0.1:18080/mcp BYWARD_LISTEN=127.0.0.1:18080 BYWARD_INTERNAL_LISTEN=127.0.0.1:18081 \
    BYWARD_UPSTREAM_URL=http://127.0.0.1:18082/mcp BYWARD_DATA_DIR="$data" \
    BYWARD_ENTRA_TENANT="$BYWARD_CI_ENTRA_TENANT" BYWARD_ENTRA_CLIENT_ID="$BYWARD_CI_ENTRA_CLIENT_ID" \
    BYWARD_ENTRA_FEDERATED_TOKEN_FILE="$token" "$work/byward" "$@"
}

echo "byward check --offline:"
(proxy check --offline) || fail "byward check --offline"

proxy >"$work/proxy.log" 2>&1 &
pid=$!
ready=""
for _ in $(seq 1 60); do
  if curl -fsS -o /dev/null http://127.0.0.1:18081/readyz 2>/dev/null; then
    ready=1
    break
  fi
  kill -0 "$pid" 2>/dev/null || break
  sleep 0.5
done
if [ -z "$ready" ]; then
  cat "$work/proxy.log" >&2
  fail "the proxy did not become ready"
fi

fetch_token # a fresh one: the GitHub token is short-lived, and byward re-reads the file per request
echo "byward doctor against tenant $BYWARD_CI_ENTRA_TENANT:"
code=0
(proxy doctor --json) >"$work/doctor.json" || code=$?
jq -r '.checks[] | "\(.status)\t\(.class)\t\(.name): \(.message)"' "$work/doctor.json"
[ "$code" -eq 0 ] || fail "byward doctor exited $code"

# Every Entra check the lane exists for must pass, not just not fail: the federated credential
# reached Entra, and its token is what the proxy accepts.
for check in "entra tenant" "entra signing keys" "entra app and credential" "entra access token" "entra idtyp claim"; do
  status=$(jq -r --arg n "$check" '[.checks[] | select(.name == $n) | .status][0] // "missing"' "$work/doctor.json")
  [ "$status" = pass ] || fail "doctor check \"$check\" is $status, want pass"
done
echo "real-entra lane: ok"
