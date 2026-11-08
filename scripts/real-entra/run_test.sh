#!/bin/sh
# Table test for run.sh with stubs first on PATH (no network, no GitHub, no Entra): `curl` answers
# GitHub's OIDC endpoint from a fixture and /readyz, and `go build` writes a fake byward whose
# check, doctor and serve behaviour the case sets. The fake gets only what run.sh passes through
# env -i, so its fixture paths are baked in when it is built.
set -eu
script="$(cd "$(dirname "$0")" && pwd)/run.sh"
tmp=$(mktemp -d)
trap 'pkill -f "$tmp/" 2>/dev/null || true; rm -rf "$tmp"' EXIT
failures=0

# A token whose payload is {"iss":…,"sub":"repo:o@1/r@2:environment:real-entra","aud":…}; the
# signature part stands for the secret the lane must never print.
payload=$(printf '%s' '{"iss":"https://token.actions.githubusercontent.com","sub":"repo:o@1/r@2:environment:real-entra","aud":"api://AzureADTokenExchange"}' |
  base64 | tr -d '\n=' | tr '/+' '_-')
sig=c2lnLXNlY3JldC1wYXJ0
token="eyJhbGciOiJSUzI1NiJ9.$payload.$sig"

mkdir -p "$tmp/bin" "$tmp/repo"
: >"$tmp/repo/go.mod"
cat >"$tmp/bin/curl" <<EOF
#!/bin/sh
for a in "\$@"; do url=\$a; done
case \$url in
*/readyz) [ -f "$tmp/serve-exits" ] && exit 7; exit 0 ;;
esac
printf '%s\n' "\$*" >>"$tmp/oidc-calls"
[ -f "$tmp/oidc-fails" ] && exit 22
# A different token per request, so the test can tell which one doctor was given.
n=\$(wc -l <"$tmp/oidc-calls" | tr -d ' ')
sed "s/$sig/$sig\$n/" "$tmp/oidc.json"
EOF
cat >"$tmp/bin/go" <<EOF
#!/bin/sh
while [ \$# -gt 0 ]; do [ "\$1" = -o ] && out=\$2; shift; done
cat >"\$out" <<'FAKE'
#!/bin/sh
env >"$tmp/byward-env.\$\$"
case \${1:-} in
check) [ -f "$tmp/check-fails" ] && exit 2; echo "configuration OK"; exit 0 ;;
doctor)
  [ "\${2:-}" = --json ] || exit 64
  # What Entra would be sent: the setting, the file's mode and its content.
  { printf '%s\n' "\$BYWARD_ENTRA_FEDERATED_TOKEN_FILE"; ls -l "\$BYWARD_ENTRA_FEDERATED_TOKEN_FILE" | cut -c1-10; cat "\$BYWARD_ENTRA_FEDERATED_TOKEN_FILE"; } >"$tmp/doctor-saw"
  cat "$tmp/doctor.json"; exit \$(cat "$tmp/doctor-exit") ;;
esac
[ -f "$tmp/serve-exits" ] && exit 1
while sleep 1; do :; done # no exec: the process keeps this path, so the test can see it left running
FAKE
chmod +x "\$out"
EOF
chmod +x "$tmp/bin/curl" "$tmp/bin/go"

pass='"status":"pass","class":"idp","message":"m"'
all_pass="{\"checks\":[{\"name\":\"entra tenant\",$pass},{\"name\":\"entra signing keys\",$pass},{\"name\":\"entra app and credential\",$pass},{\"name\":\"entra access token\",$pass},{\"name\":\"entra idtyp claim\",$pass}]}"

# case name | OIDC response ("fail" for an HTTP error) | doctor JSON | doctor exit | serve ("exits") |
# want exit | want output (grep -E)
run() {
  rm -f "$tmp/oidc-fails" "$tmp/serve-exits" "$tmp/check-fails" "$tmp/oidc-calls" "$tmp/doctor-saw" "$tmp"/byward-env.*
  rm -rf "$tmp/runner" && mkdir -p "$tmp/runner"
  if [ "$2" = fail ]; then : >"$tmp/oidc-fails"; else printf '%s' "$2" >"$tmp/oidc.json"; fi
  printf '%s' "$3" >"$tmp/doctor.json"
  printf '%s' "$4" >"$tmp/doctor-exit"
  [ "$5" = exits ] && : >"$tmp/serve-exits"
  [ "$5" = check-fails ] && : >"$tmp/check-fails"
  set +e
  out=$(cd "$tmp/repo" && env PATH="$tmp/bin:$PATH" RUNNER_TEMP="$tmp/runner" ACTIONS_ID_TOKEN_REQUEST_URL="https://oidc.example/t?v=1" \
    ACTIONS_ID_TOKEN_REQUEST_TOKEN=request-token BYWARD_CI_ENTRA_TENANT=00000000-0000-0000-0000-000000000001 \
    BYWARD_CI_ENTRA_CLIENT_ID=00000000-0000-0000-0000-000000000002 sh "$script" 2>&1)
  code=$?
  set -e
  if [ "$code" -ne "$6" ] || ! printf '%s\n' "$out" | grep -Eq "$7"; then
    echo "FAIL $1: exit $code (want $6), output: $out"
    failures=$((failures + 1))
  fi
  # Whatever happened: the token appears only in the mask line, before anything else that could
  # carry it; this run's files are gone; no byward is left running; byward saw none of the
  # runner's environment.
  if printf '%s\n' "$out" | grep -v '^::add-mask::' | grep -q "$sig"; then
    echo "FAIL $1: the token was printed outside the mask line"
    failures=$((failures + 1))
  fi
  # Once a token was fetched, the first thing printed is the mask for exactly that token.
  if case $2 in *"$token"*) true ;; *) false ;; esac && [ "$(printf '%s\n' "$out" | head -n 1)" != "::add-mask::${token}1" ]; then
    echo "FAIL $1: the mask is not the first thing printed"
    failures=$((failures + 1))
  fi
  # GitHub was asked for an Entra token, with the job's request token; doctor read exactly that
  # token from a 0600 file, fetched afresh for it (the second request).
  if [ -f "$tmp/oidc-calls" ] && ! grep -q 'audience=api://AzureADTokenExchange' "$tmp/oidc-calls"; then
    echo "FAIL $1: the OIDC request names no Entra audience"
    failures=$((failures + 1))
  fi
  if [ -f "$tmp/oidc-calls" ] && ! grep -q 'Authorization: bearer request-token' "$tmp/oidc-calls"; then
    echo "FAIL $1: the OIDC request lacks the job's request token"
    failures=$((failures + 1))
  fi
  if [ -f "$tmp/oidc-calls" ] && grep -vq '&audience=api://AzureADTokenExchange$' "$tmp/oidc-calls"; then
    echo "FAIL $1: an OIDC request does not end with the Entra audience: $(cat "$tmp/oidc-calls")"
    failures=$((failures + 1))
  fi
  # byward ran as the lane means it: the CI app, in --dev on loopback.
  if [ -f "$tmp/doctor-saw" ]; then
    for want in BYWARD_ENTRA_TENANT=00000000-0000-0000-0000-000000000001 BYWARD_ENTRA_CLIENT_ID=00000000-0000-0000-0000-000000000002 BYWARD_DEV=true; do
      cat "$tmp"/byward-env.* | grep -qx "$want" || {
        echo "FAIL $1: byward did not get $want"
        failures=$((failures + 1))
      }
    done
  fi
  if [ -f "$tmp/doctor-saw" ]; then
    saw_mode=$(sed -n 2p "$tmp/doctor-saw")
    saw_token=$(sed -n 3p "$tmp/doctor-saw")
    if [ "$saw_mode" != "-rw-------" ] || [ "$saw_token" != "${token}2" ] || [ "$(wc -l <"$tmp/oidc-calls" | tr -d ' ')" != 2 ]; then
      echo "FAIL $1: doctor's token file: mode $saw_mode, the second token? $([ "$saw_token" = "${token}2" ] && echo yes || echo no), OIDC requests $(wc -l <"$tmp/oidc-calls" | tr -d ' ')"
      failures=$((failures + 1))
    fi
    for n in 1 2; do
      printf '%s\n' "$out" | grep -qx "::add-mask::${token}$n" || {
        echo "FAIL $1: token $n was not masked"
        failures=$((failures + 1))
      }
    done
  fi
  if [ -n "$(ls -A "$tmp/runner")" ]; then
    echo "FAIL $1: left $(ls "$tmp/runner") behind"
    failures=$((failures + 1))
  fi
  if pgrep -f "$tmp/runner/" >/dev/null 2>&1; then
    echo "FAIL $1: a byward is still running"
    failures=$((failures + 1))
  fi
  if cat "$tmp"/byward-env.* 2>/dev/null | grep -Eq '^(ACTIONS_|BYWARD_CI_|RUNNER_)'; then
    echo "FAIL $1: byward inherited the runner's environment"
    failures=$((failures + 1))
  fi
}

ok="{\"value\":\"$token\"}"
warn=$(printf '%s' "$all_pass" | sed 's/"name":"entra idtyp claim","status":"pass"/"name":"entra idtyp claim","status":"warn"/')
missing=$(printf '%s' "$all_pass" | sed 's/,{"name":"entra access token",[^}]*}//')

run passes           "$ok"  "$all_pass" 0 serves 0 'real-entra lane: ok'
run prints-the-sub   "$ok"  "$all_pass" 0 serves 0 '"sub":"repo:o@1/r@2:environment:real-entra"'
run fetch-fails      fail   "$all_pass" 0 serves 1 'FAIL: fetching the GitHub OIDC token'
run no-token         '{}'   "$all_pass" 0 serves 1 'FAIL: the GitHub OIDC response holds no token'
run empty-token      '{"value":""}' "$all_pass" 0 serves 1 'FAIL: the GitHub OIDC response holds no token'
run doctor-fails     "$ok"  "$all_pass" 4 serves 1 'FAIL: byward doctor exited 4'
run a-check-warns    "$ok"  "$warn"     0 serves 1 'doctor check "entra idtyp claim" is warn, want pass'
run a-check-missing  "$ok"  "$missing"  0 serves 1 'doctor check "entra access token" is missing, want pass'
run never-ready      "$ok"  "$all_pass" 0 exits  1 'FAIL: the proxy did not become ready'
run check-fails      "$ok"  "$all_pass" 0 check-fails 1 'FAIL: byward check --offline'

out=$(env -i PATH="$PATH" sh "$script" 2>&1) && code=0 || code=$?
if [ "$code" -ne 1 ] || ! printf '%s\n' "$out" | grep -q 'the job needs permissions: id-token: write'; then
  echo "FAIL no-id-token-permission: exit $code, output: $out"
  failures=$((failures + 1))
fi

if [ "$failures" -ne 0 ]; then
  echo "real-entra run.sh: $failures failure(s)"
  exit 1
fi
echo "real-entra run.sh: ok"
