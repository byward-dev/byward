#!/bin/sh
# Runs inside the node container with --network none: the reference server, byward and the
# conformance CLI share one loopback, so the CLI targets http://127.0.0.1:PORT/mcp (the
# dns-rebinding scenario needs a localhost URL). Usage: inside.sh <revision>...
set -eu
ref_port=39301
proxy_port=39302
ref_url="http://127.0.0.1:$ref_port/mcp"
proxy_url="http://127.0.0.1:$proxy_port/mcp"
# ADR-0024 §15 gives test:integration 10 minutes: the runs share an 8-minute budget (the CI job has 12,
# for install and build), so adding a revision cannot push the lane past it, and the logs and summary
# still appear when a run times out. Healthy runs take seconds.
budget=480
[ "$#" -gt 0 ] || { echo "usage: inside.sh <revision>..." >&2; exit 2; }
per_run=$((budget / (2 * $#)))
cd /work
pids=
# shellcheck disable=SC2329 # invoked by the EXIT trap
stop_all() {
  for pid in $pids; do kill "$pid" 2>/dev/null || true; done
  for pid in $pids; do wait "$pid" 2>/dev/null || true; done
  pids=
}
trap stop_all EXIT

# up reports whether something answers on a port within the given seconds (no curl in the image).
up() { # $1 port, $2 seconds
  node -e '
    const [port, secs] = process.argv.slice(1);
    const deadline = Date.now() + secs * 1000;
    (function poll() {
      require("net").connect(+port, "127.0.0.1").on("connect", () => process.exit(0)).on("error", () => {
        if (Date.now() > deadline) process.exit(1);
        setTimeout(poll, 250);
      });
    })();' "$1" "$2"
}

# start runs a fresh reference server and proxy, so every run sees the same server state.
start() { # $1 log suffix
  # node itself, with tsx as a loader, so the pid stopped below is the process holding the port
  # (the tsx wrapper could exit and leave its child serving the old state).
  (cd src/examples/servers/typescript && PORT=$ref_port exec node --import tsx everything-server.ts) \
    >> reference.log 2>&1 &
  pids="$pids $!"
  BYWARD_INSECURE_NO_AUTH=true \
  BYWARD_PUBLIC_URL="$proxy_url" \
  BYWARD_LISTEN="127.0.0.1:$proxy_port" \
  BYWARD_UPSTREAM_URL="$ref_url" \
    ./byward >> proxy.log 2>&1 &
  pids="$pids $!"
  up "$ref_port" 30 || { echo "reference server did not start on $ref_port for $1 (see reference.log)" >&2; exit 1; }
  up "$proxy_port" 30 || { echo "byward did not start on $proxy_port for $1 (see proxy.log)" >&2; exit 1; }
}

# run one CLI pass against a fresh pair; a server that is down afterwards is recorded for compare.sh.
run() { # $1 direct|proxy, $2 revision, $3 url, rest: extra CLI flags
  mode=$1 rev=$2 url=$3
  shift 3
  echo "=== $mode $rev" >> reference.log
  echo "=== $mode $rev" >> proxy.log
  start "$mode $rev"
  set +e
  # Bounded (coreutils timeout; exit 124), so a hung scenario fails instead of holding CI.
  timeout "$per_run" node src/dist/index.js server --requirements "$rev" --url "$url" \
    -o "results/$mode/$rev" "$@" > "results/$mode-$rev.txt" 2>&1
  echo $? > "results/$mode-$rev.exit"
  set -e
  # A server that died mid-run makes its checks fail for the wrong reason; say so (compare.sh fails).
  up "$ref_port" 2 || echo "reference server down after the $mode run" >> "results/died-$rev"
  up "$proxy_port" 2 || echo "byward down after the $mode run" >> "results/died-$rev"
  stop_all
  # The next run must not reach this run's servers: both ports have to be free again.
  for port in $ref_port $proxy_port; do
    tries=0
    while up "$port" 0; do
      tries=$((tries + 1))
      [ "$tries" -lt 20 ] || { echo "port $port still answers after the $mode $rev servers stopped" >&2; exit 1; }
      sleep 0.25
    done
  done
}

rm -rf results reference.log proxy.log && mkdir results
for rev in "$@"; do
  run direct "$rev" "$ref_url" --expected-failures "baseline-$rev.yml"
  run proxy "$rev" "$proxy_url"
done
