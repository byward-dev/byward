#!/bin/sh
# Runs inside the node container with --network none: the reference server, byward and the
# conformance CLI share one loopback, so the CLI targets http://127.0.0.1:PORT/mcp (the
# dns-rebinding scenario needs a localhost URL). Usage: inside.sh <revision>...
set -eu
ref_port=39301
proxy_port=39302
ref_url="http://127.0.0.1:$ref_port/mcp"
proxy_url="http://127.0.0.1:$proxy_port/mcp"
cd /work
pids=
# shellcheck disable=SC2329 # invoked by the EXIT trap
stop_all() { for pid in $pids; do kill "$pid" 2>/dev/null || true; done; }
trap stop_all EXIT

(cd src/examples/servers/typescript && PORT=$ref_port exec node_modules/.bin/tsx everything-server.ts) \
  > reference.log 2>&1 &
pids="$pids $!"
BYWARD_INSECURE_NO_AUTH=true \
BYWARD_PUBLIC_URL="$proxy_url" \
BYWARD_LISTEN="127.0.0.1:$proxy_port" \
BYWARD_UPSTREAM_URL="$ref_url" \
  ./byward > proxy.log 2>&1 &
pids="$pids $!"

# Wait until something answers on the port (no curl in the image; node is).
wait_up() {
  node -e '
    const [port, name] = process.argv.slice(1);
    const deadline = Date.now() + 30000;
    (function poll() {
      require("net").connect(+port, "127.0.0.1").on("connect", () => process.exit(0)).on("error", () => {
        if (Date.now() > deadline) { console.error(name + " did not start on " + port); process.exit(1); }
        setTimeout(poll, 250);
      });
    })();' "$1" "$2"
}
wait_up "$ref_port" "reference server (see reference.log)"
wait_up "$proxy_port" "byward (see proxy.log)"

rm -rf results && mkdir results
for rev in "$@"; do
  set +e
  node src/dist/index.js server --requirements "$rev" --url "$ref_url" \
    -o "results/direct/$rev" --expected-failures "baseline-$rev.yml" > "results/direct-$rev.txt" 2>&1
  echo $? > "results/direct-$rev.exit"
  node src/dist/index.js server --requirements "$rev" --url "$proxy_url" \
    -o "results/proxy/$rev" > "results/proxy-$rev.txt" 2>&1
  echo $? > "results/proxy-$rev.exit"
  set -e
done
