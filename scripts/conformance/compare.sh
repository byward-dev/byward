#!/bin/sh
# Compares the conformance results of the direct and proxied runs (ADR-0024 §4a). Usage:
#   compare.sh <results dir> <expectations dir> <revision>...
# For each revision: the direct run must have passed its baseline, it must have produced exactly the
# scenarios in <expectations dir>/scenarios-<revision>.txt, and every (scenario, check id, status)
# through the proxy must equal the direct run. Writes <results dir>/summary.md; exits 1 on any failure.
set -eu
# Bytewise ordering everywhere: the committed scenario lists are C-sorted.
export LC_ALL=C
out=$1 expect=$2
shift 2
status=0
: > "$out/failures.txt"
# failed reports a gate that failed: on stderr, and in the summary (a red run never shows only "yes").
failed() {
  echo "conformance: FAIL: $*" >&2
  printf -- '- %s\n' "$*" >> "$out/failures.txt"
  status=1
}

# Timestamps, logs and messages (which name ports) are dropped. A checks.json jq cannot read fails
# the revision (status=1), and the summary is still written.
normalise() { # $1 results dir, $2 output TSV
  : > "$2.unsorted"
  for d in "$1"/server-*; do
    [ -d "$d" ] || continue
    scenario=$(basename "$d" | sed -E 's/^server-//; s/-[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9-]+Z$//')
    jq -r --arg s "$scenario" '.[] | [$s, .id, .status] | @tsv' "$d/checks.json" >> "$2.unsorted" \
      || failed "cannot read $d/checks.json"
  done
  sort "$2.unsorted" > "$2"
  rm -f "$2.unsorted"
}

# why explains a CLI exit code: 124 is inside.sh's timeout.
why() {
  case "$1" in
    124) echo "timed out (inside.sh's per-run timeout; a hung scenario?)" ;;
    missing) echo "left no exit file (the run container died before the CLI finished?)" ;;
    *) echo "exited $1" ;;
  esac
}
for rev in "$@"; do
  if [ -s "$out/died-$rev" ]; then
    failed "the reference server or byward exited during $rev ($(tr '\n' ' ' < "$out/died-$rev"));" \
      "its checks failed for that reason. See build/conformance/reference.log and proxy.log"
  fi
  code=$(cat "$out/direct-$rev.exit" 2>/dev/null || echo missing)
  if [ "$code" != 0 ]; then
    failed "$rev direct run $(why "$code"): a new failure, a stale baseline-$rev.yml entry, a CLI" \
      "crash or a timeout (last lines of $out/direct-$rev.txt in the log)"
    tail -n 30 "$out/direct-$rev.txt" >&2 2>/dev/null || true
  fi
  normalise "$out/direct/$rev" "$out/direct-$rev.tsv"
  normalise "$out/proxy/$rev" "$out/proxy-$rev.tsv"
  [ -s "$out/direct-$rev.tsv" ] || {
    failed "$rev produced no checks; see $out/direct-$rev.txt and $out/proxy-$rev.txt (CI artifact conformance-results)"
  }
  # A scenario that silently drops out of both runs would leave the diff below empty.
  { grep -v '^#' "$expect/scenarios-$rev.txt" || true; } > "$out/expected-scenarios-$rev.txt"
  cut -f1 "$out/direct-$rev.tsv" | sort -u > "$out/direct-scenarios-$rev.txt"
  if ! diff "$out/expected-scenarios-$rev.txt" "$out/direct-scenarios-$rev.txt" > "$out/scenarios-diff-$rev.txt"; then
    failed "$rev ran a different set of scenarios than scenarios-$rev.txt (diff in the log: < expected, > ran)"
    cat "$out/scenarios-diff-$rev.txt" >&2
  fi
  if diff "$out/direct-$rev.tsv" "$out/proxy-$rev.tsv" > "$out/diff-$rev.txt"; then
    echo yes > "$out/same-$rev"
  else
    echo no > "$out/same-$rev"
    failed "$rev results through the proxy differ from direct (diff in the log: < direct, > proxy)"
    cat "$out/diff-$rev.txt" >&2
    # The proxy run has no baseline, so its exit code reflects the reference server's own failures;
    # only a timeout or a missing exit file says something about the run itself.
    pcode=$(cat "$out/proxy-$rev.exit" 2>/dev/null || echo missing)
    case "$pcode" in
      124 | missing) echo "  the proxy run $(why "$pcode"); last lines of $out/proxy-$rev.txt:" >&2 ;;
      *) echo "  (the proxy run's exit code is not gated: it has no baseline); last lines of $out/proxy-$rev.txt:" >&2 ;;
    esac
    tail -n 15 "$out/proxy-$rev.txt" >&2 2>/dev/null || true
    echo "  details: $out/proxy-$rev.txt and $out/proxy/$rev/server-<scenario>-*/checks.json (CI artifact conformance-results)" >&2
  fi
done

counts() { awk -F'\t' '$3 == "FAILURE" { f++ } $3 == "WARNING" { w++ } END { printf "%d / %d", f, w }' "$1"; }
{
  echo "| Revision | Scenarios | Checks | FAILURE / WARNING (direct) | FAILURE / WARNING (proxy) | Proxy = direct |"
  echo "|---|---|---|---|---|---|"
  for rev in "$@"; do
    printf '| %s | %s | %s | %s | %s | %s |\n' "$rev" \
      "$(wc -l < "$out/direct-scenarios-$rev.txt" | tr -d ' ')" "$(wc -l < "$out/direct-$rev.tsv" | tr -d ' ')" \
      "$(counts "$out/direct-$rev.tsv")" "$(counts "$out/proxy-$rev.tsv")" "$(cat "$out/same-$rev")"
  done
  if [ "$status" = 0 ]; then
    echo
    echo "All gates passed: baselines, scenario lists, and proxy = direct."
  else
    echo
    echo "**FAILED**"
    cat "$out/failures.txt"
  fi
} > "$out/summary.md"
exit "$status"
