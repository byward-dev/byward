#!/bin/sh
# The Go tests that read this repository's docs: what a docs-only change can break. CI runs these in
# place of the whole `test` task when a change is docs-only (.github/workflows/ci.yml, `changes`).
# A test that starts reading docs/ or a *.md file belongs in this list too.
# Fails when any listed test did not run and pass, so a renamed test cannot drop out unseen.
set -eu

tests='
internal/audit TestTheEventsReferenceIsCurrent
internal/broker TestTheDocumentedKeyRetirementPeriodCoversEveryRefreshableGrant
internal/config TestEveryBYWARDNameInTheCodeAndDocsIsASetting
internal/config TestReferenceIsCurrent
internal/doclinks TestEveryRelativeLinkInTheMarkdownResolves
internal/doclinks TestEveryPageTheSiteLinksToExists
internal/doctor TestTheChecksReferenceIsCurrent
internal/metrics TestTheMetricsReferenceIsCurrent
internal/server TestTheDocumentedIdPAlertLabelsAreTheExportedOnes
internal/server TestTheDocumentedUpstreamRefusalLabelsAreTheExportedOnes
internal/server TestTheAlertRulesInTheDocsQueryExportedMetrics
internal/server TestTheDocumentedAlertRulesUseExportedLabelsAndValues
internal/testutil/clientsim TestTheMatrixDocAndTheProfilesNameTheSameSimulatedCells
internal/testutil/fixtures TestTheRepositoryHoldsNoForbiddenIdentifiersAndItsTestDataNoRealEmails
'

names=$(printf '%s\n' "$tests" | awk 'NF { print $2 }' | paste -sd '|' -)
pkgs=$(printf '%s\n' "$tests" | awk 'NF { print "./" $1 "/" }' | sort -u | tr '\n' ' ')
out=$(mktemp)
trap 'rm -f "$out"' EXIT
status=0
# shellcheck disable=SC2086 # pkgs is a list of package paths, split on purpose
go test -race -v -run "^($names)\$" $pkgs > "$out" 2>&1 || status=$?
grep -E '^(--- (FAIL|PASS)|FAIL|ok)' "$out" || true
missing=0
for name in $(printf '%s\n' "$tests" | awk 'NF { print $2 }'); do
  if ! grep -q "^--- PASS: $name " "$out"; then
    echo "test-docs: $name did not run and pass" >&2
    missing=$((missing + 1))
  fi
done
if [ "$status" -ne 0 ] || [ "$missing" -ne 0 ]; then
  cat "$out" >&2
  exit 1
fi
echo "test-docs: all $(printf '%s\n' "$tests" | awk 'NF' | wc -l | tr -d ' ') docs tests passed"
