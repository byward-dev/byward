package audit

import (
	"testing"

	"github.com/byward-dev/byward/internal/testutil/reftable"
)

// The events table in the observability reference lists every audit event, in the order audit.go
// declares them; when, outcomes, rate limiting and the OCSF mapping are written by hand.
func TestTheEventsReferenceIsCurrent(t *testing.T) {
	names := eventNames(t)
	if len(names) < 20 {
		t.Fatalf("found %d event names, want every one of the const block", len(names))
	}
	reftable.Sync(t, "../../docs/reference/observability.md", "### Events and OCSF mapping", 0, names, func(name string, old []string) []string {
		row := []string{"`" + name + "`", reftable.Todo, reftable.Todo, reftable.Todo, reftable.Todo}
		if len(old) == len(row) {
			copy(row[1:], old[1:])
		}
		return row
	})
}
