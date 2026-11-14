package doctor

import (
	"slices"
	"testing"

	"github.com/byward-dev/byward/internal/testutil/reftable"
)

// The checks table in the commands reference lists every check, in order, with its class from the
// code; what each one passes on is written by hand.
func TestTheChecksReferenceIsCurrent(t *testing.T) {
	var names []string
	class := map[string]Class{}
	for _, c := range Checks() {
		names = append(names, c.Name())
		class[c.Name()] = c.Class()
	}
	table := reftable.Table{Path: "../../docs/reference/commands.md", Heading: "### Checks", KeyCol: 1, Package: "./internal/doctor/"}
	table.Sync(t, names, func(name string, old []string) []string {
		row := []string{"`" + string(class[name]) + "`", name, reftable.Todo}
		if len(old) == len(row) {
			row[2] = old[2]
		}
		return row
	})
}

// Every check has its own name, so a report and the reference name each one once.
func TestEveryCheckHasItsOwnName(t *testing.T) {
	seen := map[string]bool{}
	for _, c := range Checks() {
		if seen[c.Name()] {
			t.Errorf("two checks are named %q", c.Name())
		}
		seen[c.Name()] = true
	}
}

// Checks hands out a copy: changing it changes no later list.
func TestChecksIsACopy(t *testing.T) {
	want := slices.Clone(Checks())
	got := Checks()
	got[0], got[1] = CheckAuthentication, CheckAuthentication
	if !slices.Equal(Checks(), want) {
		t.Fatal("Checks() changed after a caller changed its copy")
	}
}
