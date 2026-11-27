package lifecycle

import (
	"slices"
	"strings"
	"testing"
)

// full is a matrix with every cell unreachable, for a reason.
func full() map[Cell]Case {
	m := map[Cell]Case{}
	for _, e := range Endings {
		for _, s := range States {
			m[Cell{Ending: e, State: s}] = Unreachable("why")
		}
	}
	return m
}

// A matrix fails each cell it leaves out, and each it marks unpinned without why, by the cell's
// name; one that classifies every cell, with why, passes.
func TestAMatrixFailsEachCellItDoesNotClassify(t *testing.T) {
	if p := problems(full()); len(p) != 0 {
		t.Fatalf("a full matrix: %q, want none", p)
	}
	for name, tc := range map[string]struct {
		change func(map[Cell]Case)
		want   string
	}{
		"a cell left out":         {func(m map[Cell]Case) { delete(m, Cell{Ending: Timeout, State: Streaming}) }, "cell timeout/streaming is not classified"},
		"unreachable without why": {func(m map[Cell]Case) { m[Cell{Ending: Shutdown, State: After1xx}] = Unreachable("") }, "cell shutdown/after 1xx: an Unreachable"},
		"not run without why":     {func(m map[Cell]Case) { m[Cell{Ending: Completes, State: NotStarted}] = NotRun("") }, "cell completes/not started: an Unreachable"},
		"known residual without why": {func(m map[Cell]Case) {
			m[Cell{Ending: ClientGone, State: BodyInFlight}] = KnownResidual("#1", "", func(*testing.T) {})
		}, "cell client gone/body in flight: an Unreachable"},
		"known residual without an issue": {func(m map[Cell]Case) {
			m[Cell{Ending: Timeout, State: Streaming}] = KnownResidual("", "why", func(*testing.T) {})
		}, "cell timeout/streaming: a KnownResidual cell names the issue"},
	} {
		t.Run(name, func(t *testing.T) {
			m := full()
			tc.change(m)
			if p := problems(m); len(p) != 1 || !strings.HasPrefix(p[0], tc.want) {
				t.Errorf("problems %q, want one starting %q", p, tc.want)
			}
		})
	}
}

// Every ending and state has a name, so a new one added to the enumerations names its cells, and
// Endings and States list every one.
func TestEveryEndingAndStateHasAName(t *testing.T) {
	var names []string
	for _, e := range Endings {
		names = append(names, e.String())
	}
	for _, s := range States {
		names = append(names, s.String())
	}
	if want := append(endingNames[:], stateNames[:]...); !slices.Equal(names, want) {
		t.Errorf("names %q; want %q", names, want)
	}
	if slices.Contains(names, "") || len(slices.Compact(slices.Sorted(slices.Values(names)))) != len(names) {
		t.Errorf("names %q: want each one, distinct", names)
	}
}

// Run runs every Pinned and KnownResidual cell, each once, and no other.
func TestRunRunsEveryCellThatHasARun(t *testing.T) {
	m := full()
	ran := map[Cell]int{}
	pinned, residual := Cell{Ending: Completes, State: Streaming}, Cell{Ending: Shutdown, State: After1xx}
	m[pinned] = Pinned(func(*testing.T) { ran[pinned]++ })
	var residualName string
	m[residual] = KnownResidual("#1", "why", func(t *testing.T) { ran[residual]++; residualName = t.Name() })
	Run(t, m)
	if len(ran) != 2 || ran[pinned] != 1 || ran[residual] != 1 {
		t.Errorf("ran %v; want the pinned and the residual cell once each", ran)
	}
	if !strings.HasSuffix(residualName, "/shutdown/after_1xx_(known_residual_#1)") {
		t.Errorf("the residual cell ran as %q; want it named by its cell and its issue", residualName)
	}
}
