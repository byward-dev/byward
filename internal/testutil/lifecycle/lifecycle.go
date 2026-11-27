// Package lifecycle is the matrix every component whose work outlives a step is tested on (#672):
// each way a request can end, crossed with each state its work can be in. A component's test lists
// every cell, as one it runs, one that cannot happen, one it knows is wrong, or one it does not run,
// each with why; Run fails a cell not listed, so a new ending or state fails every matrix until each
// component classifies it.
package lifecycle

import (
	"fmt"
	"testing"
)

// An Ending is a way a request ends.
type Ending int

const (
	Completes    Ending = iota // the work finishes and is answered
	ClientGone                 // the MCP client goes away: its connection or request context ends
	UpstreamGone               // the upstream or its process goes away: exit, crash, reset, closed pipe
	Timeout                    // a bound the component sets runs out
	Shutdown                   // the proxy shuts down
	endings                    // the count; a new Ending goes above it
)

// Endings are every Ending, in order.
var Endings = upTo(endings)

var endingNames = [endings]string{
	Completes: "completes", ClientGone: "client gone", UpstreamGone: "upstream gone", Timeout: "timeout", Shutdown: "shutdown",
}

func (e Ending) String() string { return endingNames[e] }

// A State is where a request's work is when it ends.
type State int

const (
	NotStarted       State = iota // nothing sent to the upstream yet
	BodyInFlight                  // the request body is still being sent
	AwaitingHeaders               // the request is sent; no response has started
	After1xx                      // an interim (1xx) response was sent; the final one has not started
	Streaming                     // the response has started; its body is still in flight
	TrailerPending                // the response body is sent; its trailers are not
	UpgradeRequested              // the client asked for a protocol upgrade
	states                        // the count; a new State goes above it
)

// States are every State, in order.
var States = upTo(states)

var stateNames = [states]string{
	NotStarted: "not started", BodyInFlight: "body in flight", AwaitingHeaders: "awaiting headers", After1xx: "after 1xx",
	Streaming: "streaming", TrailerPending: "trailer pending", UpgradeRequested: "upgrade requested",
}

func (s State) String() string { return stateNames[s] }

// upTo is every value below n, so Endings and States cannot leave out a constant declared above
// their count.
func upTo[T ~int](n T) []T {
	out := make([]T, n)
	for i := range out {
		out[i] = T(i)
	}
	return out
}

// A Cell is one (Ending, State) pair.
type Cell struct {
	Ending Ending
	State  State
}

func (c Cell) String() string { return c.Ending.String() + "/" + c.State.String() }

// A Case is what a component's matrix says of one cell.
type Case struct {
	run      func(t *testing.T)
	why      string
	issue    string
	residual bool
}

// Pinned is a cell the matrix runs: run drives the work to the state, ends it, and asserts what the
// client gets, what is logged, and that nothing is left held.
func Pinned(run func(t *testing.T)) Case { return Case{run: run} }

// Unreachable is a cell that cannot happen, and why.
func Unreachable(why string) Case { return Case{why: why} }

// NotRun is a cell that can happen but this matrix does not run, and why (another test pins it, or
// it takes a bound no test should wait out).
func NotRun(why string) Case { return Case{why: why} }

// KnownResidual is a cell whose behaviour is known to be wrong, with the issue that fixes it and why;
// run pins today's behaviour, so the fix flips the cell to Pinned.
func KnownResidual(issue, why string, run func(t *testing.T)) Case {
	return Case{run: run, why: why, issue: issue, residual: true}
}

// Run runs every cell m pins as a subtest named by the cell, and fails each cell m leaves out or
// does not say why of.
func Run(t *testing.T, m map[Cell]Case) {
	t.Helper()
	for _, p := range problems(m) {
		t.Error(p)
	}
	for _, e := range Endings {
		for _, s := range States {
			c := Cell{Ending: e, State: s}
			if k := m[c]; k.run != nil {
				name := c.String()
				if k.residual {
					name = fmt.Sprintf("%s (known residual %s)", name, k.issue)
				}
				t.Run(name, k.run)
			}
		}
	}
}

// problems are the cells m leaves out, those it marks Unreachable, NotRun or KnownResidual without
// saying why, and the KnownResidual cells that name no issue.
func problems(m map[Cell]Case) []string {
	var out []string
	for _, e := range Endings {
		for _, s := range States {
			c := Cell{Ending: e, State: s}
			switch k, ok := m[c]; {
			case !ok:
				out = append(out, fmt.Sprintf("cell %s is not classified: pin it, or mark it Unreachable, NotRun or KnownResidual with why", c))
			case (k.run == nil || k.residual) && k.why == "":
				out = append(out, fmt.Sprintf("cell %s: an Unreachable, NotRun or KnownResidual cell says why", c))
			case k.residual && k.issue == "":
				out = append(out, fmt.Sprintf("cell %s: a KnownResidual cell names the issue that fixes it", c))
			}
		}
	}
	return out
}
