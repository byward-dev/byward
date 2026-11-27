package registration

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/byward-dev/byward/internal/store/memory"
	"github.com/byward-dev/byward/internal/testutil/lifecycle"
)

// lookup is one Client call's answer.
type lookup struct {
	client Client
	err    error
}

// lookupIn runs Client(ctx, cimdID) in the background.
func lookupIn(r *CIMDRegistry, ctx context.Context) <-chan lookup {
	got := make(chan lookup, 1)
	go func() {
		c, err := r.Client(ctx, cimdID)
		got <- lookup{c, err}
	}()
	return got
}

// answered waits for a lookup's answer and fails t unless it is a client (want nil) or wraps want.
func answered(t *testing.T, got <-chan lookup, want error) {
	t.Helper()
	select {
	case l := <-got:
		if want == nil && (l.err != nil || l.client == nil) || want != nil && (!errors.Is(l.err, want) || l.client != nil) {
			t.Errorf("Client = %v, %v; want %v", l.client, l.err, cmpWant(want))
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the lookup never returned")
	}
}

func cmpWant(want error) any {
	if want == nil {
		return "a client"
	}
	return want
}

// idle fails t unless the registry has let go of every fetch: none in flight, no slot held (so
// the leader's goroutine has finished: it deletes its call before it releases its waiters).
func idle(t *testing.T, r *CIMDRegistry) {
	t.Helper()
	var n, slots int
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(time.Millisecond) {
		r.mu.Lock()
		n, slots = len(r.inflight), len(r.slots)
		r.mu.Unlock()
		if n == 0 && slots == 0 {
			return
		}
	}
	t.Fatalf("the registry still holds %d fetches and %d slots", n, slots)
}

// gated is a registry whose fetches wait for open, closed at the latest when t ends, so no
// leader is left behind; its first reply is rs.
func gated(t *testing.T, rs ...reply) (r *CIMDRegistry, f *fakeFetch, open func()) {
	t.Helper()
	f = &fakeFetch{replies: map[string][]reply{cimdID: rs}, gate: make(chan struct{})}
	var once atomic.Bool
	open = func() {
		if once.CompareAndSwap(false, true) {
			close(f.gate)
		}
	}
	t.Cleanup(open)
	return newReg(f, newClock(), nil, nil), f, open
}

// The CIMD registry's lifecycle matrix (#672): every way a lookup can end, crossed with every
// state the shared fetch can be in, pins what each lookup is answered and that the registry lets
// go of the fetch: nothing in flight, no slot held, the leader's goroutine done. UpstreamGone is
// the metadata host here (CONTEXT.md: the upstream is the MCP server); Timeout is the fetch's
// bound, which the SSRF guard sets.
func TestTheCIMDFetchLifecycleMatrix(t *testing.T) {
	const (
		noBody      = "a CIMD fetch is a GET with no body"
		no1xx       = "Get returns only the final response; the transport absorbs a 1xx"
		noTrailer   = "the document is read whole; trailers are ignored"
		noUpgrade   = "a JSON GET, never upgraded"
		oneGet      = "the body is read inside the one Get call, which the registry cannot tell from awaiting its headers: TestAStallingServerTimesOutWithoutLeakingTheQuery (ssrfguard) pins a stalled body"
		noPreBound  = "nothing bounds a lookup before its fetch; the dial is inside the fetch's own bound"
		definiteNow = "a definite failure inside the retry gap is answered from the attempt log, with no fetch: TestCIMDCacheFollowsTheDocumentAndTheDraft pins it"
	)
	at := func(e lifecycle.Ending, s lifecycle.State) lifecycle.Cell { return lifecycle.Cell{Ending: e, State: s} }
	m := map[lifecycle.Cell]lifecycle.Case{}
	for _, e := range lifecycle.Endings {
		m[at(e, lifecycle.BodyInFlight)] = lifecycle.Unreachable(noBody)
		m[at(e, lifecycle.After1xx)] = lifecycle.Unreachable(no1xx)
		m[at(e, lifecycle.Streaming)] = lifecycle.NotRun(oneGet)
		m[at(e, lifecycle.TrailerPending)] = lifecycle.Unreachable(noTrailer)
		m[at(e, lifecycle.UpgradeRequested)] = lifecycle.Unreachable(noUpgrade)
	}
	m[at(lifecycle.Timeout, lifecycle.NotStarted)] = lifecycle.Unreachable(noPreBound)
	m[at(lifecycle.UpstreamGone, lifecycle.NotStarted)] = lifecycle.NotRun(definiteNow)

	// Answered without a fetch: from a fresh copy, or refused inside the retry gap. A full set of
	// fetch slots is the third way, which TestFetchesInFlightAreCapped pins.
	m[at(lifecycle.Completes, lifecycle.NotStarted)] = lifecycle.Pinned(func(t *testing.T) {
		t.Run("a fresh copy", func(t *testing.T) {
			f, c := &fakeFetch{replies: map[string][]reply{cimdID: {ok("max-age=3600")}}}, newClock()
			r := newReg(f, c, nil, nil)
			answered(t, lookupIn(r, context.Background()), nil)
			c.Advance(MinCIMDRetry + time.Second) // past the retry gap, inside max-age: only a fresh copy answers without a fetch
			answered(t, lookupIn(r, context.Background()), nil)
			if n := f.calls.Load(); n != 1 {
				t.Errorf("%d fetches; want the copy to answer the second lookup", n)
			}
			idle(t, r)
		})
		t.Run("inside the retry gap", func(t *testing.T) {
			r, f, open := gated(t, transient())
			open()
			answered(t, lookupIn(r, context.Background()), ErrUnavailable)
			answered(t, lookupIn(r, context.Background()), ErrUnavailable)
			if n := f.calls.Load(); n != 1 {
				t.Errorf("%d fetches; want the second lookup refused without one", n)
			}
			idle(t, r)
		})
	})

	for _, e := range lifecycle.ContextEndings {
		// A lookup whose request has already ended is answered unavailable at once; its fetch is
		// started all the same and fills the cache for the next request (#672: kept as it is).
		m[at(e.Ending, lifecycle.NotStarted)] = lifecycle.Pinned(func(t *testing.T) {
			r, f, open := gated(t, ok("max-age=3600"))
			ctx, end := e.Start(context.Background())
			end()
			answered(t, lookupIn(r, ctx), ErrUnavailable)
			waitForFetches(t, f, 1)
			open()
			idle(t, r)
			answered(t, lookupIn(r, context.Background()), nil)
			if n := f.calls.Load(); n != 1 {
				t.Errorf("%d fetches; want the detached one to have filled the cache", n)
			}
		})
		// Whichever lookup's request ends, leader or a joined waiter, it leaves at once; the
		// shared fetch finishes for the other, and the registry lets it go.
		m[at(e.Ending, lifecycle.AwaitingHeaders)] = lifecycle.Pinned(func(t *testing.T) {
			for _, leaderEnds := range []bool{true, false} {
				name := map[bool]string{true: "its leader's request", false: "a waiter's request"}[leaderEnds]
				t.Run(name, func(t *testing.T) {
					r, _, open := gated(t, ok("max-age=3600"))
					ctx, end := e.Start(context.Background())
					leaderCtx, waiterCtx := ctx, context.Background()
					if !leaderEnds {
						leaderCtx, waiterCtx = context.Background(), ctx
					}
					leader := lookupIn(r, leaderCtx)
					waitForFetches(t, r.cfg.Fetch.(*fakeFetch), 1)
					waiter := lookupIn(r, waiterCtx)
					waitForWaiters(t, r, 1)
					end()
					gone, stays := leader, waiter
					if !leaderEnds {
						gone, stays = waiter, leader
					}
					answered(t, gone, ErrUnavailable) // before the fetch is done
					open()
					answered(t, stays, nil)
					idle(t, r)
				})
			}
		})
	}

	// shared runs a leader and a joined waiter on one fetch that replies rep, and fails t unless
	// both are answered want and the registry lets the fetch go.
	shared := func(t *testing.T, rep reply, want error) *fakeFetch {
		t.Helper()
		r, f, open := gated(t, rep)
		leader := lookupIn(r, context.Background())
		waitForFetches(t, f, 1)
		waiter := lookupIn(r, context.Background())
		waitForWaiters(t, r, 1)
		open()
		answered(t, leader, want)
		answered(t, waiter, want)
		idle(t, r)
		return f
	}
	// The shared fetch answers its leader and every waiter alike.
	m[at(lifecycle.Completes, lifecycle.AwaitingHeaders)] = lifecycle.Pinned(func(t *testing.T) {
		if n := shared(t, ok("max-age=3600"), nil).calls.Load(); n != 1 {
			t.Errorf("%d fetches; want one shared", n)
		}
	})
	// The metadata host fails the shared fetch: every lookup gets its outcome. A transient
	// failure is unavailable; a refused or invalid document refuses the client.
	m[at(lifecycle.UpstreamGone, lifecycle.AwaitingHeaders)] = lifecycle.Pinned(func(t *testing.T) {
		for name, tc := range map[string]struct {
			reply reply
			want  error
		}{
			"a transient failure": {transient(), ErrUnavailable},
			"a refused document":  {gone(), ErrMetadataRefused},
			"an invalid document": {invalidDoc(), ErrMetadataRefused},
		} {
			t.Run(name, func(t *testing.T) { shared(t, tc.reply, tc.want) })
		}
		t.Run("a fetch that panics", func(t *testing.T) {
			calls := new(atomic.Int32)
			r := NewCIMDRegistry(CIMDConfig{Fetch: panicFetch{calls}, JTI: NewStoreJTICache(memory.New()), Now: newClock().Now})
			answered(t, lookupIn(r, context.Background()), ErrUnavailable)
			idle(t, r)
		})
	})
	// The fetch's bound runs out (the SSRF guard's timeout, a transient failure): every lookup
	// gets unavailable. The bound itself is the guard's, in real time, which its own test pins.
	m[at(lifecycle.Timeout, lifecycle.AwaitingHeaders)] = lifecycle.Pinned(func(t *testing.T) {
		shared(t, reply{err: context.DeadlineExceeded}, ErrUnavailable)
	})
	lifecycle.Run(t, m)
}
