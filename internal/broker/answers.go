package broker

import (
	"sync"
	"time"
)

// maxFlows bounds the answered flows remembered; a full table forgets the one recorded last.
const maxFlows = 10000

// answers records which flows were answered, so a flow is single-use: the same answer again (a
// double click) repeats the first response, a different one is refused. In memory, per replica: a
// second replica accepting the same Allow produces the same IdP request, and the IdP login cookie
// and the code stay single-use.
//
// Anyone can mint flows, so a full table never refuses: it forgets the flow recorded last, which
// under a flood is the flood's own newest answer, so answers given before the flood are kept
// whenever their pages were shown. A forgotten flow can be answered again, either way.
type answers struct {
	mu   sync.Mutex
	seen map[string]answer
	next uint64 // record order
}

type answer struct {
	allow   bool
	expires time.Time
	seq     uint64
}

func newAnswers() *answers { return &answers{seen: map[string]answer{}} }

// prior returns the recorded answer to a flow, if any.
func (a *answers) prior(id string, now time.Time) (allow, ok bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	p, ok := a.seen[id]
	if !ok || !p.expires.After(now) {
		return false, false
	}
	return p.allow, true
}

// record stores the answer and reports whether it may proceed: ok for a first answer or the same
// one again, first only for the answer that recorded the flow (one audit record per decision, even
// when answers arrive together). evicted reports that the table was full and an unexpired flow was
// forgotten.
func (a *answers) record(id string, allow bool, now, expires time.Time) (ok, first, evicted bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if prev, seen := a.seen[id]; seen && prev.expires.After(now) {
		return prev.allow == allow, false, false
	}
	if len(a.seen) >= maxFlows {
		var latest string
		for k, v := range a.seen {
			if !v.expires.After(now) {
				delete(a.seen, k)
			} else if latest == "" || v.seq > a.seen[latest].seq {
				latest = k
			}
		}
		if len(a.seen) >= maxFlows {
			delete(a.seen, latest)
			evicted = true
		}
	}
	a.next++
	a.seen[id] = answer{allow: allow, expires: expires, seq: a.next}
	return true, true, evicted
}
