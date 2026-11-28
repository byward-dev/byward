package host

import (
	"testing"

	"github.com/byward-dev/byward/internal/testutil/hostfamilies"
)

// LoopbackAsWritten, as the no-auth check asks it of an allowed host as stored (Hostname, then
// LoopbackAsWritten), decides every host family as pinned in testdata/hostdecisions.golden, and
// calls loopback only the hosts in testdata/hostdecisions.allowed, so a host newly read as loopback
// fails by name (#656). It pins the shared helper as the allowed-hosts fence calls it (Hostname
// lower-cases first); the decisions it feeds (the no-auth check, the http public URL and issuer on
// loopback, a discovered endpoint in --dev) have columns of their own.
func TestLoopbackAsWrittenDecidesEveryHostFamilyAsPinned(t *testing.T) {
	hostfamilies.Run(t, "internal/host", hostColumns(t))
}

// FuzzHostDecisions fuzzes the host each of these checks reads, beyond the golden's families (#661):
// see hostfamilies.Fuzz for what it fails.
func FuzzHostDecisions(f *testing.F) { hostfamilies.Fuzz(f, hostColumns, Split, Serialize) }

// hostColumns are the checks the golden test and FuzzHostDecisions judge.
func hostColumns(testing.TB) []hostfamilies.Column {
	return []hostfamilies.Column{
		{Name: "loopback as written", Probes: hostfamilies.HostProbes(), Judge: func(in string) (bool, string) {
			return LoopbackAsWritten(Hostname(in)), "not loopback"
		}}, // not a list: all of 127.0.0.0/8 is loopback
	}
}
