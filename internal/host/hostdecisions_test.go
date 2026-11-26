package host

import (
	"testing"

	"github.com/byward-dev/byward/internal/testutil/hostfamilies"
)

// LoopbackAsWritten, as the no-auth check asks it of an allowed host as stored (Hostname, then
// LoopbackAsWritten), decides every host family as pinned in testdata/hostdecisions.golden, and calls
// loopback only the hosts in testdata/hostdecisions.allowed, so a host newly read as loopback fails by
// name (#656). It pins the shared helper; the decisions it feeds (the no-auth check, the http
// public URL and issuer on loopback, a discovered endpoint in --dev) have columns of their own.
func TestLoopbackAsWrittenDecidesEveryHostFamilyAsPinned(t *testing.T) {
	hostfamilies.Run(t, "internal/host", []hostfamilies.Column{
		{Name: "loopback as written", Probes: hostfamilies.HostProbes(), Judge: func(in string) (bool, string) {
			return LoopbackAsWritten(Hostname(in)), "not loopback"
		}},
	})
}
