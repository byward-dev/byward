package host

import (
	"testing"

	"github.com/byward-dev/byward/internal/testutil/hostfamilies"
)

// LoopbackAsWritten, which the no-auth check and the --dev issuer ask of a host as stored, decides
// every host family as pinned in testdata/hostdecisions.golden, and calls loopback only the hosts in
// testdata/hostdecisions.allowed, so a host newly read as loopback fails by name (#656).
func TestLoopbackAsWrittenDecidesEveryHostFamilyAsPinned(t *testing.T) {
	hostfamilies.Run(t, "internal/host", []hostfamilies.Column{
		{Name: "loopback as written", Probes: hostfamilies.HostProbes(), Judge: func(in string) (bool, string) {
			return LoopbackAsWritten(Hostname(in)), "not loopback"
		}},
	})
}
