package broker

import (
	"net/http/httptest"
	"testing"

	"github.com/byward-dev/byward/internal/host"
	"github.com/byward-dev/byward/internal/testutil/hostfamilies"
)

// The consent page's CSRF check takes exactly one Origin, the public URL's, decided for every host
// family as pinned in testdata/hostdecisions.golden: only the origin in
// testdata/hostdecisions.allowed passes, so a check that folds a spelling into it fails by name (#656).
func TestTheConsentOriginCheckDecidesEveryHostFamilyAsPinned(t *testing.T) {
	hostfamilies.Run(t, "internal/broker", hostColumns(t))
}

// FuzzHostDecisions fuzzes the host each of these checks reads, beyond the golden's families (#661):
// see hostfamilies.Fuzz for what it fails.
func FuzzHostDecisions(f *testing.F) { hostfamilies.Fuzz(f, hostColumns, host.Split, host.Serialize) }

// hostColumns are the checks the golden test and FuzzHostDecisions judge.
func hostColumns(testing.TB) []hostfamilies.Column {
	b := &Broker{cfg: Config{Origin: "https://mcp.example.com"}}
	return []hostfamilies.Column{
		{Name: "consent Origin", Probes: hostfamilies.URLProbes("", "https", "http"), Judge: func(in string) (bool, string) {
			r := httptest.NewRequest("POST", "/consent", nil)
			r.Header.Set("Origin", in)
			return b.fromConsentPage(r), "not the public URL's origin"
		}, Lists: true},
	}
}
