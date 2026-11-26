package broker

import (
	"net/http/httptest"
	"testing"

	"github.com/byward-dev/byward/internal/testutil/hostfamilies"
)

// The consent page's CSRF check takes exactly one Origin, the public URL's, decided for every host
// family as pinned in testdata/hostdecisions.golden: only the origin in
// testdata/hostdecisions.allowed passes, so a check that folds a spelling into it fails by name (#656).
func TestTheConsentOriginCheckDecidesEveryHostFamilyAsPinned(t *testing.T) {
	b := &Broker{cfg: Config{Origin: "https://mcp.example.com"}}
	hostfamilies.Run(t, "internal/broker", []hostfamilies.Column{
		{Name: "consent Origin", Probes: hostfamilies.URLProbes("", "https", "http"), Judge: func(in string) (bool, string) {
			r := httptest.NewRequest("POST", "/consent", nil)
			r.Header.Set("Origin", in)
			return b.fromConsentPage(r), "not the public URL's origin"
		}},
	})
}
