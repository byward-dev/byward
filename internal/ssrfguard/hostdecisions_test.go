package ssrfguard

import (
	"net/url"
	"testing"

	"github.com/byward-dev/byward/internal/testutil/hostfamilies"
)

// The guard's URL rule, checked before any dial, decides every host family as pinned in
// testdata/hostdecisions.golden, and passes only the URLs in testdata/hostdecisions.allowed, so a
// guard that would fetch a new form fails by name (#656). The dial's address check is not a host
// form's: it is ssrfguard's own tests'.
func TestTheGuardsURLRuleDecidesEveryHostFamilyAsPinned(t *testing.T) {
	hostfamilies.Run(t, "internal/ssrfguard", []hostfamilies.Column{
		{Name: "SSRF guard URL", Probes: hostfamilies.URLProbes("/jwks.json", "https", "http"), Judge: func(in string) (bool, string) {
			u, err := url.Parse(in)
			switch {
			case err != nil:
				return false, "not a URL"
			case !Fetchable(u):
				return false, "not an https URL on port 443"
			}
			return true, ""
		}},
	})
}
