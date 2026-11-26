package ssrfguard

import (
	"context"
	"errors"
	"net"
	"testing"

	"github.com/byward-dev/byward/internal/testutil/hostfamilies"
)

// The guard's URL rule, which Get checks before any dial, decides every host family as pinned in
// testdata/hostdecisions.golden, and lets only the URLs in testdata/hostdecisions.allowed reach the
// dial, so a guard that would fetch a new form fails by name (#656). The dial is a test hook that
// records it was reached and dials nothing; the address check at dial is ssrfguard's own tests'.
func TestTheGuardsURLRuleDecidesEveryHostFamilyAsPinned(t *testing.T) {
	var reached bool
	f := New(Config{Dial: func(context.Context, string, string) (net.Conn, error) {
		reached = true
		return nil, errors.New("not dialled")
	}})
	hostfamilies.Run(t, "internal/ssrfguard", []hostfamilies.Column{
		{Name: "SSRF guard URL", Probes: hostfamilies.URLProbes("/jwks.json", "https", "http"), Judge: func(in string) (bool, string) {
			reached = false
			_, err := f.Get(context.Background(), in, 1)
			switch {
			case reached:
				return true, ""
			case errors.Is(err, ErrRefused):
				return false, "refused before the dial"
			}
			return false, "not dialled"
		}},
	})
}
