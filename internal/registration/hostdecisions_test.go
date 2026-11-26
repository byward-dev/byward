package registration

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/byward-dev/byward/internal/testutil/hostfamilies"
)

// The CIMD client ID rule, the CIMD allow check and the client denylist decide every host family as
// pinned in testdata/hostdecisions.golden, and pass only the inputs in testdata/hostdecisions.allowed,
// so a check that lets a new form through fails by name (#656). A client ID passes the registry when
// it reaches the fetch: every check before it took it.
func TestEveryClientHostCheckDecidesEveryHostFamilyAsPinned(t *testing.T) {
	reaches := func(cfg CIMDConfig) func(string) (bool, string) {
		f := &fakeFetch{}
		cfg.Fetch, cfg.Now = f, time.Now
		r := NewCIMDRegistry(cfg)
		return func(in string) (bool, string) {
			before := f.calls.Load()
			_, err := r.Client(context.Background(), in)
			if f.calls.Load() > before {
				return true, ""
			}
			// The registry wraps the URL rule's error with %v, so its reason is read from the message;
			// a host that is not allowed is named in it, and is left out here.
			msg := err.Error()
			switch {
			case err == ErrUnknownClient: //nolint:errorlint // the bare error: no https client ID
				return false, "not an https URL"
			case errors.Is(err, ErrClientDenied):
				return false, "denied"
			case strings.Contains(msg, "is not allowed"):
				return false, "the CIMD host is not allowed"
			case errors.Is(err, ErrUnknownClient):
				return false, strings.TrimPrefix(msg, ErrUnknownClient.Error()+": ")
			}
			return false, "not fetched: " + msg
		}
	}
	deny := func(entries ...string) *Denylist {
		d, err := NewDenylist(entries)
		if err != nil {
			t.Fatalf("the decision denylist: %v", err)
		}
		return d
	}
	clientIDs := deny("https://mcp.example.com/client.json", "https://127.0.0.1/client.json", "https://[::1]/client.json", "https://xn--bcher-kva.example/client.json")
	redirects := deny("evil.example", "xn--bcher-kva.example")
	ids := hostfamilies.URLProbes("/client.json", "https")
	hostfamilies.Run(t, "internal/registration", []hostfamilies.Column{
		{Name: "CIMD client ID", Probes: ids, Judge: reaches(CIMDConfig{})},
		{Name: "CIMD allowed host", Probes: ids, Judge: reaches(CIMDConfig{AllowedHosts: []string{"mcp.example.com", "app.example"}, TrustedHosts: []string{"xn--bcher-kva.example"}})},
		{Name: "denylist entry", Probes: append(hostfamilies.HostProbes(), ids...), Judge: func(in string) (bool, string) {
			var ee *EntryError
			if _, err := NewDenylist([]string{in}); errors.As(err, &ee) {
				return false, ee.Reason
			}
			return true, ""
		}},
		{Name: "denylist client ID", Probes: ids, Judge: func(in string) (bool, string) { return !clientIDs.DeniesClient(in), "denied" }, Denies: true},
		{Name: "denylist redirect", Probes: hostfamilies.URLProbes("/cb", "https", "http"), Judge: func(in string) (bool, string) { return !redirects.DeniesRedirect(in), "denied" }, Denies: true},
	})
}
