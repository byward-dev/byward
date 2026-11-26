package registration

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/byward-dev/byward/internal/ssrfguard"
	"github.com/byward-dev/byward/internal/testutil/hostfamilies"
)

// selfDoc answers every URL with a valid client metadata document whose client_id is that URL, so a
// client ID's trust is decided by its host alone.
type selfDoc struct{}

func (selfDoc) Get(_ context.Context, url string, _ int64) (*ssrfguard.Response, error) {
	return &ssrfguard.Response{Body: doc(map[string]any{"client_id": url})}, nil
}

// The CIMD client ID rule, the CIMD allow and trust checks, the client denylist, redirect URI
// validation, the loopback redirect match and the remembered consent's redirect key decide every
// host family as pinned in testdata/hostdecisions.golden; testdata/hostdecisions.allowed holds the
// inputs each passes (a denylist: the inputs it stops), so a check that lets a new form through fails
// by name (#656). A client ID passes the registry when
// it reaches the fetch: every check before it took it.
func TestEveryRegistrationHostCheckDecidesEveryHostFamilyAsPinned(t *testing.T) {
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
			if err == nil {
				return false, "returned a client without fetching it"
			}
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
	redirects := deny("evil.example", "mcp.example.com", "xn--bcher-kva.example", "fass.example", "127.0.0.1") // mcp.example.com is the URL shapes' host; faß.example matches fass.example by the transitional fold
	ids := hostfamilies.URLProbes("/client.json", "https")
	redirectURIs := hostfamilies.URLProbes("/cb", "https", "http")
	redirectReason := func(err error) (bool, string) {
		var re *RedirectError
		if errors.As(err, &re) {
			return false, string(re.Reason)
		}
		return err == nil, "refused"
	}
	hostfamilies.Run(t, "internal/registration", []hostfamilies.Column{
		{Name: "CIMD client ID", Probes: ids, Judge: reaches(CIMDConfig{})},
		{Name: "CIMD allowed host", Probes: ids, Judge: reaches(CIMDConfig{AllowedHosts: []string{"mcp.example.com", "app.example"}, TrustedHosts: []string{"xn--bcher-kva.example"}})},
		// A client passes when the registry vouches for it (Verified), which only a trusted host's does:
		// an allowed one, as production lists both, is not.
		{Name: "CIMD trusted host", Probes: ids, Judge: func() func(string) (bool, string) {
			r := NewCIMDRegistry(CIMDConfig{Fetch: selfDoc{}, Now: time.Now, TrustedHosts: []string{"xn--bcher-kva.example", "app.example"}, AllowedHosts: []string{"mcp.example.com"}})
			return func(in string) (bool, string) {
				c, err := r.Client(context.Background(), in)
				if err != nil {
					return false, "no client"
				}
				return c.Trust() == Verified, "trust " + string(c.Trust())
			}
		}()},
		// An entry judged by the denylist alone, before config's refusals, since the denylist is the full rule.
		{Name: "denylist entry", Probes: append(hostfamilies.HostProbes(), ids...), Judge: func(in string) (bool, string) {
			_, err := NewDenylist([]string{in})
			if ee := (*EntryError)(nil); errors.As(err, &ee) {
				return false, ee.Reason
			}
			return err == nil, "refused" // the wiring refuses on any error
		}},
		// The token validator and the static-client check ask about any client ID, valid or not, so
		// this column judges every one, not only those the CIMD rule keeps.
		{Name: "denylist client ID", Probes: ids, Judge: func(in string) (bool, string) { return !clientIDs.DeniesClient(in), "denied" }, Denies: true},
		// DCR asks the denylist only about the redirect URIs the redirect rule keeps (dcr.go), so only
		// those can be stopped.
		{Name: "denylist redirect", Probes: redirectURIs, Judge: func(in string) (bool, string) {
			return ValidateRedirect(in) != nil || !redirects.DeniesRedirect(in), "denied"
		}, Denies: true},
		{Name: "redirect URI", Probes: redirectURIs, Judge: func(in string) (bool, string) { return redirectReason(ValidateRedirect(in)) }},
		// A registered loopback redirect matches the same host, as written, on any port (ADR-0009 §2):
		// one is registered, so a redirect to another loopback host is refused.
		{Name: "loopback redirect", Probes: redirectURIs, Judge: func(in string) (bool, string) {
			return redirectReason(MatchRedirect([]string{"http://127.0.0.1/cb"}, in))
		}},
		// A remembered consent compares redirect URIs by RedirectKey, which drops the port of an http
		// loopback one only: a URI passes when its port is dropped, so a remembered consent covers it
		// on another port.
		{Name: "consent redirect key", Probes: redirectURIs, Judge: func(in string) (bool, string) {
			return RedirectKey(in) != in, "compared as written"
		}},
	})
}
