package registration

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/byward-dev/byward/internal/store/memory"
	"github.com/byward-dev/byward/internal/testutil/fakeclock"
)

func TestDenylistEntriesAreCIMDClientIDsOrHostNames(t *testing.T) {
	for _, entry := range []string{"https://app.example/client.json", "app.example", "App.Example"} {
		if _, err := NewDenylist([]string{entry}); err != nil {
			t.Errorf("%q refused: %v", entry, err)
		}
	}
	for entry, why := range map[string]string{
		"":                              "neither",
		"localhost":                     "neither", // a single label is not a host anyone registers
		"*.app.example":                 "neither",
		"app.example:8443":              "neither",
		"user@app.example":              "neither",
		"app.example/path":              "neither",
		"http://app.example/c.json":     "neither", // not a CIMD client ID, and not a host
		"https://app.example/c.json?q=": "query",
	} {
		if _, err := NewDenylist([]string{entry}); err == nil || !strings.Contains(err.Error(), why) {
			t.Errorf("%q: %v, want a refusal mentioning %q", entry, err, why)
		}
	}
}

// A refused denylist entry is an *EntryError: its place in the list and a fixed reason, never the entry
// (ADR-0031 §1), which config names by its length (Config.RefusedDenylistEntry).
func TestARefusedDenylistEntryIsNamedByItsPlaceNeverShown(t *testing.T) {
	const secret = "s3cretPW"
	for entry, reason := range map[string]string{
		"https://user:" + secret + "@app.example/c.json":   "it is not a client ID metadata document URL: must not contain user information",
		"https://app.example/c.json?token=" + secret:       "it is not a client ID metadata document URL: must not have a query",
		"https://app.example/c.json#" + secret:             "it is not a client ID metadata document URL: must not have a fragment",
		"https://app " + secret + ".example/c.json":        "it is not a client ID metadata document URL: must be printable ASCII",
		"https://app.example:" + secret + "/c.json":        "it is not a client ID metadata document URL: not an absolute URL",
		"https://app.example:8443/" + secret + "@x/c.json": "it is not a client ID metadata document URL: only port 443 is fetched",
		"http://" + secret + ".example/c.json":             "it is neither a CIMD client ID (https URL) nor a host name",
	} {
		for _, list := range [][]string{{entry, "good.example"}, {"good.example", entry}} {
			_, err := NewDenylist(list)
			at := slices.Index(list, entry)
			var ee *EntryError
			if !errors.As(err, &ee) || ee.Index != at || ee.Reason != reason || err.Error() != fmt.Sprintf("entry %d: %s", at+1, reason) || strings.Contains(err.Error(), secret) {
				t.Errorf("%q at %d: %v, want entry %d refused as %q, never the entry", entry, at, err, at+1, reason)
			}
		}
	}
}

// A static client's refused redirect URI is a startup and check error, so it is shown as logs may
// show it: never its user information, query or fragment (security invariant 2).
func TestARefusedStaticRedirectURINeverShowsItsCredential(t *testing.T) {
	const secret = "s3cretPW"
	for _, uri := range []string{"https://user:" + secret + "@app.example/cb", "https://app.example/cb#" + secret,
		"http://app.example/cb?token=" + secret} {
		_, err := load(t, files{"/etc/mcp/clients.json": `{"clients":[{"client_id":"a","token_endpoint_auth_method":"none","redirect_uris":["` + uri + `"]}]}`})
		if err == nil || strings.Contains(err.Error(), secret) || !strings.Contains(err.Error(), "redirect_uris[0]: redirect URI ") || !strings.Contains(err.Error(), "app.example/cb") {
			t.Errorf("%s: %v, want it refused, named by scheme, host and path, without the secret", uri, err)
		}
	}
}

func TestADeniedHostMatchesExactlyIgnoringCase(t *testing.T) {
	d, err := NewDenylist([]string{"App.Example", "denied.example.", "https://app.example/client.json"})
	if err != nil {
		t.Fatal(err)
	}
	for uri, denied := range map[string]bool{
		"https://APP.example/cb":      true,
		"https://app.example./cb":     true, // a trailing dot is the same host
		"https://denied.example/cb":   true, // and so is an entry written with one
		"http://app.example:8080/cb":  true,
		"https://sub.app.example/cb":  false, // a subdomain is another host
		"https://other.example/cb":    false,
		"://not a uri":                false,
		"https://app.example.evil/cb": false,
	} {
		if got := d.DeniesRedirect(uri); got != denied {
			t.Errorf("DeniesRedirect(%q) = %v, want %v", uri, got, denied)
		}
	}
	for _, spelling := range []string{"https://app.example/client.json", "https://APP.example/client.json", "https://app.example./client.json",
		"https://app.example:443/client.json", "https://app.example/client%2Ejson"} {
		if !d.DeniesClient(spelling) {
			t.Errorf("DeniesClient(%q) = false: another spelling of a denied document URL", spelling)
		}
	}
	if d.DeniesClient("https://app.example/other.json") {
		t.Error("another document on a denied CIMD URL's host is denied")
	}
	for _, notCIMD := range []string{"http://app.example/client.json", "//app.example/client.json"} {
		if d.DeniesClient(notCIMD) {
			t.Errorf("DeniesClient(%q) = true: not a CIMD client ID, so never denied by ID", notCIMD)
		}
	}
	var none *Denylist
	if none.DeniesClient("https://app.example/client.json") || none.DeniesRedirect("https://app.example/cb") {
		t.Error("a nil denylist denied something")
	}
}

// A denied host is denied in every spelling a browser resolves to it: an internationalized name in
// Unicode or xn-- form, full-width letters and full stops, a trailing ideographic full stop. So a client
// cannot register the Unicode spelling of a host the operator listed in xn-- form, or the reverse. It is
// also denied as an older or transitional IDNA browser goes to it (faß as fass). A name a browser
// refuses still matches its own xn-- form; other hosts stay apart.
func TestADeniedHostMatchesEverySpellingTheBrowserGoesTo(t *testing.T) {
	for _, c := range []struct {
		entry, uri string
		denied     bool
	}{
		{"xn--bcher-kva.example", "https://bücher.example/cb", true},
		{"xn--bcher-kva.example", "https://BÜCHER.example/cb", true},
		{"xn--bcher-kva.example", "https://bücher。example/cb", true},
		{"xn--bcher-kva.example", "https://bücher.example。/cb", true},
		{"bücher.example", "https://xn--bcher-kva.example/cb", true},
		{"app.example", "https://app.example。/cb", true},
		{"app.example", "https://ａｐｐ.example/cb", true},
		{"xn--aib-9dc.example", "https://aİb.example/cb", true}, // UTS #46 maps İ to i̇, not to i
		{"xn--fa-hia.example", "https://faß.example/cb", true},  // non-transitional: ß stays ß, as in browsers
		{"xn--fa-hia.example", "https://faẞ.example/cb", true},  // ẞ maps to ß since Unicode 15.1
		// Older or transitional IDNA maps ß and ẞ to ss, and a browser with it goes there: denied too.
		{"fass.example", "https://faß.example/cb", true},
		{"fass.example", "https://faẞ.example/cb", true},
		{"fass.example", "https://faß.example:8443/cb", true}, // the port is not part of the host
		{"xn--fa-hia.example", "https://faß.example:8443/cb", true},
		{"faß.example", "https://xn--fa-hia.example/cb", true}, // an entry is kept by its browser fold
		{"app.example", "https://app．example/cb", true},        // a full-width full stop
		// Names with "_" or "--", which a browser still maps.
		{"xn--b_cher-3ya.example", "https://bü_cher.example/cb", true},
		{"my_app.example", "https://ｍｙ_app.example/cb", true},
		{"ab--c.example", "https://ＡＢ--c.example/cb", true},
		// A name the browser refuses is compared by the mapping it got that far: its own xn-- form for a
		// joiner out of context or a label mixing directions, and lower case for invalid punycode (the
		// mapping lower-cases first).
		{"xn--ab-m1t.example", "https://a\u200db.example/cb", true},
		{"xn--a-0hc.example", "https://aא.example/cb", true},
		{"xn--zz.example", "https://XN--ZZ.example./cb", true},
		{"xn--zz.example", "https://xn--zy.example/cb", false},
		// Other hosts stay apart.
		{"xn--bcher-kva.example", "https://böcher.example/cb", false},
		{"xn--bcher-kva.example", "https://bucher.example/cb", false},
		{"aib.example", "https://aİb.example/cb", false},
	} {
		d, err := NewDenylist([]string{c.entry})
		if err != nil {
			t.Errorf("entry %q: %v", c.entry, err)
			continue
		}
		if got := d.DeniesRedirect(c.uri); got != c.denied {
			t.Errorf("entry %q: DeniesRedirect(%q) = %v, want %v", c.entry, c.uri, got, c.denied)
		}
	}
}

// A denied CIMD client is unknown, with the reason for the operator log, before its document is
// fetched; another document on the same host still resolves.
func TestADeniedCIMDClientIsUnknownWithoutAFetch(t *testing.T) {
	const other = "https://app.example/other.json"
	deny, _ := NewDenylist([]string{cimdID})
	f := &fakeFetch{replies: map[string][]reply{other: {{body: doc(map[string]any{"client_id": other})}}}}
	c := newClock()
	r := newDenyingReg(f, c, deny)
	_, err := r.Client(context.Background(), cimdID)
	if !errors.Is(err, ErrUnknownClient) || !errors.Is(err, ErrClientDenied) || errors.Is(err, ErrMetadataRefused) || f.calls.Load() != 0 {
		t.Fatalf("denied client: %v after %d fetches, want unknown, ErrClientDenied and no fetch", err, f.calls.Load())
	}
	if cl, err := r.Client(context.Background(), other); err != nil || cl.ID() != other {
		t.Fatalf("another client on the host: %v %v", cl, err)
	}
}

// The chain answers with the first registry that has something to say: a refused CIMD document or
// a denied client ID stays refused (so its grants are revoked on refresh) even with the DCR
// registry after it.
func TestTheChainKeepsTheFirstReasonedRefusal(t *testing.T) {
	f := &fakeFetch{replies: map[string][]reply{cimdID: {gone()}}}
	c := newClock()
	ch := Chain{newReg(f, c, nil, nil), newDCR(brokenClients(), c.Now, 0)}
	if _, err := ch.Client(context.Background(), cimdID); !errors.Is(err, ErrMetadataRefused) {
		t.Fatalf("refused document behind the DCR registry: %v, want ErrMetadataRefused", err)
	}
	deny, err := NewDenylist([]string{cimdID})
	if err != nil {
		t.Fatal(err)
	}
	denied := Chain{newDenyingReg(f, c, deny), newDCR(brokenClients(), c.Now, 0)}
	if _, err := denied.Client(context.Background(), cimdID); !errors.Is(err, ErrClientDenied) {
		t.Fatalf("denied client ID behind the DCR registry: %v, want ErrClientDenied", err)
	}
	if _, err := ch.Client(context.Background(), "nobody"); err != ErrUnknownClient {
		t.Fatalf("an ID no registry knows: %v, want the plain ErrUnknownClient", err)
	}
	if _, err := (Chain{reasoned("first"), reasoned("second")}).Client(context.Background(), "x"); err == nil || !strings.Contains(err.Error(), "first") {
		t.Fatalf("two reasoned refusals: %v, want the first", err)
	}
}

// A CIMD client returning to a denied host is refused at its redirect, like a DCR client.
func TestACIMDClientReturningToADeniedHostIsRefused(t *testing.T) {
	deny, _ := NewDenylist([]string{"app.example"})
	f := &fakeFetch{replies: map[string][]reply{cimdID: {ok("")}}}
	c := newClock()
	cl, err := newDenyingReg(f, c, deny).Client(context.Background(), cimdID)
	if err != nil {
		t.Fatal(err)
	}
	var re *RedirectError
	if err := cl.RedirectAllowed("https://app.example/cb"); !errors.As(err, &re) || re.Reason != ReasonDenied {
		t.Fatalf("RedirectAllowed = %v, want a denied redirect", err)
	}
}

// A CIMD client is denied once any one of its registered redirect URIs returns to a denied host
// (#338), as the broker sees it: a client from the registry, checked with Denied(), and refused as
// denied for every redirect URI it sends, its allowed ones included. A DCR client shares the check;
// the broker's refresh tests cover both kinds.
func TestACIMDClientIsDeniedByAnyOfItsRedirectHosts(t *testing.T) {
	redirects := []string{"https://app.example/cb", "https://second.example/cb"}
	for name, tc := range map[string]struct {
		entries []string
		want    bool
	}{
		"the first redirect's host":  {entries: []string{"app.example"}, want: true},
		"the second redirect's host": {entries: []string{"second.example"}, want: true},
		"another host":               {entries: []string{"other.example"}},
		"no denylist":                {},
	} {
		t.Run(name, func(t *testing.T) {
			deny, err := NewDenylist(tc.entries)
			if err != nil {
				t.Fatal(err)
			}
			f := &fakeFetch{replies: map[string][]reply{cimdID: {{body: doc(map[string]any{"redirect_uris": redirects})}}}}
			c := newClock()
			cl, err := newDenyingReg(f, c, deny).Client(context.Background(), cimdID)
			if err != nil {
				t.Fatal(err)
			}
			d, ok := cl.(interface{ Denied() bool })
			if !ok {
				t.Fatalf("%T has no Denied method", cl)
			}
			if got := d.Denied(); got != tc.want {
				t.Fatalf("Denied() = %v, want %v", got, tc.want)
			}
			for _, u := range redirects {
				var re *RedirectError
				err := cl.RedirectAllowed(u)
				if denied := errors.As(err, &re) && re.Reason == ReasonDenied; denied != tc.want || (!tc.want && err != nil) {
					t.Errorf("RedirectAllowed(%s) = %v, want denied %v", u, err, tc.want)
				}
			}
		})
	}
}

// newDenyingReg is a CIMD registry fetching through f, with deny as the operator's denylist.
func newDenyingReg(f *fakeFetch, c *fakeclock.Clock, deny *Denylist) *CIMDRegistry {
	return NewCIMDRegistry(CIMDConfig{Fetch: f, Deny: deny, JTI: NewStoreJTICache(memory.New()), Now: c.Now})
}

// reasoned is a registry that does not know the client and says why.
type reasoned string

func (r reasoned) Client(context.Context, string) (Client, error) {
	return nil, fmt.Errorf("%w: %s", ErrUnknownClient, string(r))
}
