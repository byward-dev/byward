package registration

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/byward-dev/byward/internal/store/memory"
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

// A denied CIMD client is unknown, with the reason for the operator log, before its document is
// fetched; another document on the same host still resolves.
func TestADeniedCIMDClientIsUnknownWithoutAFetch(t *testing.T) {
	const other = "https://app.example/other.json"
	deny, _ := NewDenylist([]string{cimdID})
	f := &fakeFetch{replies: map[string][]reply{other: {{body: doc(map[string]any{"client_id": other})}}}}
	c := newClock()
	r := NewCIMDRegistry(CIMDConfig{Fetch: f, Deny: deny, JTI: NewStoreJTICache(memory.New()), Now: c.now})
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
	ch := Chain{newReg(f, c, nil, nil), newDCR(brokenClients{}, c.now, 0)}
	if _, err := ch.Client(context.Background(), cimdID); !errors.Is(err, ErrMetadataRefused) {
		t.Fatalf("refused document behind the DCR registry: %v, want ErrMetadataRefused", err)
	}
	deny, err := NewDenylist([]string{cimdID})
	if err != nil {
		t.Fatal(err)
	}
	denied := Chain{NewCIMDRegistry(CIMDConfig{Fetch: f, Deny: deny, JTI: NewStoreJTICache(memory.New()), Now: c.now}), newDCR(brokenClients{}, c.now, 0)}
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
	cl, err := NewCIMDRegistry(CIMDConfig{Fetch: f, Deny: deny, JTI: NewStoreJTICache(memory.New()), Now: c.now}).Client(context.Background(), cimdID)
	if err != nil {
		t.Fatal(err)
	}
	var re *RedirectError
	if err := cl.RedirectAllowed("https://app.example/cb"); !errors.As(err, &re) || re.Reason != ReasonDenied {
		t.Fatalf("RedirectAllowed = %v, want a denied redirect", err)
	}
}

// A client is denied once any one of its registered redirect URIs returns to a denied host (#338),
// as the broker sees it: a client from the registry, checked with Denied().
func TestAClientIsDeniedByAnyOfItsRedirectHosts(t *testing.T) {
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
			cl, err := NewCIMDRegistry(CIMDConfig{Fetch: f, Deny: deny, JTI: NewStoreJTICache(memory.New()), Now: c.now}).Client(context.Background(), cimdID)
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
		})
	}
}

// reasoned is a registry that does not know the client and says why.
type reasoned string

func (r reasoned) Client(context.Context, string) (Client, error) {
	return nil, fmt.Errorf("%w: %s", ErrUnknownClient, string(r))
}
