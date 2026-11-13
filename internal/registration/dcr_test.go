package registration

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"github.com/byward-dev/byward/internal/store"
	"github.com/byward-dev/byward/internal/store/memory"
	"github.com/byward-dev/byward/internal/testutil/clientdocs"
)

func newDCR(st store.Clients, now func() time.Time, max int) *DCRRegistry {
	return NewDCRRegistry(DCRConfig{Store: st, JTI: NewStoreJTICache(memory.New(), now), Now: now, Scopes: []string{"mcp", "offline_access"}, Max: max})
}

func response(t *testing.T, r *Registered) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(r.Response, &m); err != nil {
		t.Fatal(err)
	}
	return m
}

// The registrations real clients send are accepted, echo every registered field (the TypeScript SDK
// rejects a response without redirect_uris) and resolve to an unverified client that may refresh.
// Cursor's cursor:// callback fails the redirect policy and is dropped (ADR-0009, amended).
func TestRealClientRegistrationsAreAccepted(t *testing.T) {
	for _, name := range clientdocs.Registrations {
		t.Run(name, func(t *testing.T) {
			fx := clientdocs.LoadRegistration(t, name)
			c := newClock()
			r := newDCR(memory.New(), c.now, 0)
			reg, err := r.Register(context.Background(), fx.Body)
			if err != nil {
				t.Fatal(err)
			}
			resp := response(t, reg)
			var sent struct {
				RedirectURIs []string `json:"redirect_uris"`
			}
			_ = json.Unmarshal(fx.Body, &sent)
			kept := slices.DeleteFunc(slices.Clone(sent.RedirectURIs), func(u string) bool { return slices.Contains(fx.Dropped, u) })
			if !strings.HasPrefix(reg.ClientID, DCRIDPrefix) || resp["client_id"] != reg.ClientID || resp["client_secret"] != nil ||
				resp["client_id_issued_at"] != float64(c.now().Unix()) || resp["token_endpoint_auth_method"] != "none" ||
				!slices.Equal(stringsOf(resp["redirect_uris"]), kept) || !slices.Equal(reg.Dropped, fx.Dropped) {
				t.Fatalf("response %v, dropped %v", resp, reg.Dropped)
			}
			cl, err := r.Client(context.Background(), reg.ClientID)
			if err != nil {
				t.Fatal(err)
			}
			if cl.Trust() != NotVerified || !cl.AllowsRefresh() || cl.RedirectAllowed(fx.Redirect) != nil {
				t.Fatalf("trust %v, refresh %v, redirect %v", cl.Trust(), cl.AllowsRefresh(), cl.RedirectAllowed(fx.Redirect))
			}
		})
	}
}

func stringsOf(v any) []string {
	var out []string
	for _, s := range v.([]any) {
		out = append(out, s.(string))
	}
	return out
}

func TestRegistrationsThatBreakTheRulesAreRefused(t *testing.T) {
	ok := `"client_name":"App","redirect_uris":["https://app.example/cb"]`
	for name, tc := range map[string]struct {
		body string
		want error
		text string
	}{
		"no redirect passes":        {`{"client_name":"App","redirect_uris":["myapp://cb","http://evil.example/cb"]}`, ErrInvalidRedirectURI, "no redirect URI passes"},
		"no redirects":              {`{"client_name":"App"}`, ErrInvalidRedirectURI, "between 1 and"},
		"too many redirects":        {tooManyRedirects(), ErrInvalidRedirectURI, "between 1 and 10"},
		"no name":                   {`{"redirect_uris":["https://app.example/cb"]}`, ErrInvalidClientMetadata, "client_name"},
		"a shared secret method":    {`{` + ok + `,"token_endpoint_auth_method":"client_secret_basic"}`, ErrInvalidClientMetadata, "shared secret"},
		"a client secret":           {`{` + ok + `,"client_secret":"s"}`, ErrInvalidClientMetadata, "client_secret"},
		"no code grant":             {`{` + ok + `,"grant_types":["client_credentials"]}`, ErrInvalidClientMetadata, "authorization_code"},
		"not JSON":                  {`client_name=App`, ErrInvalidClientMetadata, "not a JSON object"},
		"a JSON array":              {`[]`, ErrInvalidClientMetadata, "not a JSON object (array)"},
		"a field of the wrong type": {`{"client_name":"App","redirect_uris":"https://app.example/cb"}`, ErrInvalidClientMetadata, "redirect_uris: wrong JSON type (string)"},
		"private_key_jwt no keys":   {`{` + ok + `,"token_endpoint_auth_method":"private_key_jwt"}`, ErrInvalidClientMetadata, "jwks: required"},
	} {
		t.Run(name, func(t *testing.T) {
			st := memory.New()
			_, err := newDCR(st, newClock().now, 0).Register(context.Background(), []byte(tc.body))
			if !errors.Is(err, tc.want) || !strings.Contains(err.Error(), tc.text) {
				t.Fatalf("err = %v, want %v containing %q", err, tc.want, tc.text)
			}
		})
	}
}

// The response says what was registered: an omitted method becomes none (no secret is ever
// issued), unknown scopes are dropped, and a method list (an OIDC field) is ignored.
func TestARegisteredClientIsPublicWithOnlySupportedScopesAndGrants(t *testing.T) {
	reg, err := newDCR(memory.New(), newClock().now, 0).Register(context.Background(),
		[]byte(`{"client_name":"App","redirect_uris":["https://app.example/cb"],"scope":"mcp admin offline_access mcp","token_endpoint_auth_methods_supported":["private_key_jwt"]}`))
	if err != nil {
		t.Fatal(err)
	}
	resp := response(t, reg)
	if resp["token_endpoint_auth_method"] != "none" || resp["scope"] != "mcp offline_access" || !slices.Equal(stringsOf(resp["grant_types"]), []string{"authorization_code"}) ||
		!slices.Equal(stringsOf(resp["response_types"]), []string{"code"}) {
		t.Fatalf("response %v", resp)
	}
}

func TestRegistrationsAreCapped(t *testing.T) {
	r := newDCR(memory.New(), newClock().now, 1)
	body := []byte(`{"client_name":"App","redirect_uris":["https://app.example/cb"]}`)
	if _, err := r.Register(context.Background(), body); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Register(context.Background(), body); !errors.Is(err, ErrRegistrationsFull) {
		t.Fatalf("err = %v, want ErrRegistrationsFull", err)
	}
}

// A store that fails: registrations and lookups are temporarily unavailable, never refused.
type brokenClients struct{ store.Clients }

func (brokenClients) CreateClient(context.Context, store.Client, int) error {
	return errors.New("disk I/O error")
}
func (brokenClients) Client(context.Context, string) (store.Client, error) {
	return store.Client{}, errors.New("disk I/O error")
}

func TestAStoreFailureIsTemporary(t *testing.T) {
	r := newDCR(brokenClients{}, newClock().now, 0)
	if _, err := r.Register(context.Background(), []byte(`{"client_name":"App","redirect_uris":["https://app.example/cb"]}`)); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("register: %v", err)
	}
	if _, err := r.Client(context.Background(), DCRIDPrefix+"x"); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("lookup: %v", err)
	}
}

// Static and CIMD client IDs are not looked up in the store.
func TestClientIDsTheRegistryDidNotIssueAreUnknownEvenWithTheStoreDown(t *testing.T) {
	r := newDCR(brokenClients{}, newClock().now, 0)
	for _, id := range []string{"static-app", cimdID} {
		if _, err := r.Client(context.Background(), id); err != ErrUnknownClient {
			t.Fatalf("%s: %v, want the plain ErrUnknownClient without a store call", id, err)
		}
	}
}

// With the synctest clock: a registration expires DCRLifetime after its last use, renews when used
// (about once a day, not on every use), and an expired one is unknown, not refused; one never used
// is collected after a day.
func TestRegistrationsSlideAndExpire(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		st := memory.New()
		r := newDCR(st, time.Now, 0)
		ctx := context.Background()
		body := []byte(`{"client_name":"App","redirect_uris":["https://app.example/cb"]}`)
		used, err := r.Register(ctx, body)
		if err != nil {
			t.Fatal(err)
		}
		unused, _ := r.Register(ctx, body)
		use := func() {
			t.Helper()
			cl, err := r.Client(ctx, used.ClientID)
			if err != nil {
				t.Fatalf("registration in use: %v", err)
			}
			u, ok := cl.(interface {
				RecordUse(context.Context, time.Time) error
			})
			if !ok {
				t.Fatal("a DCR client does not record its use")
			}
			if err := u.RecordUse(ctx, time.Now()); err != nil {
				t.Fatal(err)
			}
		}
		expires := func() time.Time {
			t.Helper()
			c, err := st.Client(ctx, used.ClientID)
			if err != nil {
				t.Fatal(err)
			}
			return c.ExpiresAt
		}
		use()
		// Used again within DCRRenewal: no store write, the expiry stays.
		first := expires()
		time.Sleep(DCRRenewal - time.Second)
		use()
		if got := expires(); !got.Equal(first) {
			t.Fatalf("expiry moved from %v to %v on a use within DCRRenewal", first, got)
		}

		time.Sleep(store.UnusedClientLifetime)
		if err := st.Collect(ctx, time.Now()); err != nil {
			t.Fatal(err)
		}
		if _, err := r.Client(ctx, unused.ClientID); !errors.Is(err, ErrUnknownClient) {
			t.Fatalf("never-used registration after a day: %v", err)
		}
		if _, err := r.Client(ctx, used.ClientID); err != nil {
			t.Fatalf("used registration after a day: %v", err)
		}

		// Use it every 60 days: it never expires, and each use renews it.
		for range 3 {
			time.Sleep(60 * 24 * time.Hour)
			use()
			if got, want := expires(), time.Now().Add(DCRLifetime); !got.Equal(want) {
				t.Fatalf("expiry after a use = %v, want %v", got, want)
			}
		}
		// Left alone for DCRLifetime, it expires: unknown, never a refused document.
		time.Sleep(DCRLifetime)
		_, err = r.Client(ctx, used.ClientID)
		if !errors.Is(err, ErrUnknownClient) || errors.Is(err, ErrMetadataRefused) {
			t.Fatalf("expired registration: %v", err)
		}
	})
}

// One redirect URI returning to a denied host refuses the whole registration: unlike a URI that
// fails the policy, it is not dropped. The reason names the URI without its query.
func TestADeniedRedirectHostRefusesTheWholeRegistration(t *testing.T) {
	deny, _ := NewDenylist([]string{"app.example"})
	c := newClock()
	r := NewDCRRegistry(DCRConfig{Store: memory.New(), JTI: NewStoreJTICache(memory.New(), c.now), Now: c.now, Deny: deny})
	_, err := r.Register(context.Background(), []byte(`{"client_name":"App","redirect_uris":["https://ok.example/cb","https://app.example/cb?code=leak"]}`))
	if !errors.Is(err, ErrInvalidRedirectURI) || !strings.Contains(err.Error(), "https://app.example/cb returns to a host on the operator's denylist") || strings.Contains(err.Error(), "leak") {
		t.Fatalf("err = %v", err)
	}
}

// A stored registration that no longer reads or no longer passes the rules, or that expires right
// now, is unknown: the client registers again. It is never ErrMetadataRefused, which would revoke.
func TestAStoredRegistrationThatCannotBeUsedIsUnknown(t *testing.T) {
	c := newClock()
	for name, rec := range map[string]store.Client{
		"unreadable":       {Metadata: []byte("{"), ExpiresAt: c.now().Add(time.Hour)},
		"no longer valid":  {Metadata: []byte(`{"client_name":"App","redirect_uris":["myapp://cb"]}`), ExpiresAt: c.now().Add(time.Hour)},
		"expiring exactly": {Metadata: []byte(`{"client_name":"App","redirect_uris":["https://app.example/cb"]}`), ExpiresAt: c.now()},
	} {
		t.Run(name, func(t *testing.T) {
			st := memory.New()
			rec.ID, rec.CreatedAt = DCRIDPrefix+"stored", c.now().Add(-time.Hour)
			if err := st.CreateClient(context.Background(), rec, 10); err != nil {
				t.Fatal(err)
			}
			_, err := newDCR(st, c.now, 0).Client(context.Background(), rec.ID)
			if !errors.Is(err, ErrUnknownClient) || errors.Is(err, ErrMetadataRefused) {
				t.Fatalf("err = %v, want unknown and never refused", err)
			}
		})
	}
}

// A client registering inline keys gets them back in the response, and after a lookup its
// assertions signed with the matching key authenticate it.
func TestAClientWithInlineKeysAuthenticatesWithThem(t *testing.T) {
	e := newAuthEnv(t)
	r := newDCR(memory.New(), func() time.Time { return now }, 0)
	reg, err := r.Register(context.Background(), []byte(`{"client_name":"App","redirect_uris":["https://app.example/cb"],"token_endpoint_auth_method":"private_key_jwt","jwks":`+
		publicJWKS(t, e.cert)+`}`))
	if err != nil {
		t.Fatal(err)
	}
	if resp := response(t, reg); resp["jwks"] == nil || resp["token_endpoint_auth_method"] != "private_key_jwt" {
		t.Fatalf("response %v, want the registered keys and method", resp)
	}
	cl, err := r.Client(context.Background(), reg.ClientID)
	if err != nil {
		t.Fatal(err)
	}
	form := e.assertion(t, e.cert, "PS256", map[string]any{"iss": reg.ClientID, "sub": reg.ClientID})
	form.Set("client_id", reg.ClientID)
	if err := cl.Authenticate(context.Background(), form, http.Header{}, tokenEndpoint, now); err != nil {
		t.Fatalf("assertion signed with the registered key: %v", err)
	}
}

// tooManyRedirects is a registration with one redirect URI more than the limit.
func tooManyRedirects() string {
	uris := make([]string, MaxRedirectURIs+1)
	for i := range uris {
		uris[i] = fmt.Sprintf("%q", fmt.Sprintf("https://a.example/%d", i))
	}
	return `{"client_name":"App","redirect_uris":[` + strings.Join(uris, ",") + `]}`
}

// A client_id in the request never becomes the client's ID: the broker issues one, so nobody can
// register under a static, CIMD or chosen dcr- ID.
func TestARequestedClientIDIsIgnored(t *testing.T) {
	r := newDCR(memory.New(), newClock().now, 0)
	for _, asked := range []string{"https://evil.example/client.json", "static-app", DCRIDPrefix + "mine"} {
		reg, err := r.Register(context.Background(), []byte(`{"client_id":"`+asked+`","client_name":"App","redirect_uris":["https://app.example/cb"]}`))
		if err != nil {
			t.Fatal(err)
		}
		if reg.ClientID == asked || !strings.HasPrefix(reg.ClientID, DCRIDPrefix) || response(t, reg)["client_id"] != reg.ClientID {
			t.Fatalf("asked for %q, got %q (response %v)", asked, reg.ClientID, response(t, reg))
		}
	}
}

// capSpy records the cap the registry passes to the store.
type capSpy struct {
	store.Clients
	max int
}

func (c *capSpy) CreateClient(ctx context.Context, cl store.Client, max int) error {
	c.max = max
	return c.Clients.CreateClient(ctx, cl, max)
}

// Without a configured cap, registrations are capped at MaxDCRClients, never unlimited.
func TestTheDefaultCapIsMaxDCRClients(t *testing.T) {
	spy := &capSpy{Clients: memory.New()}
	if _, err := newDCR(spy, newClock().now, 0).Register(context.Background(), []byte(`{"client_name":"App","redirect_uris":["https://app.example/cb"]}`)); err != nil {
		t.Fatal(err)
	}
	if spy.max != MaxDCRClients {
		t.Fatalf("cap passed to the store = %d, want %d", spy.max, MaxDCRClients)
	}
}

// Redirect URIs that pass are registered once each; the others, and repeats, are reported as dropped
// without their query, fragment or user information, so the broker can log them.
func TestRedirectsAreKeptOrReportedAsDropped(t *testing.T) {
	for name, tc := range map[string]struct {
		uris                string
		registered, dropped []string
	}{
		"query, fragment and userinfo stripped": {`"myapp://cb?secret=s3cr3t#f","com.example.app:/cb?x=1","http://u:s3cr3t@evil.example/cb","https://app.example/cb"`,
			[]string{"https://app.example/cb"}, []string{"myapp://cb", "com.example.app:/cb", "http://evil.example/cb"}},
		"a repeat registered once": {`"https://app.example/cb","https://app.example/cb"`, []string{"https://app.example/cb"}, []string{"https://app.example/cb"}},
	} {
		t.Run(name, func(t *testing.T) {
			reg, err := newDCR(memory.New(), newClock().now, 0).Register(context.Background(), []byte(`{"client_name":"App","redirect_uris":[`+tc.uris+`]}`))
			if err != nil {
				t.Fatal(err)
			}
			if got := stringsOf(response(t, reg)["redirect_uris"]); !slices.Equal(got, tc.registered) || !slices.Equal(reg.Dropped, tc.dropped) {
				t.Fatalf("registered %q, dropped %q; want %q, %q", got, reg.Dropped, tc.registered, tc.dropped)
			}
		})
	}
}
