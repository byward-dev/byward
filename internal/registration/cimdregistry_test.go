package registration

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"code.dny.dev/ssrf"
	"github.com/go-jose/go-jose/v4"

	"github.com/byward-dev/byward/internal/ssrfguard"
	"github.com/byward-dev/byward/internal/store/memory"
	"github.com/byward-dev/byward/internal/testutil/fakeidp"
)

// fakeFetch answers each URL with the next scripted reply (the last one repeats) and counts fetches.
type fakeFetch struct {
	mu      sync.Mutex
	replies map[string][]reply
	calls   atomic.Int32
	max     atomic.Int64  // the size limit of the last fetch
	gate    chan struct{} // when set, every fetch waits for it
}

type reply struct {
	body  []byte
	cache string
	err   error
}

func (f *fakeFetch) Get(ctx context.Context, url string, maxBytes int64) (*ssrfguard.Response, error) {
	f.calls.Add(1)
	f.max.Store(maxBytes)
	if f.gate != nil {
		select {
		case <-f.gate:
			if err := ctx.Err(); err != nil { // a cancelled fetch always loses, not at random
				return nil, err
			}
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(5 * time.Second):
			return nil, errors.New("fakeFetch: the gate never opened")
		}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	rs := f.replies[url]
	if len(rs) == 0 {
		return nil, &ssrfguard.StatusError{Code: http.StatusNotFound}
	}
	r := rs[0]
	if len(rs) > 1 {
		f.replies[url] = rs[1:]
	}
	if r.err != nil {
		return nil, r.err
	}
	if int64(len(r.body)) > maxBytes {
		return nil, ssrfguard.ErrTooLarge
	}
	return &ssrfguard.Response{Header: http.Header{"Cache-Control": {r.cache}}, Body: r.body}, nil
}

func newClock() *clock { return &clock{t: time.Unix(1_800_000_000, 0)} }

func ok(cache string) reply { return reply{body: doc(nil), cache: cache} }
func transient() reply {
	return reply{err: &ssrfguard.StatusError{Code: http.StatusServiceUnavailable}}
}
func gone() reply       { return reply{err: &ssrfguard.StatusError{Code: http.StatusNotFound}} }
func invalidDoc() reply { return reply{body: []byte(`{"client_id":"https://other.example/x"}`)} }
func newReg(f *fakeFetch, c *clock, trusted, allowed []string) *CIMDRegistry {
	return NewCIMDRegistry(CIMDConfig{Fetch: f, TrustedHosts: trusted, AllowedHosts: allowed, JTI: NewStoreJTICache(memory.New()), Now: c.now})
}

// step is one lookup after advancing the clock: whether it fetches and what it answers.
type step struct {
	after   time.Duration
	fetches int32 // total fetches after this step
	err     error // nil, ErrUnknownClient or ErrUnavailable
}

func TestCIMDCacheFollowsTheDocumentAndTheDraft(t *testing.T) {
	for name, tc := range map[string]struct {
		replies []reply
		steps   []step
	}{
		"max-age is honoured": {[]reply{ok("public, max-age=300")}, []step{
			{0, 1, nil}, {299 * time.Second, 1, nil}, {time.Second, 2, nil}}},
		"VS Code's no-store,no-cache,max-age=0 is reused for the minimum": {[]reply{ok("no-store,no-cache,max-age=0")}, []step{
			{0, 1, nil}, {MinCIMDTTL - time.Second, 1, nil}, {time.Second, 2, nil}}},
		"no header gets the minimum": {[]reply{ok("")}, []step{{0, 1, nil}, {MinCIMDTTL - time.Second, 1, nil}, {time.Second, 2, nil}}},
		"a short max-age is raised to the minimum": {[]reply{ok("max-age=30")}, []step{
			{0, 1, nil}, {MinCIMDTTL - time.Second, 1, nil}, {time.Second, 2, nil}}},
		"no-cache wins over a long max-age": {[]reply{ok("no-cache, max-age=300")}, []step{{0, 1, nil}, {MinCIMDTTL - time.Second, 1, nil}, {time.Second, 2, nil}}},
		"no-store wins over a long max-age": {[]reply{ok("no-store, max-age=300")}, []step{{0, 1, nil}, {MinCIMDTTL, 2, nil}}},
		"a long max-age is clamped to a day": {[]reply{ok("max-age=31536000")}, []step{
			{0, 1, nil}, {MaxCIMDTTL - time.Second, 1, nil}, {time.Second, 2, nil}}},
		"an error is not kept, and is refetched after MinCIMDRetry": {[]reply{gone(), ok("max-age=300")}, []step{
			{0, 1, ErrUnknownClient}, {MinCIMDRetry, 2, nil}}},
		"an invalid document is not kept, and is refetched after MinCIMDRetry": {[]reply{invalidDoc(), ok("max-age=300")}, []step{
			{0, 1, ErrUnknownClient}, {MinCIMDRetry, 2, nil}}},
		"a transient failure serves the last valid copy": {[]reply{ok("max-age=60"), transient()}, []step{
			{0, 1, nil}, {time.Minute, 2, nil}, {MaxCIMDStale - time.Minute - time.Second, 3, nil}, {time.Second, 3, ErrUnavailable}, {MinCIMDRetry, 4, ErrUnavailable}}},
		"a 4xx drops the cached copy, and the retry gap holds": {[]reply{ok("max-age=60"), gone()}, []step{
			{0, 1, nil}, {time.Minute, 2, ErrUnknownClient}, {time.Second, 2, ErrUnknownClient}}},
		"an invalid refetch drops the cached copy, and the retry gap holds": {[]reply{ok("max-age=60"), invalidDoc()}, []step{
			{0, 1, nil}, {time.Minute, 2, ErrUnknownClient}, {time.Second, 2, ErrUnknownClient}}},
		"a failing URL is not fetched again until MinCIMDRetry": {[]reply{transient()}, []step{
			{0, 1, ErrUnavailable}, {MinCIMDRetry - time.Second, 1, ErrUnavailable}, {time.Second, 2, ErrUnavailable}}},
		"a too large document is refused":                                    {[]reply{{body: doc(map[string]any{"pad": strings.Repeat("a", MaxCIMDDocBytes)})}}, []step{{0, 1, ErrUnknownClient}}},
		"an address the guard refuses is an unknown client, not unavailable": {[]reply{{err: ssrfguard.ErrRefused}}, []step{{0, 1, ErrUnknownClient}}},
		"a 404 stays an unknown client, not unavailable, during the retry gap": {[]reply{gone()}, []step{
			{0, 1, ErrUnknownClient}, {time.Second, 1, ErrUnknownClient}, {MinCIMDRetry, 2, ErrUnknownClient}}},
		"the last valid copy is served during the retry gap": {[]reply{ok("max-age=60"), transient()}, []step{
			{0, 1, nil}, {time.Minute, 2, nil}, {time.Second, 2, nil}}},
		"a 429 keeps the cached copy": {[]reply{ok("max-age=60"), {err: &ssrfguard.StatusError{Code: http.StatusTooManyRequests}}}, []step{
			{0, 1, nil}, {time.Minute, 2, nil}}},
	} {
		t.Run(name, func(t *testing.T) {
			f := &fakeFetch{replies: map[string][]reply{cimdID: tc.replies}}
			c := newClock()
			r := newReg(f, c, nil, nil)
			for i, s := range tc.steps {
				c.advance(s.after)
				cl, err := r.Client(context.Background(), cimdID)
				if (s.err == nil) != (err == nil) || (s.err != nil && !errors.Is(err, s.err)) || f.calls.Load() != s.fetches {
					t.Fatalf("step %d: err = %v (want %v), fetches = %d (want %d)", i, err, s.err, f.calls.Load(), s.fetches)
				}
				if err == nil && cl.ID() != cimdID {
					t.Fatalf("step %d: client %s", i, cl.ID())
				}
			}
		})
	}
}

func TestConcurrentLookupsShareOneFetch(t *testing.T) {
	f := &fakeFetch{replies: map[string][]reply{cimdID: {ok("max-age=300")}}, gate: make(chan struct{})}
	c := newClock()
	r := newReg(f, c, nil, nil)
	var wg sync.WaitGroup
	errs := make(chan error, 8)
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := r.Client(context.Background(), cimdID)
			errs <- err
		}()
	}
	waitForFetches(t, f, 1)
	waitForWaiters(t, r, 7) // every other lookup joined the fetch in flight
	close(f.gate)
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	if n := f.calls.Load(); n != 1 {
		t.Fatalf("fetches = %d, want 1", n)
	}
}

func TestTrustFollowsTheOperatorsHostLists(t *testing.T) {
	const other = "https://other.example/client.json"
	for name, tc := range map[string]struct {
		trusted, allowed []string
		id               string
		trust            TrustLevel
		refused          bool
	}{
		"trusted host":                     {trusted: []string{"app.example"}, id: cimdID, trust: Verified},
		"upper-case host in the client ID": {trusted: []string{"app.example"}, id: "https://App.Example/oauth/client.json", trust: Verified},
		"trusted host, any case":           {trusted: []string{"App.Example"}, id: cimdID, trust: Verified},
		"any other host":                   {trusted: []string{"other.example"}, id: cimdID, trust: Domain},
		"allowed host":                     {allowed: []string{"app.example"}, id: cimdID, trust: Domain},
		"not on the allowlist":             {allowed: []string{"app.example"}, id: other, refused: true},
		"trusted counts as allowed":        {trusted: []string{"other.example"}, allowed: []string{"app.example"}, id: other, trust: Verified},
		"a subdomain is another host":      {trusted: []string{"example"}, id: cimdID, trust: Domain},
		"a parent is not trusted, either":  {trusted: []string{"oauth.app.example"}, id: cimdID, trust: Domain},
	} {
		t.Run(name, func(t *testing.T) {
			otherDoc := doc(map[string]any{"client_id": other})
			f := &fakeFetch{replies: map[string][]reply{cimdID: {ok("")}, other: {{body: otherDoc}}}}
			if _, ok := f.replies[tc.id]; !ok {
				f.replies[tc.id] = []reply{{body: doc(map[string]any{"client_id": tc.id})}}
			}
			c := newClock()
			cl, err := newReg(f, c, tc.trusted, tc.allowed).Client(context.Background(), tc.id)
			if tc.refused {
				if !errors.Is(err, ErrUnknownClient) || f.calls.Load() != 0 {
					t.Fatalf("err = %v, fetches = %d: want refused before fetching", err, f.calls.Load())
				}
				return
			}
			if err != nil || cl.Trust() != tc.trust {
				t.Fatalf("err = %v, trust = %v, want %v", err, cl, tc.trust)
			}
		})
	}
}

func TestNonCIMDAndInvalidIDsAreNotFetched(t *testing.T) {
	f := &fakeFetch{}
	c := newClock()
	r := newReg(f, c, nil, nil)
	for _, id := range []string{"static-app", "http://app.example/client", "https://app.example/client?x=1"} {
		if _, err := r.Client(context.Background(), id); !errors.Is(err, ErrUnknownClient) {
			t.Errorf("%s: err = %v", id, err)
		}
	}
	if f.calls.Load() != 0 {
		t.Fatalf("fetches = %d", f.calls.Load())
	}
}

func TestChainAsksStaticClientsFirst(t *testing.T) {
	// A static client may use a URL as its ID; the static registry answers without a fetch.
	static, err := LoadStatic("/c.json", files{"/c.json": `{"clients":[{"client_id":"` + cimdID + `","client_name":"Static","token_endpoint_auth_method":"none","redirect_uris":["https://a.example/cb"]},
		{"client_id":"static-app","token_endpoint_auth_method":"none","redirect_uris":["https://a.example/cb"]}]}`}.read, NewStoreJTICache(memory.New()))
	if err != nil {
		t.Fatal(err)
	}
	const other = "https://app.example/other.json"
	f := &fakeFetch{replies: map[string][]reply{other: {{body: doc(map[string]any{"client_id": other})}}}}
	ch := Chain{static, newReg(f, newClock(), nil, nil)}
	if cl, err := ch.Client(context.Background(), cimdID); err != nil || cl.Name() != "Static" || f.calls.Load() != 0 {
		t.Fatalf("URL-shaped static client: %v %v, fetches %d", cl, err, f.calls.Load())
	}
	if cl, err := ch.Client(context.Background(), other); err != nil || cl.ID() != other {
		t.Fatalf("cimd: %v %v", cl, err)
	}
	if _, err := ch.Client(context.Background(), "nobody"); !errors.Is(err, ErrUnknownClient) {
		t.Fatalf("unknown: %v", err)
	}
}

// A document listing several methods lets the client use any of them (draft -03 §5); keys come
// inline or from jwks_uri.
func TestCIMDClientsAuthenticateWithAnyListedMethod(t *testing.T) {
	e := newAuthEnv(t)
	good := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(publicJWKS(t, e.cert))) }))
	t.Cleanup(good.Close)
	down := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusServiceUnavailable) }))
	t.Cleanup(down.Close)
	gone := httptest.NewServer(http.NotFoundHandler())
	t.Cleanup(gone.Close)
	garbage := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("<html>")) }))
	t.Cleanup(garbage.Close)
	jwksAt := map[string]any{"token_endpoint_auth_method": "private_key_jwt", "jwks_uri": "https://keys.example/jwks"}
	var weakSet jose.JSONWebKeySet
	_ = json.Unmarshal([]byte(weakJWKS(t)), &weakSet)
	weakSet.Keys[0].KeyID = "k0" // the assertion's kid: the key is found, then refused by the key rules
	weak, _ := json.Marshal(weakSet)
	weakKeys := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(weak) }))
	t.Cleanup(weakKeys.Close)
	both := []string{"private_key_jwt", "none"}
	for name, tc := range map[string]struct {
		fields   map[string]any
		jwtOK    bool
		noneOK   bool
		keysFrom string
		keys     *http.Client // instead of keysFrom
		jwtErr   string       // in the private_key_jwt error, when set
		// unavailable: the private_key_jwt failure is temporary (ErrUnavailable, a 503 at /token);
		// otherwise any failure is a definite refusal.
		unavailable bool
		refused     bool // the keys are definitely unusable (ErrKeysRefused), not the assertion
	}{
		"inline keys, both methods": {fields: map[string]any{"token_endpoint_auth_methods_supported": both, "jwks": json.RawMessage(publicJWKS(t, e.cert))}, jwtOK: true, noneOK: true},
		"jwks_uri, jwt only":        {fields: map[string]any{"token_endpoint_auth_method": "private_key_jwt", "jwks_uri": "https://keys.example/jwks"}, jwtOK: true, keysFrom: good.URL},
		"none only":                 {fields: nil, noneOK: true},
		// A keys host that fails for now is a temporary failure, not a refused authentication.
		"jwks_uri answering 503":          {fields: jwksAt, keysFrom: down.URL, unavailable: true},
		"jwks_uri unreachable":            {fields: jwksAt, keysFrom: "", unavailable: true},
		"jwks_uri answering 404":          {fields: jwksAt, keysFrom: gone.URL, refused: true},
		"jwks_uri not JSON":               {fields: jwksAt, keysFrom: garbage.URL, refused: true},
		"jwks_uri serving a weak RSA key": {fields: jwksAt, keysFrom: weakKeys.URL, refused: true}, // breaks the registered-key rules
		// jwks_uri goes through the SSRF guard (whose refusal the key set's error carries as text).
		"jwks_uri on a private address": {fields: map[string]any{"token_endpoint_auth_method": "private_key_jwt", "jwks_uri": "https://127.0.0.1/jwks"},
			keys: ssrfguard.New(ssrfguard.Config{}).HTTPClient(), jwtErr: ssrf.ErrProhibitedIP.Error(), refused: true},
	} {
		t.Run(name, func(t *testing.T) {
			keysClient := tc.keys
			if keysClient == nil {
				keysClient = &http.Client{Transport: rewrite(tc.keysFrom)}
			}
			f := &fakeFetch{replies: map[string][]reply{cimdID: {{body: doc(tc.fields)}}}}
			r := NewCIMDRegistry(CIMDConfig{Fetch: f, KeysClient: keysClient, JTI: e.jti, Now: func() time.Time { return now }})
			c, err := r.Client(context.Background(), cimdID)
			if err != nil {
				t.Fatal(err)
			}
			form := e.assertion(t, e.cert, "PS256", map[string]any{"iss": cimdID, "sub": cimdID})
			form.Set("client_id", cimdID)
			err = c.Authenticate(context.Background(), form, http.Header{}, tokenEndpoint, now)
			if (err == nil) != tc.jwtOK || (tc.jwtErr != "" && !strings.Contains(fmt.Sprint(err), tc.jwtErr)) || errors.Is(err, ErrUnavailable) != tc.unavailable || errors.Is(err, ErrKeysRefused) != tc.refused {
				t.Fatalf("private_key_jwt: err = %v, want ok %v (error containing %q), temporary %v, keys refused %v", err, tc.jwtOK, tc.jwtErr, tc.unavailable, tc.refused)
			}
			if err := c.Authenticate(context.Background(), url.Values{"client_id": {cimdID}}, http.Header{}, tokenEndpoint, now); (err == nil) != tc.noneOK {
				t.Fatalf("none: err = %v, want ok %v", err, tc.noneOK)
			}
		})
	}
}

// rewrite sends every request to target (a plain-HTTP test server); "" fails every request.
type rewrite string

func (r rewrite) RoundTrip(req *http.Request) (*http.Response, error) {
	if r == "" {
		return nil, errors.New("no key server")
	}
	u, _ := url.Parse(string(r))
	out := req.Clone(req.Context())
	out.URL.Scheme, out.URL.Host = u.Scheme, u.Host
	return http.DefaultTransport.RoundTrip(out)
}

// Keys fetched from a jwks_uri get the registered-JWKS rules: public keys only, RSA ≥ MinRSABits.
func TestKeysFromAJWKSURIFollowTheRegisteredKeyRules(t *testing.T) {
	cert := fakeidp.NewCertificate(t)
	var weak jose.JSONWebKeySet
	if err := json.Unmarshal([]byte(weakJWKS(t)), &weak); err != nil {
		t.Fatal(err)
	}
	for name, tc := range map[string]struct {
		key jose.JSONWebKey
		ok  bool
	}{
		"public RSA 2048": {key: jose.JSONWebKey{Key: &cert.Key.PublicKey, KeyID: "k", Use: "sig"}, ok: true},
		"private key":     {key: jose.JSONWebKey{Key: cert.Key, KeyID: "k", Use: "sig"}},
		"weak RSA":        {key: jose.JSONWebKey{Key: weak.Keys[0].Key, KeyID: "k", Use: "sig"}},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := clientKeys{fixedKey{tc.key}}.Key(context.Background(), "k")
			if (err == nil) != tc.ok || (err != nil && !errors.Is(err, ErrKeysRefused)) {
				t.Fatalf("err = %v, want ok %v", err, tc.ok)
			}
		})
	}
}

type fixedKey struct{ k jose.JSONWebKey }

func (f fixedKey) Key(context.Context, string) (*jose.JSONWebKey, error) { return &f.k, nil }

func TestFetchOutcomesAreObserved(t *testing.T) {
	f := &fakeFetch{replies: map[string][]reply{cimdID: {gone(), invalidDoc(), transient(), ok("")}}}
	c := newClock()
	r, outcomes := newObservedReg(f, c)
	for _, d := range []time.Duration{0, time.Second, MinCIMDRetry, MinCIMDRetry, MinCIMDRetry} {
		c.advance(d)
		_, _ = r.Client(context.Background(), cimdID)
	}
	want := []string{FetchRefused, FetchRateLimited, FetchInvalid, FetchUnavailable, FetchOK}
	if got := outcomes(); !slices.Equal(got, want) {
		t.Fatalf("outcomes %v, want %v", got, want)
	}
}

// The retry gap is per URL: another URL is still fetched while one is waiting.
func TestTheRetryGapIsPerURL(t *testing.T) {
	const other = "https://app.example/other.json"
	f := &fakeFetch{replies: map[string][]reply{cimdID: {transient()}, other: {{body: doc(map[string]any{"client_id": other})}}}}
	c := newClock()
	r := newReg(f, c, nil, nil)
	if _, err := r.Client(context.Background(), cimdID); !errors.Is(err, ErrUnavailable) {
		t.Fatal(err)
	}
	if cl, err := r.Client(context.Background(), other); err != nil || cl.ID() != other || f.calls.Load() != 2 {
		t.Fatalf("other URL: %v, %v, fetches %d", cl, err, f.calls.Load())
	}
}

// Lookups waiting on a fetch get its failure, and a waiter whose request ends gives up at once.
func TestWaitersGetTheFetchOutcomeOrGiveUp(t *testing.T) {
	f := &fakeFetch{replies: map[string][]reply{cimdID: {transient()}}, gate: make(chan struct{})}
	c := newClock()
	r := newReg(f, c, nil, nil)
	first := make(chan error, 1)
	go func() { _, err := r.Client(context.Background(), cimdID); first <- err }()
	waitForFetches(t, f, 1)
	waiter := make(chan error, 1)
	go func() { _, err := r.Client(context.Background(), cimdID); waiter <- err }()
	waitForWaiters(t, r, 1)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	start := time.Now()
	if _, err := r.Client(ctx, cimdID); !errors.Is(err, ErrUnavailable) || time.Since(start) > time.Second {
		t.Fatalf("cancelled waiter: %v after %v, want ErrUnavailable at once", err, time.Since(start))
	}
	close(f.gate)
	if err := <-first; !errors.Is(err, ErrUnavailable) {
		t.Fatalf("fetching lookup: %v", err)
	}
	if err := <-waiter; !errors.Is(err, ErrUnavailable) || strings.Contains(err.Error(), "rate-limited") {
		t.Fatalf("waiting lookup: %v, want the fetch's own failure", err)
	}
	if n := f.calls.Load(); n != 1 {
		t.Fatalf("fetches = %d, want 1", n)
	}
}

// No more than MaxCIMDInFlight fetches run at once; the next one is busy (unavailable) at once.
func TestFetchesInFlightAreCapped(t *testing.T) {
	f := &fakeFetch{replies: map[string][]reply{}, gate: make(chan struct{})}
	ids := docIDs(f, MaxCIMDInFlight+1, "")
	r, outcomes := newObservedReg(f, newClock())
	var wg sync.WaitGroup
	for _, id := range ids[:MaxCIMDInFlight] {
		wg.Add(1)
		go func() { defer wg.Done(); _, _ = r.Client(context.Background(), id) }()
	}
	waitForFetches(t, f, MaxCIMDInFlight)
	_, err := r.Client(context.Background(), ids[MaxCIMDInFlight])
	close(f.gate)
	wg.Wait()
	if !errors.Is(err, ErrUnavailable) || f.calls.Load() != MaxCIMDInFlight || !slices.Contains(outcomes(), FetchBusy) {
		t.Fatalf("err = %v, fetches = %d, outcomes %v", err, f.calls.Load(), outcomes())
	}
}

// The cache holds at most MaxCIMDEntries documents and evicts the one that expires first; the log
// of failed attempts stays bounded too.
func TestTheCacheIsBounded(t *testing.T) {
	f := &fakeFetch{replies: map[string][]reply{}}
	ids := docIDs(f, MaxCIMDEntries+1, "max-age=3600")
	mid := MaxCIMDEntries / 2                    // neither the first inserted nor the last
	f.replies[ids[mid]][0].cache = "max-age=120" // expires first
	f.replies[ids[2]][0].cache = "max-age=7200"  // expires last
	c := newClock()
	r := newReg(f, c, nil, nil)
	for i := range MaxCIMDEntries + 1 {
		if _, err := r.Client(context.Background(), ids[i]); err != nil {
			t.Fatal(err)
		}
	}
	if len(r.entries) != MaxCIMDEntries {
		t.Fatalf("a full cache holds %d entries, want exactly %d", len(r.entries), MaxCIMDEntries)
	}
	before := f.calls.Load()
	_, _ = r.Client(context.Background(), ids[0])
	_, _ = r.Client(context.Background(), ids[1])
	if f.calls.Load() != before {
		t.Fatal("an early entry was evicted; the first-expiring entry should have been")
	}
	_, _ = r.Client(context.Background(), ids[mid])
	if len(r.entries) != MaxCIMDEntries || f.calls.Load() != before+1 {
		t.Fatalf("entries %d, fetches after %d (want %d): the first-expiring entry should be the one evicted", len(r.entries), f.calls.Load(), before+1)
	}
	// Refreshing a cached entry in a full cache replaces it in place and evicts nothing else: ids[2]
	// expires last, so any other entry would be the victim.
	c.advance(2*time.Hour + time.Second)
	if _, err := r.Client(context.Background(), ids[2]); err != nil || len(r.entries) != MaxCIMDEntries {
		t.Fatalf("refreshing a cached entry in a full cache: %v, %d entries, want %d", err, len(r.entries), MaxCIMDEntries)
	}
	for i := range 2 * MaxCIMDEntries {
		_, _ = r.Client(context.Background(), fmt.Sprintf("https://app.example/missing%d.json", i))
		c.advance(MinCIMDRetry / 100)
	}
	if len(r.attempts) > MaxCIMDEntries+1 {
		t.Fatalf("attempt log holds %d URLs", len(r.attempts))
	}
}

// waitForWaiters blocks until n lookups wait on the fetch in flight for cimdID.
func waitForWaiters(t *testing.T, r *CIMDRegistry, n int) {
	t.Helper()
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(time.Millisecond) {
		r.mu.Lock()
		call := r.inflight[cimdID]
		joined := call != nil && call.waiters >= n
		r.mu.Unlock()
		if joined {
			return
		}
	}
	t.Fatalf("%d lookups never joined the fetch", n)
}

// The fetch is shared, so the request that started it leaving does not fail the others: the
// document is still fetched and cached.
func TestTheSharedFetchOutlivesTheRequestThatStartedIt(t *testing.T) {
	f := &fakeFetch{replies: map[string][]reply{cimdID: {ok("max-age=300")}}, gate: make(chan struct{})}
	r := newReg(f, newClock(), nil, nil)
	ctx, cancel := context.WithCancel(context.Background())
	first := make(chan error, 1)
	go func() { _, err := r.Client(ctx, cimdID); first <- err }()
	waitForFetches(t, f, 1)
	waiter := make(chan error, 1)
	go func() { _, err := r.Client(context.Background(), cimdID); waiter <- err }()
	waitForWaiters(t, r, 1)
	cancel()
	close(f.gate)
	if err := <-waiter; err != nil {
		t.Fatalf("waiter: %v", err)
	}
	if err := <-first; err != nil {
		t.Fatalf("the lookup that started the fetch: %v (its request ending must not fail the shared fetch)", err)
	}
	if _, err := r.Client(context.Background(), cimdID); err != nil || f.calls.Load() != 1 {
		t.Fatalf("cached lookup: %v, fetches %d", err, f.calls.Load())
	}
}

// When every fetch slot is busy, a client with a copy inside the stale window keeps working.
func TestABusyRefetchServesTheLastValidCopy(t *testing.T) {
	f := &fakeFetch{replies: map[string][]reply{}}
	ids := docIDs(f, MaxCIMDInFlight+1, "max-age=60")
	c := newClock()
	r, outcomes := newObservedReg(f, c)
	last := ids[MaxCIMDInFlight]
	if _, err := r.Client(context.Background(), last); err != nil {
		t.Fatal(err)
	}
	c.advance(time.Minute) // expired, inside the stale window
	f.gate = make(chan struct{})
	var wg sync.WaitGroup
	for _, id := range ids[:MaxCIMDInFlight] {
		wg.Add(1)
		go func() { defer wg.Done(); _, _ = r.Client(context.Background(), id) }()
	}
	waitForFetches(t, f, MaxCIMDInFlight+1)
	cl, err := r.Client(context.Background(), last)
	close(f.gate)
	wg.Wait()
	if err != nil || cl.ID() != last || !slices.Contains(outcomes(), FetchBusy) {
		t.Fatalf("client %v, err %v, outcomes %v", cl, err, outcomes())
	}
}

// waitForFetches blocks until f has started n fetches.
func waitForFetches(t *testing.T, f *fakeFetch, n int32) {
	t.Helper()
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(time.Millisecond) {
		if f.calls.Load() >= n {
			return
		}
	}
	t.Fatalf("%d fetches started, want %d", f.calls.Load(), n)
}

// docIDs gives f a valid document for n URLs on one host and returns them.
func docIDs(f *fakeFetch, n int, cache string) []string {
	ids := make([]string, n)
	for i := range ids {
		ids[i] = fmt.Sprintf("https://app.example/c%d.json", i)
		f.replies[ids[i]] = []reply{{body: doc(map[string]any{"client_id": ids[i]}), cache: cache}}
	}
	return ids
}

// newObservedReg is a registry whose fetch outcomes are recorded; outcomes returns them so far.
func newObservedReg(f *fakeFetch, c *clock) (r *CIMDRegistry, outcomes func() []string) {
	var mu sync.Mutex
	var got []string
	r = NewCIMDRegistry(CIMDConfig{Fetch: f, JTI: NewStoreJTICache(memory.New()), Now: c.now,
		Observe: func(o string) { mu.Lock(); got = append(got, o); mu.Unlock() }})
	return r, func() []string { mu.Lock(); defer mu.Unlock(); return slices.Clone(got) }
}

// Pruning the attempt log only forgets attempts older than the retry gap: with more than
// MaxCIMDEntries failures inside one gap, an early one is still not refetched.
func TestPruningKeepsAttemptsInsideTheRetryGap(t *testing.T) {
	f := &fakeFetch{replies: map[string][]reply{}}
	c := newClock()
	r := newReg(f, c, nil, nil)
	url := func(i int) string { return fmt.Sprintf("https://app.example/missing%d.json", i) }
	for i := range MaxCIMDEntries + 2 { // the last insertions prune
		_, _ = r.Client(context.Background(), url(i))
		c.advance(MinCIMDRetry / (2 * MaxCIMDEntries))
	}
	n := f.calls.Load()
	if _, err := r.Client(context.Background(), url(0)); !errors.Is(err, ErrUnknownClient) || f.calls.Load() != n {
		t.Fatalf("a failure inside the retry gap was refetched after pruning: %v, fetches %d -> %d", err, n, f.calls.Load())
	}
}

// Documents are fetched with the draft's 5 KB limit (§10.11); the guard enforces whatever limit it
// is given, so the registry's value is what matters.
func TestDocumentsAreFetchedWithTheFiveKilobyteLimit(t *testing.T) {
	f := &fakeFetch{replies: map[string][]reply{cimdID: {ok("")}}}
	if _, err := newReg(f, newClock(), nil, nil).Client(context.Background(), cimdID); err != nil {
		t.Fatal(err)
	}
	if got := f.max.Load(); got != 5<<10 {
		t.Fatalf("fetched with a %d-byte limit, want 5120", got)
	}
}

// ErrMetadataRefused is reserved for a document that was fetched, or definitely refused, and found
// unacceptable; refresh revokes grants only for it.
func TestOnlyARefusedDocumentIsErrMetadataRefused(t *testing.T) {
	for name, tc := range map[string]struct {
		id      string
		allowed []string
		reply   reply
		refused bool
	}{
		"a 404":                         {id: cimdID, reply: gone(), refused: true},
		"an invalid document":           {id: cimdID, reply: invalidDoc(), refused: true},
		"an address the guard refuses":  {id: cimdID, reply: reply{err: ssrfguard.ErrRefused}, refused: true},
		"a host off the allowlist":      {id: cimdID, allowed: []string{"other.example"}, reply: ok("")},
		"a client ID that is not valid": {id: "https://app.example/client?x=1", reply: ok("")},
		"a static client ID":            {id: "static-app", reply: ok("")},
	} {
		t.Run(name, func(t *testing.T) {
			f := &fakeFetch{replies: map[string][]reply{tc.id: {tc.reply}}}
			c := newClock()
			r := newReg(f, c, nil, tc.allowed)
			_, err := r.Client(context.Background(), tc.id)
			if !errors.Is(err, ErrUnknownClient) || errors.Is(err, ErrMetadataRefused) != tc.refused {
				t.Fatalf("err = %v, want ErrUnknownClient, refused document %v", err, tc.refused)
			}
			if tc.refused { // still a refused document during the retry gap
				c.advance(time.Second)
				if _, err := r.Client(context.Background(), tc.id); !errors.Is(err, ErrMetadataRefused) {
					t.Fatalf("during the retry gap: %v", err)
				}
			}
		})
	}
}
