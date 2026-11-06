package idp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"

	"github.com/corker/mcp-authproxy/internal/testutil/fakeidp"
)

// jwksServer proxies a fake IdP's JWKS, counts fetches, and can fail them or hold them open.
type jwksServer struct {
	srv     *httptest.Server
	hits    atomic.Int32
	done    atomic.Int32 // fetches that have finished, served or not
	fail    atomic.Bool
	gate    atomic.Pointer[chan struct{}] // when set, a fetch waits on it
	entered chan struct{}                 // receives one value per fetch that reaches the gate
}

func newJWKSServer(t *testing.T, f *fakeidp.IdP) *jwksServer {
	t.Helper()
	js := &jwksServer{entered: make(chan struct{}, 64)}
	js.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		js.hits.Add(1)
		defer js.done.Add(1)
		if g := js.gate.Load(); g != nil {
			js.entered <- struct{}{}
			select {
			case <-*g:
			case <-r.Context().Done():
				return
			}
		}
		if js.fail.Load() {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		resp, err := http.Get(f.JWKSURL(""))
		if err != nil {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		defer func() { _ = resp.Body.Close() }()
		var body json.RawMessage
		_ = json.NewDecoder(resp.Body).Decode(&body)
		_, _ = w.Write(body)
	}))
	t.Cleanup(js.srv.Close)
	return js
}

// hold makes fetches wait until the returned release is called; release also runs at cleanup
// (before the server closes), so a failing test never hangs on a held fetch.
func (js *jwksServer) hold(t *testing.T) (release func()) {
	g := make(chan struct{})
	js.gate.Store(&g)
	release = sync.OnceFunc(func() { close(g) })
	t.Cleanup(release)
	return release
}

func testClock() *fakeidp.Clock { return fakeidp.NewClock(time.Unix(1_800_000_000, 0)) }

func noBackoff() *Fetcher {
	f := NewFetcher(nil)
	f.Backoff = 0
	return f
}

func TestKeySetRateLimitsRefetchForUnknownKid(t *testing.T) {
	f := fakeidp.New(t, fakeidp.Generic)
	js := newJWKSServer(t, f)
	c := testClock()
	ks := NewKeySet(NewFetcher(nil), js.srv.URL, c.Now)
	ctx := context.Background()
	if _, err := ks.Key(ctx, jwksKid(t, f)); err != nil {
		t.Fatal(err)
	}
	for range 3 {
		_, err := ks.Key(ctx, "unknown")
		if err == nil || errors.Is(err, ErrKeysUnavailable) || TokenCheckError(err, "").Class != Fatal {
			t.Fatalf("unknown kid with a healthy JWKS: %v", err)
		}
	}
	if n := js.hits.Load(); n != 1 {
		t.Fatalf("fetches = %d, want 1 (cached, rate-limited)", n)
	}
	f.RotateKeys(t)
	c.Advance(MinJWKSRefresh)
	if _, err := ks.Key(ctx, jwksKid(t, f)); err != nil {
		t.Fatalf("rotated key not found after the interval: %v", err)
	}
	if n := js.hits.Load(); n != 2 {
		t.Fatalf("fetches = %d, want 2", n)
	}
}

func TestKeySetKeepsLastGoodSetWhileTheIdPIsDownAndRecovers(t *testing.T) {
	f := fakeidp.New(t, fakeidp.Generic)
	js := newJWKSServer(t, f)
	c := testClock()
	ks := NewKeySet(noBackoff(), js.srv.URL, c.Now)
	ctx := context.Background()
	kid := jwksKid(t, f)
	if _, err := ks.Key(ctx, kid); err != nil {
		t.Fatal(err)
	}
	js.fail.Store(true)
	c.Advance(MinJWKSRefresh)
	if _, err := ks.Key(ctx, "other"); !errors.Is(err, ErrKeysUnavailable) {
		t.Fatalf("miss while the IdP is down: %v", err)
	}
	hits := js.hits.Load()
	if _, err := ks.Key(ctx, "other"); !errors.Is(err, ErrKeysUnavailable) || js.hits.Load() != hits {
		t.Fatalf("second miss in the interval: %v, fetches %d -> %d", err, hits, js.hits.Load())
	}
	if _, err := ks.Key(ctx, kid); err != nil {
		t.Fatalf("last good key lost: %v", err)
	}
	js.fail.Store(false)
	c.Advance(MinJWKSRefresh)
	if _, err := ks.Key(ctx, "other"); err == nil || errors.Is(err, ErrKeysUnavailable) {
		t.Fatalf("after recovery a missing kid must be unknown, not unavailable: %v", err)
	}
}

func TestKeySetFirstFetchFailureIsUnavailableAndNotRetriedWithinInterval(t *testing.T) {
	f := fakeidp.New(t, fakeidp.Generic)
	js := newJWKSServer(t, f)
	js.fail.Store(true)
	c := testClock()
	ks := NewKeySet(noBackoff(), js.srv.URL, c.Now)
	if _, err := ks.Key(context.Background(), "k"); !errors.Is(err, ErrKeysUnavailable) {
		t.Fatalf("err = %v", err)
	}
	hits := js.hits.Load()
	if _, err := ks.Key(context.Background(), "k"); !errors.Is(err, ErrKeysUnavailable) || js.hits.Load() != hits {
		t.Fatalf("second call: %v, fetches %d -> %d", err, hits, js.hits.Load())
	}
}

// Before the fix, a cancelled caller recorded the refetch time, so after a rotation every later
// caller got "unknown key id" for MinJWKSRefresh.
func TestKeySetRefetchCompletesAfterCallerCancels(t *testing.T) {
	f := fakeidp.New(t, fakeidp.Generic)
	js := newJWKSServer(t, f)
	c := testClock()
	ks := NewKeySet(NewFetcher(nil), js.srv.URL, c.Now)
	if _, err := ks.Key(context.Background(), jwksKid(t, f)); err != nil {
		t.Fatal(err)
	}
	f.RotateKeys(t)
	c.Advance(MinJWKSRefresh)
	rotated := jwksKid(t, f)
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := ks.Key(cancelled, rotated); !errors.Is(err, context.Canceled) || !errors.Is(err, ErrKeysUnavailable) {
		t.Fatalf("cancelled caller: %v", err)
	}
	if _, err := ks.Key(context.Background(), rotated); err != nil {
		t.Fatalf("live caller after a cancelled one: %v", err)
	}
	if n := js.hits.Load(); n != 2 {
		t.Fatalf("fetches = %d, want 2 (the warm-up and one refetch)", n)
	}
}

func TestKeySetWaitingCallerDeadlineIsUnavailable(t *testing.T) {
	f := fakeidp.New(t, fakeidp.Generic)
	js := newJWKSServer(t, f)
	js.hold(t)
	ks := NewKeySet(NewFetcher(nil), js.srv.URL, testClock().Now)
	ctx, cancel := context.WithDeadline(context.Background(), time.Unix(0, 0)) // already past
	defer cancel()
	_, err := ks.Key(ctx, "k")
	if !errors.Is(err, context.DeadlineExceeded) || TokenCheckError(err, "hint").Class != Unavailable {
		t.Fatalf("err = %v", err)
	}
}

func TestKeySetCachedLookupIsNotBlockedByARefetch(t *testing.T) {
	f := fakeidp.New(t, fakeidp.Generic)
	js := newJWKSServer(t, f)
	c := testClock()
	ks := NewKeySet(NewFetcher(nil), js.srv.URL, c.Now)
	old := jwksKid(t, f)
	if _, err := ks.Key(context.Background(), old); err != nil {
		t.Fatal(err)
	}
	release := js.hold(t)
	c.Advance(MinJWKSRefresh)
	missed := make(chan error, 1)
	go func() { _, err := ks.Key(context.Background(), "rotated-away"); missed <- err }()
	<-js.entered // the refetch is in flight and held
	// A cached key is returned before ctx is looked at, so an already-cancelled context proves the
	// lookup did not wait for the held refetch (it would return context.Canceled otherwise).
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := ks.Key(cancelled, old); err != nil {
		t.Fatalf("cached lookup waited for the refetch: %v", err)
	}
	if n := js.done.Load(); n != 1 { // only the warm-up has finished: the refetch is still held
		t.Fatalf("cached lookup returned after the held refetch ended (%d fetches done)", n)
	}
	release()
	if err := <-missed; err == nil || errors.Is(err, ErrKeysUnavailable) {
		t.Fatalf("rotated-away kid: %v, want unknown kid", err)
	}
}

func TestKeySetConcurrentMissesShareOneRefetch(t *testing.T) {
	f := fakeidp.New(t, fakeidp.Generic)
	js := newJWKSServer(t, f)
	release := js.hold(t)
	ks := NewKeySet(NewFetcher(nil), js.srv.URL, testClock().Now)
	kid := jwksKid(t, f)
	const callers = 8
	var started sync.WaitGroup
	errs := make(chan error, callers)
	for range callers {
		started.Add(1)
		go func() {
			started.Done()
			_, err := ks.Key(context.Background(), kid)
			errs <- err
		}()
	}
	started.Wait()
	<-js.entered // one fetch is held; every caller either joined it or is about to
	release()
	for range callers {
		if err := <-errs; err != nil {
			t.Fatal(err)
		}
	}
	if n := js.hits.Load(); n != 1 {
		t.Fatalf("JWKS fetched %d times, want 1", n)
	}
}

func TestTokenCheckError(t *testing.T) {
	for name, tc := range map[string]struct {
		err      error
		class    Class
		keepHint bool
	}{
		"keys unavailable":        {ErrKeysUnavailable, Unavailable, false},
		"wrapped twice":           {fmt.Errorf("a: %w", fmt.Errorf("b: %w", ErrKeysUnavailable)), Unavailable, false},
		"bad signature":           {errors.New("idp: JWT signature: crypto"), Fatal, true},
		"cancel without sentinel": {context.Canceled, Fatal, true},
	} {
		t.Run(name, func(t *testing.T) {
			e := TokenCheckError(tc.err, "fix it")
			if e.Class != tc.class || (e.OperatorHint == "fix it") != tc.keepHint || !errors.Is(e, tc.err) {
				t.Fatalf("got %+v", e)
			}
		})
	}
}

type unavailableKeys struct{}

func (unavailableKeys) Key(context.Context, string) (*jose.JSONWebKey, error) {
	return nil, fmt.Errorf("down: %w", ErrKeysUnavailable)
}

func TestVerifyJWTPassesKeyOutagesThrough(t *testing.T) {
	f := fakeidp.New(t, fakeidp.Generic)
	raw := f.Mint(map[string]any{"iss": "i", "aud": "c", "sub": "s"})
	_, err := VerifyJWT(context.Background(), raw, unavailableKeys{}, TokenRules{
		Issuer: func(string, map[string]any) error { return nil }, ClientID: "c",
		Algs: []jose.SignatureAlgorithm{jose.RS256}, Now: time.Now})
	if !errors.Is(err, ErrKeysUnavailable) {
		t.Fatalf("err = %v", err)
	}
}

func TestFetcherBudgetCoversItsRetries(t *testing.T) {
	f := NewFetcher(&http.Client{Timeout: 2 * time.Second})
	f.Retries, f.Backoff = 3, 100*time.Millisecond
	if b := f.budget(); b < 4*2*time.Second+400*time.Millisecond {
		t.Fatalf("budget %v is shorter than 4 attempts and their backoff", b)
	}
	if b := NewFetcher(&http.Client{}).budget(); b < 3*DefaultTimeout {
		t.Fatalf("no client timeout: budget %v", b)
	}
}
