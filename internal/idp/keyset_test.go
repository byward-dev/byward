package idp

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
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

func testClock() *fakeidp.Clock { return fakeidp.NewClock(fixedNow) }

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
		if _, err := ks.Key(ctx, "unknown"); err == nil || errors.Is(err, ErrKeysUnavailable) {
			t.Fatalf("unknown kid with a healthy JWKS must be unknown, not unavailable: %v", err)
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
	ks := NewKeySet(noBackoff(), js.srv.URL, testClock().Now)
	_, err := ks.Key(context.Background(), "k")
	if !errors.Is(err, ErrKeysUnavailable) || !strings.Contains(err.Error(), "status 503") {
		t.Fatalf("err = %v, want unavailable with the fetch cause", err)
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
	release := js.hold(t) // the refetch cannot finish before the cancelled caller notices
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := ks.Key(cancelled, rotated); !errors.Is(err, context.Canceled) || !errors.Is(err, ErrKeysUnavailable) {
		t.Fatalf("cancelled caller: %v", err)
	}
	release()
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
	release := js.hold(t)
	ks := NewKeySet(NewFetcher(nil), js.srv.URL, testClock().Now)
	ctx, cancel := context.WithDeadline(context.Background(), time.Unix(0, 0)) // already past
	defer cancel()
	if _, err := ks.Key(ctx, "k"); !errors.Is(err, context.DeadlineExceeded) || !errors.Is(err, ErrKeysUnavailable) {
		t.Fatalf("err = %v", err)
	}
	<-js.entered
	release()
	_, _ = ks.Key(context.Background(), "k") // waits for the background refetch to finish
}

// With a client that has no timeout, the refetch's own deadline is the only bound on a hung IdP.
func TestKeySetRefetchDeadlineEndsAHungFetch(t *testing.T) {
	f := fakeidp.New(t, fakeidp.Generic)
	js := newJWKSServer(t, f)
	js.hold(t) // never released during the test: the IdP hangs
	fe := NewFetcher(&http.Client{})
	fe.Retries = 0
	ks := NewKeySet(fe, js.srv.URL, testClock().Now)
	ks.refetchTimeout = 20 * time.Millisecond
	// The caller's own bound is far longer, so ending in time proves the refetch deadline worked.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := ks.Key(ctx, "k"); !errors.Is(err, ErrKeysUnavailable) || ctx.Err() != nil {
		t.Fatalf("hung IdP: %v (caller context: %v), want the refetch to time out before the caller does", err, ctx.Err())
	}
	// The refetch has ended, so a second miss does not wait: an already-cancelled context is
	// never consulted.
	cancelled, stop := context.WithCancel(context.Background())
	stop()
	if _, err := ks.Key(cancelled, "k"); !errors.Is(err, ErrKeysUnavailable) || errors.Is(err, context.Canceled) {
		t.Fatalf("second miss waited on a refetch: %v", err)
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
	const callers = 8
	waiting := make(chan struct{}, callers)
	ks.onWait = func() { waiting <- struct{}{} }
	kid := jwksKid(t, f)
	errs := make(chan error, callers)
	for range callers {
		go func() { _, err := ks.Key(context.Background(), kid); errs <- err }()
	}
	for range callers { // every caller is waiting on a refetch while the first fetch is held
		<-waiting
	}
	release()
	for range callers {
		if err := <-errs; err != nil {
			t.Fatal(err)
		}
	}
	if n := js.hits.Load(); n != 1 {
		t.Fatalf("JWKS fetched %d times for %d concurrent misses, want 1", n, callers)
	}
}

func TestKeySetLookupUsesOnlySigningKeys(t *testing.T) {
	sig := func(kid string) map[string]any {
		k := map[string]any{}
		raw, _ := json.Marshal(jose.JSONWebKey{Key: &fakeidp.NewCertificate(t).Key.PublicKey, KeyID: kid, Use: "sig"})
		_ = json.Unmarshal(raw, &k)
		return k
	}
	withUse := func(k map[string]any, use string) map[string]any {
		if use == "" {
			delete(k, "use")
		} else {
			k["use"] = use
		}
		return k
	}
	for name, tc := range map[string]struct {
		keys  []map[string]any
		kid   string
		found bool
	}{
		"one sig key, no kid":       {keys: []map[string]any{sig("a")}, found: true},
		"two sig keys, no kid":      {keys: []map[string]any{sig("a"), sig("b")}},
		"one enc key, no kid":       {keys: []map[string]any{withUse(sig("a"), "enc")}},
		"enc key with matching kid": {keys: []map[string]any{withUse(sig("a"), "enc")}, kid: "a"},
		"key without use":           {keys: []map[string]any{withUse(sig("a"), "")}, kid: "a", found: true},
		"enc and sig, no kid":       {keys: []map[string]any{withUse(sig("a"), "enc"), sig("b")}, found: true},
	} {
		t.Run(name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				_ = json.NewEncoder(w).Encode(map[string]any{"keys": tc.keys})
			}))
			defer srv.Close()
			_, err := NewKeySet(NewFetcher(nil), srv.URL, func() time.Time { return fixedNow }).Key(context.Background(), tc.kid)
			if (err == nil) != tc.found {
				t.Fatalf("err = %v, want found %v", err, tc.found)
			}
		})
	}
}
