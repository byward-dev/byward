package ssrfguard

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"code.dny.dev/ssrf"

	"github.com/byward-dev/byward/internal/testutil/rawanswer"
	"github.com/byward-dev/byward/internal/testutil/rerun"
)

// The guard fetches https URLs with a host and no user information on the default port, given or
// not; registration checks a client's jwks_uri by the same rule.
func TestFetchableIsHTTPSOnTheDefaultPort(t *testing.T) {
	for raw, want := range map[string]bool{
		"https://app.example/jwks":      true,
		"https://app.example:443/jwks":  true,
		"https://app.example:8443/jwks": false,
		"http://app.example/jwks":       false,
		"https://u:p@app.example/jwks":  false,
		"https:///jwks":                 false,
		"https:app.example/jwks":        false,
	} {
		u, err := url.Parse(raw)
		if err != nil {
			t.Fatal(err)
		}
		if got := Fetchable(u); got != want {
			t.Errorf("Fetchable(%s) = %v, want %v", raw, got, want)
		}
	}
}

// The guard refuses before connecting, so these never reach the network.
func TestNonPublicAddressesAreRefused(t *testing.T) {
	f := New(Config{})
	for _, u := range []string{
		"https://127.0.0.1/doc",
		"https://[::1]/doc",
		"https://10.0.0.1/doc",
		"https://172.16.0.1/doc",
		"https://192.168.1.1/doc",
		"https://169.254.169.254/latest/meta-data",
		"https://100.64.0.1/doc",
		"https://0.0.0.0/doc",
		"https://198.18.0.1/doc",
		"https://240.0.0.1/doc",
		"https://[fc00::1]/doc",
		"https://[fe80::1]/doc",
		"https://[::ffff:127.0.0.1]/doc",
		"https://[64:ff9b::7f00:1]/doc",
		// A name is checked after DNS, on the address actually dialled: localhost resolves to a
		// loopback address. This is also the DNS rebinding case: there is no earlier lookup whose
		// public answer a later private one could replace.
		"https://localhost/doc",
	} {
		t.Run(u, func(t *testing.T) {
			_, err := f.Get(context.Background(), u, 1024)
			if !errors.Is(err, ErrRefused) || Transient(err) {
				t.Fatalf("err = %v, want a non-transient ErrRefused", err)
			}
		})
	}
}

// The server would answer every request, so each refusal comes from the URL rules themselves.
func TestOnlyHTTPSOnTheDefaultPortIsFetched(t *testing.T) {
	f := server(t, func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("{}")) }, time.Second)
	if _, err := f.Get(context.Background(), "https://example.com:443/doc", 1024); err != nil {
		t.Fatalf("explicit default port: %v", err)
	}
	for _, u := range []string{"http://example.com/doc", "https://example.com:8443/doc", "https://user:pw@example.com/doc", "ftp://example.com/doc", "https:///doc", "::"} {
		t.Run(u, func(t *testing.T) {
			if _, err := f.Get(context.Background(), u, 1024); !errors.Is(err, ErrRefused) {
				t.Fatalf("err = %v, want ErrRefused", err)
			}
		})
	}
}

// server is an HTTPS test server reached as https://example.com/ through the Dial hook.
func server(t *testing.T, h http.HandlerFunc, timeout time.Duration) *Fetcher {
	t.Helper()
	srv := httptest.NewTLSServer(h)
	t.Cleanup(srv.Close)
	addr := srv.Listener.Addr().String()
	return New(Config{Timeout: timeout, RootCAs: srv.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, addr)
		}})
}

func TestOnlyA200WithinTheLimitIsReturnedAndOnlyRetryableStatusesAreTransient(t *testing.T) {
	for name, tc := range map[string]struct {
		h         http.HandlerFunc
		limit     int64
		want      string
		err       error
		status    int
		transient bool
	}{
		"200 at the limit": {h: func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(strings.Repeat("a", 5120))) },
			limit: 5120, want: strings.Repeat("a", 5120)},
		"one byte over the limit": {h: func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(strings.Repeat("a", 5121))) },
			limit: 5120, err: ErrTooLarge},
		"not found":             {limit: 10, status: 404},
		"internal server error": {limit: 10, status: 500, transient: true},
		"server error":          {limit: 10, status: 502, transient: true},
		"rate-limited":          {limit: 10, status: 429, transient: true},
		"timed out":             {limit: 10, status: 408, transient: true},
		"forbidden":             {limit: 10, status: 403},
		"no content":            {limit: 10, status: 204},
	} {
		t.Run(name, func(t *testing.T) {
			h := tc.h
			if h == nil {
				h = func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(tc.status) }
			}
			res, err := server(t, h, time.Second).Get(context.Background(), "https://example.com/doc", tc.limit)
			var se *StatusError
			switch {
			case tc.err != nil:
				if !errors.Is(err, tc.err) {
					t.Fatalf("err = %v, want %v", err, tc.err)
				}
			case tc.status != 0:
				if !errors.As(err, &se) || se.Code != tc.status {
					t.Fatalf("err = %v, want status %d", err, tc.status)
				}
			case err != nil || string(res.Body) != tc.want:
				t.Fatalf("err = %v", err)
			}
			if Transient(err) != tc.transient {
				t.Fatalf("Transient(%v) = %v, want %v", err, Transient(err), tc.transient)
			}
		})
	}
}

func TestRedirectsAreNotFollowed(t *testing.T) {
	var followed atomic.Bool
	f := server(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/target" {
			followed.Store(true)
			return
		}
		http.Redirect(w, r, "/target", http.StatusFound)
	}, time.Second)
	_, err := f.Get(context.Background(), "https://example.com/doc", 1024)
	var se *StatusError
	if !errors.As(err, &se) || se.Code != http.StatusFound || Transient(err) || followed.Load() {
		t.Fatalf("err = %v, followed = %v", err, followed.Load())
	}
}

// An environment proxy would dial on our behalf, past the guard. Go reads the proxy environment
// once per process, so the fetch runs in a child process that starts with HTTPS_PROXY set: it must
// reach the server directly and read its answer. Through the proxy it would send a CONNECT, which the
// TLS server rejects, so the child never reports the direct fetch and the test fails.
func TestTheEnvironmentProxyIsIgnored(t *testing.T) {
	if rerun.Child() {
		f := server(t, func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("direct")) }, time.Second)
		if res, err := f.Get(context.Background(), "https://example.com/doc", 1024); err != nil || string(res.Body) != "direct" {
			t.Fatalf("res = %v, err = %v", res, err)
		}
		fmt.Println("fetched directly")
		return
	}
	if out := rerun.Run(t, "TestTheEnvironmentProxyIsIgnored", rerun.ProxyEnv("http://proxy.invalid:3128")...); !strings.Contains(out, "fetched directly") {
		t.Fatalf("child output %q; want the fetch to reach the server directly", out)
	}
}

// A refusal at dial time (a non-public address) names the URL as logs may show it.
func TestANonPublicRefusalNamesTheURLWithoutItsQuery(t *testing.T) {
	_, err := New(Config{}).Get(context.Background(), "https://127.0.0.1/doc?code=SECRET", 1024)
	if want := "ssrfguard: refused: https://127.0.0.1/doc resolves to a non-public address"; err == nil || err.Error() != want {
		t.Fatalf("err = %v, want %q", err, want)
	}
}

// The client for fetchers with their own rules (jwks_uri) is guarded too.
func TestTheGuardedHTTPClientRefusesPrivateAddresses(t *testing.T) {
	res, err := New(Config{}).HTTPClient().Get("https://127.0.0.1/jwks")
	if err == nil {
		_ = res.Body.Close()
	}
	if !errors.Is(err, ssrf.ErrProhibitedIP) {
		t.Fatalf("err = %v", err)
	}
}

// RefusedAddress is the guard refusing an address or port, a definite answer, for an error from Get
// (ErrRefused) or from HTTPClient (go-ssrf's own error, for an address or a port: a jwks_uri may
// name any port), and nothing else. The guard refuses before connecting.
func TestRefusedAddressIsTheGuardsRefusalAlone(t *testing.T) {
	f := New(Config{})
	_, fromGet := f.Get(context.Background(), "https://127.0.0.1:8443/doc", 1024)
	clientGet := func(u string) error {
		res, err := f.HTTPClient().Get(u)
		if err == nil {
			_ = res.Body.Close()
		}
		return err
	}
	// Each refusal is of the kind its row names: 127.0.0.1:8443 is both, and go-ssrf names the port.
	port, address := clientGet("https://127.0.0.1:8443/jwks"), clientGet("https://127.0.0.1/jwks")
	if !errors.Is(port, ssrf.ErrProhibitedPort) || !errors.Is(address, ssrf.ErrProhibitedIP) {
		t.Fatalf("HTTPClient refusals: port %v, address %v; want go-ssrf's port and address refusals", port, address)
	}
	for name, tc := range map[string]struct {
		err  error
		want bool
	}{
		"Get refusing a URL's port":      {fromGet, true}, // before any dial
		"HTTPClient refusing a port":     {port, true},
		"HTTPClient refusing an address": {address, true},
		"a body over the limit":          {ErrTooLarge, false},
		"another failure":                {errors.New("connection reset"), false},
		"no error":                       {nil, false},
	} {
		t.Run(name, func(t *testing.T) {
			if got := RefusedAddress(tc.err); got != tc.want {
				t.Errorf("RefusedAddress(%v) = %v, want %v", tc.err, got, tc.want)
			}
		})
	}
}

// A server that stalls times the fetch out (transient), and the error never carries the query:
// the HTTP client puts the full request URL in a fetch error, which the guard shows as logs may
// (logging.URLError), and a body read error quotes none.
func TestAStallingServerTimesOutWithoutLeakingTheQuery(t *testing.T) {
	for name, stall := range map[string]func(http.ResponseWriter, <-chan struct{}){
		"headers never come": func(_ http.ResponseWriter, release <-chan struct{}) { <-release },
		"the body stalls": func(w http.ResponseWriter, release <-chan struct{}) {
			_, _ = w.Write([]byte("{"))
			w.(http.Flusher).Flush()
			<-release
		},
	} {
		t.Run(name, func(t *testing.T) {
			release := make(chan struct{})
			f := server(t, func(w http.ResponseWriter, _ *http.Request) { stall(w, release) }, 200*time.Millisecond)
			defer close(release) // before the server's cleanup, which waits for this handler
			_, err := f.Get(context.Background(), "https://example.com/doc?secret=x", 1024)
			if err == nil || !Transient(err) || strings.Contains(err.Error(), "secret") {
				t.Fatalf("err = %v, want a transient timeout without the query", err)
			}
		})
	}
}

// Response headers are capped at MaxHeaderBytes: ordinary large headers pass, larger ones do not.
func TestResponseHeadersAreCappedAtMaxHeaderBytes(t *testing.T) {
	for name, tc := range map[string]struct {
		size int
		ok   bool
	}{
		"a 15 KB header passes": {size: 15000, ok: true}, // an ordinary large header (CSP, cookies), set apart from the constant
		"over the cap":          {size: MaxHeaderBytes + 1},
	} {
		t.Run(name, func(t *testing.T) {
			f := server(t, func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("X-Big", strings.Repeat("a", tc.size))
				_, _ = w.Write([]byte("{}"))
			}, time.Second)
			if _, err := f.Get(context.Background(), "https://example.com/doc", 1024); (err == nil) != tc.ok {
				t.Fatalf("err = %v, want ok %v", err, tc.ok)
			}
		})
	}
}

// A refusal, a status other than 200, a document over the limit and a refused trailer name the URL
// as logs may show it (no user information, query or fragment) and quote no line the server sent.
func TestGetErrorsNameTheURLWithoutItsSecrets(t *testing.T) {
	big := func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(strings.Repeat("a", 11))) }
	forbidden := func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusForbidden) }
	unreached := func(http.ResponseWriter, *http.Request) {} // the guard refuses before any request
	badTrailer := rawanswer.Handler(rawanswer.RefusedTrailer)
	for name, tc := range map[string]struct {
		url  string
		h    http.HandlerFunc
		want string
	}{
		"not https":         {"http://example.com/doc?code=SECRET#SECRET", unreached, "ssrfguard: refused: http://example.com/doc is not an https URL on port 443"},
		"user information":  {"https://user:SECRET@example.com/doc", unreached, "ssrfguard: refused: https://example.com/doc is not an https URL on port 443"},
		"another status":    {"https://example.com/doc?code=SECRET#SECRET", forbidden, "ssrfguard: https://example.com/doc answered HTTP status 403"},
		"larger than limit": {"https://example.com/doc?code=SECRET#SECRET", big, "ssrfguard: response too large: https://example.com/doc is larger than 10 bytes"},
		"a refused trailer": {"https://example.com/doc?code=SECRET", badTrailer, "ssrfguard: reading https://example.com/doc: a malformed header or trailer line"},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := server(t, tc.h, time.Second).Get(context.Background(), tc.url, 10)
			if err == nil || err.Error() != tc.want {
				t.Fatalf("err = %v, want %q", err, tc.want)
			}
		})
	}
}
