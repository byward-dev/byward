package envproxy

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"golang.org/x/net/http/httpproxy"
)

// closedAddr is a local address nothing listens on, so every dial to it fails at once.
func closedAddr(t *testing.T) string {
	t.Helper()
	s := httptest.NewServer(http.NotFoundHandler())
	addr := s.Listener.Addr().String()
	s.Close()
	return addr
}

// through is a transport whose proxy is setting, read as Go reads the environment.
func through(setting string) *http.Transport {
	pf := (&httpproxy.Config{HTTPProxy: setting, HTTPSProxy: setting}).ProxyFunc()
	t := http.DefaultTransport.(*http.Transport).Clone()
	t.Proxy = func(r *http.Request) (*url.URL, error) { return pf(r.URL) }
	return t
}

// chain is every message in err's chain, as anyone unwrapping or printing it would see.
func chain(err error) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%v %+v %#v", err, err, err)
	for e := err; e != nil; e = errors.Unwrap(e) {
		b.WriteString(" " + e.Error())
	}
	return b.String()
}

// Through a proxy setting Go misread, the error says only Cause: neither its text, nor anything in
// its chain, quotes the address Go dialled, which is part of the credentials. Through a well-formed
// proxy the error is the transport's own, and it does quote that address.
func TestATransportErrorThroughAMisreadProxyNeverQuotesItsAddress(t *testing.T) {
	addr := closedAddr(t)
	for _, tc := range []struct {
		name    string
		setting string
		misread bool
	}{
		// #185's split settings, aimed at the closed port: Go dials user:password-prefix.
		{"a slash", addr + "/pw-secret@egress.example:3128", true},
		{"a question mark", "http://" + addr + "?pw-secret@egress.example:3128", true},
		{"a setting that ends at a question mark", "http://" + addr + "?", true},
		{"a hash", addr + "#pw-secret@egress.example:3128", true},
		{"a password Go cannot retry", "ops:pw/secret@egress.example:3128", true},
		{"a well-formed proxy's error is its own", "http://" + addr, false},
		{"a trailing slash is well formed", "http://" + addr + "/", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := &http.Client{Transport: Redact(through(tc.setting))}
			_, err := c.Get("https://login.example/.well-known/openid-configuration")
			if err == nil {
				t.Fatal("the request through a closed proxy succeeded")
			}
			var redacted *Error
			if errors.As(err, &redacted) != tc.misread || strings.Contains(err.Error(), Cause) != tc.misread {
				t.Fatalf("error %q: redacted %v, want %v", err, errors.As(err, &redacted), tc.misread)
			}
			if got := strings.Contains(chain(err), addr); got == tc.misread {
				t.Fatalf("error chain %q shows the dialled address: %v, want %v", chain(err), got, !tc.misread)
			}
		})
	}
}

// failingDial is a transport through the proxy setting whose dial to the proxy fails with err.
func failingDial(setting string, err error) *http.Transport {
	t := through(setting)
	t.DialContext = func(context.Context, string, string) (net.Conn, error) { return nil, err }
	return t
}

type timeoutErr struct{}

func (timeoutErr) Error() string   { return "dial 127.0.0.1:4711: i/o timeout" }
func (timeoutErr) Timeout() bool   { return true }
func (timeoutErr) Temporary() bool { return true }

// A redacted error answers as the original did: a timeout is a timeout, a cancellation is
// context.Canceled and a passed deadline is context.DeadlineExceeded, so callers class it the same.
func TestARedactedErrorKeepsTheOriginalsClass(t *testing.T) {
	const misread, wellFormed = "127.0.0.1:4711/pw-secret@egress.example:3128", "http://127.0.0.1:4711"
	for _, tc := range []struct {
		name string
		dial error
	}{
		{"a timeout", timeoutErr{}},
		{"a cancellation", context.Canceled},
		{"a passed deadline", context.DeadlineExceeded},
		{"a refusal", errors.New("connect: connection refused")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			classOf := func(err error) string {
				var ne net.Error
				return fmt.Sprintf("timeout=%v canceled=%v deadline=%v", errors.As(err, &ne) && ne.Timeout(),
					errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded))
			}
			_, plain := (&http.Client{Transport: failingDial(wellFormed, tc.dial)}).Get("https://login.example/")
			_, redacted := (&http.Client{Transport: Redact(failingDial(misread, tc.dial))}).Get("https://login.example/")
			if plain == nil || redacted == nil {
				t.Fatalf("errors %v, %v; want both requests to fail", plain, redacted)
			}
			if !strings.Contains(redacted.Error(), Cause) || strings.Contains(redacted.Error(), "4711") {
				t.Fatalf("redacted %q; want the cause alone", redacted)
			}
			if classOf(redacted) != classOf(plain) {
				t.Fatalf("redacted answers %s, the original %s", classOf(redacted), classOf(plain))
			}
		})
	}
}

// Through a well-formed proxy, or none, Redact passes the transport's error through untouched: with
// no proxy the very value the dial returned, and through a well-formed one the transport's own
// error, as the bare transport gives it. A response passes through unchanged.
func TestRedactPassesAWellFormedProxysErrorThroughAsTheSameValue(t *testing.T) {
	want := errors.New("connect: connection refused")
	direct := failingDial("", want)
	direct.Proxy = nil
	req := func() *http.Request { return httptest.NewRequest(http.MethodGet, "http://login.example/", nil) }
	if _, err := Redact(direct).RoundTrip(req()); err != want { //nolint:errorlint // the same value, not a wrap
		t.Fatalf("with no proxy: error %#v, want the dial's own value", err)
	}
	proxied := failingDial("http://127.0.0.1:4711", want)
	_, bare := proxied.RoundTrip(req())
	_, err := Redact(proxied).RoundTrip(req())
	if !errors.Is(err, want) || errors.As(err, new(*Error)) || bare == nil || err.Error() != bare.Error() {
		t.Fatalf("through a well-formed proxy: error %#v, want the transport's own %#v", err, bare)
	}
	ok := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusTeapot) }))
	t.Cleanup(ok.Close)
	base := http.DefaultTransport.(*http.Transport).Clone()
	res, err := Redact(base).RoundTrip(httptest.NewRequest(http.MethodGet, ok.URL, nil))
	if err != nil || res.StatusCode != http.StatusTeapot {
		t.Fatalf("response %v, error %v; want the upstream's 418", res, err)
	}
	_ = res.Body.Close()
}

// Malformed judges a proxy as Go read it: split credentials, an opaque URL or no host.
func TestMalformedJudgesTheProxyGoRead(t *testing.T) {
	for _, tc := range []struct {
		raw  string
		want bool
	}{
		{"http://egress.example:3128", false}, {"http://egress.example:3128/", false}, {"http://ops:pw@egress.example:3128", false},
		{"http://admin:1234/5678@egress.example:3128", true}, {"http://admin:1234?5678@egress.example:3128", true},
		{"http://admin:1234?", true}, {"http://admin:1234#5678@egress.example:3128", true}, {"ops:pw/secret@egress.example:3128", true},
	} {
		u, err := url.Parse(tc.raw)
		if err != nil {
			t.Fatal(err)
		}
		if got := Malformed(u); got != tc.want {
			t.Errorf("Malformed(%q) = %v, want %v", tc.raw, got, tc.want)
		}
	}
	if Malformed(nil) {
		t.Error("no proxy counts as malformed")
	}
}
