package envproxy

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/http/httpproxy"

	"github.com/byward-dev/byward/internal/testutil/closedport"
)

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
func TestATransportErrorThroughAMisreadProxySettingNeverQuotesItsAddress(t *testing.T) {
	addr := closedport.Addr(t)
	const target = "https://login.example/.well-known/openid-configuration"
	for _, tc := range []struct {
		name    string
		setting string
		misread bool
		quotes  bool // the bare transport's error quotes the dialled address: what the redaction hides
	}{
		// #185's split settings, aimed at the closed port: Go dials user:password-prefix.
		{"a slash", addr + "/pw-secret@egress.example:3128", true, true},
		{"a question mark", "http://" + addr + "?pw-secret@egress.example:3128", true, true},
		{"a setting that ends at a question mark", "http://" + addr + "?", true, true},
		{"a hash", addr + "#pw-secret@egress.example:3128", true, true},
		// An opaque URL with no host: Go dials ":0", so only the cause shows it was caught.
		{"a setting Go cannot reparse", "ops:pw/secret@egress.example:3128", true, false},
		{"a well-formed setting's error is its own", "http://" + addr, false, true},
		{"a trailing slash is well formed", "http://" + addr + "/", false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, bare := (&http.Client{Transport: through(tc.setting)}).Get(target); bare == nil || strings.Contains(bare.Error(), addr) != tc.quotes {
				t.Fatalf("the bare transport's error %v quotes %s: %v, want %v", bare, addr, bare != nil && strings.Contains(bare.Error(), addr), tc.quotes)
			}
			c := &http.Client{Transport: Redact(through(tc.setting))}
			_, err := c.Get(target)
			if err == nil {
				t.Fatal("the request through a closed proxy succeeded")
			}
			var redacted *Error
			if errors.As(err, &redacted) != tc.misread || strings.Contains(err.Error(), Cause) != tc.misread {
				t.Fatalf("error %q: redacted %v, want %v", err, errors.As(err, &redacted), tc.misread)
			}
			if got := strings.Contains(chain(err), addr); got != (tc.quotes && !tc.misread) {
				t.Fatalf("error chain %q shows the dialled address: %v, want %v", chain(err), got, tc.quotes && !tc.misread)
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
		want string // the original's class, which the redacted error must keep
	}{
		{"a timeout", timeoutErr{}, "timeout=true canceled=false deadline=false"},
		{"a cancellation", context.Canceled, "timeout=false canceled=true deadline=false"},
		{"a passed deadline", context.DeadlineExceeded, "timeout=true canceled=false deadline=true"},
		{"a refusal", errors.New("connect: connection refused"), "timeout=false canceled=false deadline=false"},
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
			if classOf(plain) != tc.want || classOf(redacted) != classOf(plain) {
				t.Fatalf("redacted answers %s, the original %s, want %s", classOf(redacted), classOf(plain), tc.want)
			}
			if ne := (net.Error)(nil); !errors.As(redacted, &ne) || ne.Temporary() != ne.Timeout() { //nolint:staticcheck // Temporary is net.Error's, deprecated but required
				t.Fatalf("redacted %#v: Temporary must answer as Timeout", redacted)
			}
		})
	}
}

// Through a well-formed proxy, or none, Redact passes the transport's error through untouched: with
// no proxy the very value the dial returned, and through a well-formed one the transport's own
// error, as the bare transport gives it. A response passes through unchanged.
func TestRedactPassesTheSameValueWithNoProxyAndTheTransportsOwnErrorThroughAWellFormedOne(t *testing.T) {
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
	var opErr *net.OpError
	if !errors.Is(err, want) || errors.As(err, new(*Error)) || bare == nil || err.Error() != bare.Error() || !errors.As(err, &opErr) || err != error(opErr) { //nolint:errorlint // the transport's own *net.OpError, not a wrap
		t.Fatalf("through a well-formed proxy: error %#v, want the transport's own %#v", err, bare)
	}
	ok := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusTeapot) }))
	t.Cleanup(ok.Close)
	base := http.DefaultTransport.(*http.Transport).Clone()
	base.Proxy = nil // not the environment's: this checks a response, not a proxy
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

// A response body read through a proxy setting Go misread never quotes the dialled address: a body
// that breaks off (the address answers, then resets) gives an error that says only the cause, while
// a whole body reads as sent and one cut short ends in io.ErrUnexpectedEOF, which quotes nothing.
// Through a well-formed setting the read error is the transport's own and quotes that address.
func TestABodyReadThroughAMisreadProxySettingNeverQuotesItsAddressAndOtherwiseEndsAsSent(t *testing.T) {
	misread := func(addr string) string { return addr + "/pw-secret@egress.example:3128" }
	for _, tc := range []struct {
		name     string
		setting  func(addr string) string
		misread  bool
		complete bool // the proxy sends the whole body: it reads as sent, with no error
		short    bool // the proxy closes early without a reset: io.ErrUnexpectedEOF, passed through
	}{
		{"a reset through a misread setting never quotes the address", misread, true, false, false},
		{"a whole body through a misread setting reads as sent", misread, true, true, false},
		{"a body cut short through a misread setting ends in io.ErrUnexpectedEOF", misread, true, false, true},
		{"a well-formed setting's read error is its own", func(addr string) string { return "http://" + addr }, false, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ln, err := net.Listen("tcp", "127.0.0.1:0") // the "proxy" Go dials: it answers, then resets mid-body
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = ln.Close() })
			go func() {
				c, err := ln.Accept()
				if err != nil {
					return
				}
				_, _ = http.ReadRequest(bufio.NewReader(c))
				if tc.complete || tc.short {
					length := map[bool]string{true: "7", false: "1000"}[tc.complete]
					_, _ = io.WriteString(c, "HTTP/1.1 200 OK\r\nContent-Length: "+length+"\r\n\r\npartial")
					_ = c.Close()
					return
				}
				_, _ = io.WriteString(c, "HTTP/1.1 200 OK\r\nContent-Length: 1000\r\n\r\npartial")
				_ = c.(*net.TCPConn).SetLinger(0) // close with a reset, so the read error names the addresses
				_ = c.Close()
			}()
			addr := ln.Addr().String()
			res, err := (&http.Client{Transport: Redact(through(tc.setting(addr)))}).Get("http://login.example/")
			if err != nil {
				t.Fatalf("the proxy answered, but the request failed: %v", err)
			}
			body, err := io.ReadAll(res.Body)
			_ = res.Body.Close()
			if tc.complete {
				if err != nil || string(body) != "partial" {
					t.Fatalf("body %q, error %v; want the whole body and no error", body, err)
				}
				return
			}
			if tc.short {
				if !errors.Is(err, io.ErrUnexpectedEOF) || strings.Contains(chain(err), Cause) || strings.Contains(chain(err), addr) {
					t.Fatalf("read error %v; want io.ErrUnexpectedEOF, unredacted and with no address", err)
				}
				return
			}
			if err == nil || strings.Contains(chain(err), addr) == tc.misread || strings.Contains(err.Error(), Cause) != tc.misread {
				t.Fatalf("read error %v; misread %v", err, tc.misread)
			}
		})
	}
}

// failingClose is a body whose Close fails with an error that quotes the dialled address.
type failingClose struct{ io.Reader }

func (failingClose) Close() error {
	return &net.OpError{Op: "close", Net: "tcp", Addr: &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 4711}, Err: errors.New("broken pipe")}
}

// A body through a misread proxy setting that fails to close says only the cause.
func TestABodyThatFailsToCloseThroughAMisreadProxySettingSaysOnlyTheCause(t *testing.T) {
	err := redactedBody{failingClose{strings.NewReader("")}}.Close()
	if err == nil || !strings.Contains(err.Error(), Cause) || strings.Contains(chain(err), "4711") {
		t.Fatalf("close error %v; want the cause alone", err)
	}
}

// With no proxy at all, a client timeout through Redact still answers as a timeout and a passed
// deadline: http.Client cancels a transport it does not know through the request's Cancel channel,
// which changes the error's words, not its class.
func TestAClientTimeoutThroughRedactWithNoProxyIsStillATimeout(t *testing.T) {
	slow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { <-r.Context().Done() }))
	t.Cleanup(slow.Close)
	base := http.DefaultTransport.(*http.Transport).Clone()
	base.Proxy = nil
	_, err := (&http.Client{Transport: Redact(base), Timeout: 50 * time.Millisecond}).Get(slow.URL)
	var ne net.Error
	if err == nil || !errors.As(err, &ne) || !ne.Timeout() || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("error %v; want a timeout that is a passed deadline", err)
	}
}
