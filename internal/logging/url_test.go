package logging

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/textproto"
	"net/url"
	"strings"
	"testing"
	"testing/iotest"
	"time"

	"github.com/byward-dev/byward/internal/testutil/rawanswer"
)

// A URL is logged as its scheme, host and path: user information, the query, the fragment and path
// parameters are dropped. Text that is not a URL with a scheme and a hierarchical part, or that has
// an @ past its host, is logged as the marker, never as written.
func TestALoggedURLKeepsOnlyItsSchemeHostAndPath(t *testing.T) {
	const invalid = "<invalid URL>"
	for raw, want := range map[string]string{
		"https://idp.example/.well-known/openid-configuration": "https://idp.example/.well-known/openid-configuration",
		"https://idp.example:8443/keys?code=SECRET":            "https://idp.example:8443/keys",
		"https://idp.example/cb#access_token=SECRET":           "https://idp.example/cb",
		"https://idp.example/cb?":                              "https://idp.example/cb",
		"https://user:SECRET@idp.example/cb":                   "https://idp.example/cb",
		"https://idp.example/cb;jsessionid=SECRET":             "https://idp.example/cb",
		"https://idp.example/a%2Fb%3Bc;x=SECRET":               "https://idp.example/a%2Fb%3Bc", // escaped: part of the path
		"http://127.0.0.1:53682/callback?code=SECRET&state=s":  "http://127.0.0.1:53682/callback",
		"myapp:/callback?code=SECRET":                          "myapp:/callback",
		"myapp:///callback?code=SECRET":                        "myapp:///callback", // an empty authority, kept as sent
		"myapp:///cb;sid=SECRET":                               "myapp:///cb",
		"HTTPS://idp.example/cb?code=SECRET":                   "HTTPS://idp.example/cb", // the scheme as written
		"MYAPP:///cb?code=SECRET":                              "MYAPP:///cb",
		"https://admin:1234/SECRET@login.example/x":            invalid, // credentials split at an unescaped /
		"https://admin:1234?SECRET@login.example/":             invalid, // … at an unescaped ?
		"https://admin:1234#SECRET@login.example/":             invalid, // … at an unescaped #
		"https://idp.example/c@b":                              invalid,
		"https:user:SECRET@idp.example":                        invalid, // opaque: everything after the scheme
		"//idp.example/cb?code=SECRET":                         invalid, // no scheme
		"idp.example/cb":                                       invalid,
		"https://idp.example/%zz?code=SECRET":                  invalid, // does not parse
		"":                                                     invalid,
	} {
		if got := URL(raw); got != want {
			t.Errorf("URL(%q) = %q, want %q", raw, got, want)
		}
	}
}

// An HTTP client error shows its URL as URL does and keeps its type and cause: callers class any
// *url.Error as no answer (a dropped connection, io.EOF, is not a net.Error), and a timeout is still
// one. A cause that quotes a URL or a header is replaced: a parse error's, a redirect's Location the
// client could not parse, and a header line the transport refused. Any other error is left as it is.
func TestAClientErrorShowsItsURLAsLogsMay(t *testing.T) {
	for _, tc := range []struct {
		err     *url.Error
		want    string
		cause   error // the cause callers class by: kept, or the sentinel that replaces a quoting one
		timeout bool
	}{
		{&url.Error{Op: "Get", URL: "https://user:SECRET@idp.example/keys?code=SECRET", Err: io.EOF}, `Get "https://idp.example/keys": EOF`, io.EOF, false},
		{&url.Error{Op: "Post", URL: "https://idp.example/token?code=SECRET", Err: context.DeadlineExceeded}, `Post "https://idp.example/token": context deadline exceeded`, context.DeadlineExceeded, true},
		{&url.Error{Op: "parse", URL: "http://admin:SECRET/@idp.example/x", Err: errors.New(`invalid port ":SECRET" after host`)}, `parse "<invalid URL>": not a URL`, errNotAURL, false},
		{&url.Error{Op: "Get", URL: "https://idp.example/keys", Err: errors.New(`failed to parse Location header "http://x:SECRET/cb?state=SECRET": parse "http://x:SECRET/cb?state=SECRET": invalid port ":SECRET" after host`)}, `Get "https://idp.example/keys": failed to parse Location header`, errBadLocation, false},
		{&url.Error{Op: "Get", URL: "https://idp.example/keys", Err: fmt.Errorf("net/http: HTTP/1.x transport connection broken: %w", textproto.ProtocolError(`malformed MIME header line: "Set-Cookie: sid=SECRET\x01"`))}, `Get "https://idp.example/keys": ` + errBadHeader.Error(), errBadHeader, false},
	} {
		err := URLError(tc.err)
		var ue *url.Error
		var ne net.Error
		if err.Error() != tc.want || !errors.As(err, &ue) || !errors.Is(err, tc.cause) || (tc.timeout && (!errors.As(err, &ne) || !ne.Timeout())) {
			t.Errorf("URLError(%v) = %v (%T), want %q, a *url.Error (cause %v, timeout %v)", tc.err, err, err, tc.want, tc.cause, tc.timeout)
		}
	}
	other := errors.New("not a client error")
	if URLError(other) != other {
		t.Fatal("another error was changed")
	}
}

// Go's client quotes a redirect's raw Location when it cannot parse it; URLError keeps none of it.
// The error comes from a real client, so a Go release that rewords it fails here, not in a log.
func TestARealClientsUnparsableLocationIsNotQuoted(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Location", "http://admin:SECRET/@login.example/x?state=SECRET")
		w.WriteHeader(http.StatusFound)
	}))
	defer srv.Close()
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	_, err := client.Get(srv.URL + "/keys")
	if err == nil {
		t.Fatal("the client followed or accepted an unparsable Location")
	}
	if got, want := URLError(err).Error(), `Get "`+srv.URL+`/keys": failed to parse Location header`; got != want {
		t.Fatalf("URLError = %q, want %q", got, want)
	}
}

// Go's transport quotes a whole header line it refuses, in one of three wordings; none of it
// reaches the error URLError gives. Each answer comes over a real connection, so a Go release that
// reports the line neither as a textproto.ProtocolError nor in one of these wordings fails here, not
// in a log.
func TestARealTransportsRefusedHeaderLineIsNotQuoted(t *testing.T) {
	for name, answer := range map[string]string{
		"a header line with a control character":       "HTTP/1.1 200 OK\r\nSet-Cookie: sid=SECRET\x01\r\nContent-Length: 0\r\n\r\n",
		"a header line without a colon":                "HTTP/1.1 200 OK\r\nSet-Cookie sid=SECRET\r\nContent-Length: 0\r\n\r\n",
		"a first header line that starts with a space": "HTTP/1.1 200 OK\r\n Set-Cookie: sid=SECRET\r\nContent-Length: 0\r\n\r\n",
	} {
		t.Run(name, func(t *testing.T) {
			srv := httptest.NewServer(rawanswer.Handler(answer))
			defer srv.Close()
			res, err := http.Get(srv.URL + "/keys")
			if err == nil {
				_ = res.Body.Close()
				t.Fatal("the transport accepted the header line")
			}
			if got, want := URLError(err).Error(), `Get "`+srv.URL+`/keys": `+errBadHeader.Error(); got != want {
				t.Fatalf("got %q, want %q", got, want)
			}
		})
	}
}

// A trailer line Go's transport refuses fails the body read instead, quoting the whole line;
// BodyError keeps none of it. The answer comes over a real connection, as above.
func TestARealTransportsRefusedTrailerLineIsNotQuoted(t *testing.T) {
	srv := httptest.NewServer(rawanswer.Handler(rawanswer.RefusedTrailer))
	defer srv.Close()
	res, err := http.Get(srv.URL + "/keys")
	if err != nil {
		t.Fatalf("the request failed before the body: %v", err)
	}
	_, err = io.ReadAll(res.Body)
	_ = res.Body.Close()
	if err == nil || !strings.Contains(err.Error(), "SECRET") {
		t.Fatalf("reading the body = %v, want an error quoting the refused line", err)
	}
	if got := BodyError(err); got == nil || got.Error() != "a malformed header or trailer line" {
		t.Fatalf("BodyError = %v, want the refused line named without its text", got)
	}
}

// A request trailer line Go's server refuses fails the handler's body read the same way, quoting the
// whole line, which a client may have put a token or cookie in; BodyError keeps none of it. The relay
// logs this error. The request comes over a real connection, as above.
func TestARealServersRefusedRequestTrailerIsNotQuoted(t *testing.T) {
	read := make(chan error, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		_, err := io.ReadAll(r.Body)
		read <- err
	}))
	defer srv.Close()
	conn, err := net.Dial("tcp", srv.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	if _, err := conn.Write([]byte("POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n2\r\n{}\r\n0\r\nX-Sid: SECRET\x01\r\n\r\n")); err != nil {
		t.Fatal(err)
	}
	select {
	case err = <-read:
	case <-time.After(10 * time.Second):
		t.Fatal("the server never read the request body")
	}
	if err == nil || !strings.Contains(err.Error(), "SECRET") {
		t.Fatalf("reading the body = %v, want an error quoting the refused line", err)
	}
	if got := BodyError(err); got == nil || got.Error() != "a malformed header or trailer line" {
		t.Fatalf("BodyError = %v, want the refused line named without its text", got)
	}
}

// Go's client keeps only the text of an error that ends in its Client.Timeout, while awaiting the
// answer (URLError shows it) or reading its body (BodyError does). A refused line in that text is not
// quoted, and the timeout is kept.
func TestARefusedLineAtAClientTimeoutIsNotQuoted(t *testing.T) {
	refused := textproto.ProtocolError(`malformed MIME header line: "Set-Cookie: sid=SECRET\x01"`)
	// Each fails once the client has cancelled the request for its timeout: for a transport of its own,
	// the client marks the timeout before it closes Cancel, so it then reports the failure as one.
	// The body row waits in RoundTrip too, so its body fails on the first read.
	atTimeout := func(r *http.Request) error {
		select {
		case <-r.Cancel: //nolint:staticcheck // Cancel is what the client closes after marking the timeout
			return refused
		case <-time.After(10 * time.Second):
			return errors.New("the client never cancelled the request")
		}
	}
	for name, tc := range map[string]struct {
		rt   roundTrip
		path string // where the client says the timeout came
		show func(error) error
		want string
	}{
		"awaiting the answer": {func(r *http.Request) (*http.Response, error) { return nil, atTimeout(r) }, "awaiting headers", URLError, `Get "http://idp.example/keys": a malformed header or trailer line`},
		"reading the body": {func(r *http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(iotest.ErrReader(atTimeout(r))), Request: r}, nil
		}, "reading body", BodyError, "a malformed header or trailer line"},
	} {
		t.Run(name, func(t *testing.T) {
			res, err := (&http.Client{Timeout: time.Millisecond, Transport: tc.rt}).Get("http://idp.example/keys")
			if err == nil {
				_, err = io.ReadAll(res.Body)
				_ = res.Body.Close()
			}
			if err == nil || !strings.Contains(err.Error(), "SECRET") || !strings.Contains(err.Error(), tc.path) {
				t.Fatalf("err = %v, want the client's timeout %s, quoting the refused line", err, tc.path)
			}
			got := tc.show(err)
			var ne net.Error
			if got.Error() != tc.want || !errors.As(got, &ne) || !ne.Timeout() {
				t.Errorf("shown = %v (%T), want %q, still a timeout", got, got, tc.want)
			}
		})
	}
}

// timeoutText is an error that kept only its text at a client timeout, as Go's client returns it.
type timeoutText string

func (e timeoutText) Error() string { return string(e) }
func (timeoutText) Timeout() bool   { return true }
func (timeoutText) Temporary() bool { return true }

type roundTrip func(*http.Request) (*http.Response, error)

func (f roundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// BodyError replaces an error that holds a refused line, by its type or, once Go's client kept only
// its text, by any of textproto's wordings, with one that names the failure without the line and is a
// timeout only if the error was one. It returns any other error, nil included, as it is: callers
// match those with errors.Is.
func TestABodyErrorIsReplacedOnlyForARefusedLine(t *testing.T) {
	refused := textproto.ProtocolError(`malformed MIME header line: "X-Sid: SECRET\x01"`)
	for name, tc := range map[string]struct {
		err      error
		replaced bool
		timeout  bool // of a replaced error
	}{
		"a bare refused line":                   {refused, true, false},
		"a wrapped refused line":                {fmt.Errorf("reading: %w", refused), true, false},
		"a line without a colon":                {textproto.ProtocolError(`malformed MIME header: missing colon: "Cookie sid=SECRET"`), true, false},
		"a refused line Go words otherwise":     {textproto.ProtocolError(`refused line: "X-Sid: SECRET"`), true, false},
		"a refused line in a failed request":    {&url.Error{Op: "Get", URL: "http://idp.example/keys", Err: refused}, true, false},
		"text only, a control character":        {timeoutText(`malformed MIME header line: "X-Sid: SECRET\x01" (Client.Timeout exceeded while awaiting headers)`), true, true},
		"text only, without a colon":            {timeoutText(`malformed MIME header: missing colon: "Cookie sid=SECRET" (Client.Timeout or context cancellation while reading body)`), true, true},
		"text only, a first line after a space": {timeoutText(`malformed MIME header initial line: " Cookie: sid=SECRET" (Client.Timeout exceeded while awaiting headers)`), true, true},
		"a cut-off body":                        {io.ErrUnexpectedEOF, false, false},
		"a cancelled read":                      {context.Canceled, false, false},
		"no error":                              {nil, false, false},
	} {
		t.Run(name, func(t *testing.T) {
			got := BodyError(tc.err)
			var ne net.Error
			isTimeout := errors.As(got, &ne) && ne.Timeout() && ne.Temporary() //nolint:staticcheck // Temporary answers as Timeout, as Go's own timeout does
			if tc.replaced && (got == nil || got.Error() != "a malformed header or trailer line" || isTimeout != tc.timeout) {
				t.Errorf("BodyError = %v (timeout %v), want the refused line named without its text (timeout %v)", got, isTimeout, tc.timeout)
			}
			if !tc.replaced && got != tc.err { //nolint:errorlint // the same error, so errors.Is still matches it
				t.Errorf("BodyError(%v) = %v, want it unchanged", tc.err, got)
			}
		})
	}
}
