package logging

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
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
		"https://admin:1234/SECRET@login.example/x":            invalid,                  // credentials split at an unescaped /
		"https://admin:1234?SECRET@login.example/":             invalid,                  // … at an unescaped ?
		"https://admin:1234#SECRET@login.example/":             invalid,                  // … at an unescaped #
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
		{&url.Error{Op: "Get", URL: "https://idp.example/keys", Err: errors.New(`net/http: HTTP/1.x transport connection broken: malformed MIME header line: "Set-Cookie: sid=SECRET\x01"`)}, `Get "https://idp.example/keys": the answer has a malformed MIME header line`, errBadHeader, false},
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

// Go's transport quotes a whole header line it refuses; URLError keeps none of it. The answer comes
// over a real connection, so a Go release that rewords the error fails here, not in a log.
func TestARealTransportsRefusedHeaderLineIsNotQuoted(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		_, _ = conn.Read(make([]byte, 4096))
		_, _ = conn.Write([]byte("HTTP/1.1 200 OK\r\nSet-Cookie: sid=SECRET\x01\r\nContent-Length: 0\r\n\r\n"))
	}()
	target := "http://" + ln.Addr().String() + "/keys"
	_, err = (&http.Client{}).Get(target)
	if err == nil {
		t.Fatal("the transport accepted a header line with a control character")
	}
	if got, want := URLError(err).Error(), `Get "`+target+`": the answer has a malformed MIME header line`; got != want {
		t.Fatalf("URLError = %q, want %q", got, want)
	}
}
