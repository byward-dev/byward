package logging

import (
	"errors"
	"net/url"
	"strings"
)

// InvalidURL stands in for text that URL will not show, so its raw form never reaches a log.
const InvalidURL = "<invalid URL>"

// URL is raw as logs and error messages may show it: the scheme, host and path only. User
// information, the query, the fragment and path parameters (;jsessionid=…), which can carry
// passwords, codes, state or sessions, are dropped (ADR-0009 §8). It is InvalidURL for text with
// no scheme, an opaque one (scheme:rest, where rest could hold anything), and one with an @ past the
// host: credentials holding an unescaped /, ? or #, which the parser split from their @.
func URL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" || u.Opaque != "" || strings.ContainsRune(u.Path+u.RawQuery+u.Fragment, '@') {
		return InvalidURL
	}
	path, _, _ := strings.Cut(u.EscapedPath(), ";") // escaped: a %3B or %2F is part of the path
	scheme := raw[:len(u.Scheme)]                   // as written: HTTPS is shown as the HTTPS it is
	if u.Host == "" && strings.HasPrefix(raw[len(u.Scheme)+1:], "//") {
		return scheme + "://" + path // myapp:///cb: an empty authority, kept as sent
	}
	shown := url.URL{Scheme: u.Scheme, Host: u.Host}
	return scheme + strings.TrimPrefix(shown.String(), u.Scheme) + path
}

// URLError is err, an error the HTTP client returned, with the URL its *url.Error quotes shown as
// URL shows it. The type and the cause are kept, so callers can still tell a network failure or a
// timeout (net.Error) from a definite answer. A cause that quotes a URL or a header is replaced: a
// parse error's (invalid port ":secret"), a redirect's Location the client could not parse, and a
// header line the transport refused.
func URLError(err error) error {
	ue, ok := err.(*url.Error) //nolint:errorlint // the client returns *url.Error itself; its text is what is rewritten
	if !ok {
		return err
	}
	if ue.Op == "parse" {
		return &url.Error{Op: ue.Op, URL: InvalidURL, Err: errNotAURL}
	}
	cause := ue.Err
	switch text := cause.Error(); {
	case strings.HasPrefix(text, badLocation): // the client quotes a redirect's raw Location
		cause = errBadLocation
	case strings.Contains(text, badHeader): // the transport quotes the whole header line
		cause = errBadHeader
	}
	return &url.Error{Op: ue.Op, URL: URL(ue.URL), Err: cause}
}

const (
	badLocation = "failed to parse Location header"
	badHeader   = "malformed MIME header line"
)

var (
	errNotAURL     = errors.New("not a URL")
	errBadLocation = errors.New(badLocation)
	errBadHeader   = errors.New("the answer has a " + badHeader)
)
