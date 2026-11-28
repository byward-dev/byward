package logging

import (
	"errors"
	"net"
	"net/textproto"
	"net/url"
	"strconv"
	"strings"
	"unicode/utf8"
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

// Hidden stands in for an operator's value that is not shown.
const Hidden = "the value (not shown: it may hold a password)"

// MarkedURL is raw, a URL setting the proxy uses whole, as a log line or doctor's report may show it
// (security invariant 2): URL's scheme, host and path, then ";…" when path parameters are left out,
// "?…" when a query is and "#…" when a fragment is, so the reader can tell the value holds more than
// is shown. Where URL will not show it (InvalidURL), such as an accepted URL with an @ past its
// host (which can be a password holding an unescaped / or ?, split from its user name), it is
// Hidden: the value may be valid, it is only not shown. It never holds a character that is not
// printable: url.Parse refuses an ASCII control character, and the host and path are shown escaped, so it
// is always one line (#505).
func MarkedURL(raw string) string {
	shown := URL(raw)
	if shown == InvalidURL {
		return Hidden
	}
	u, _ := url.Parse(raw) // URL parsed it
	if strings.Contains(u.EscapedPath(), ";") {
		shown += ";…"
	}
	if u.RawQuery != "" || u.ForceQuery {
		shown += "?…"
	}
	if strings.Contains(raw, "#") { // url.Parse splits at the first #, so any # starts the fragment
		shown += "#…"
	}
	return shown
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
	cause := BodyError(ue.Err)                         // the transport quotes the whole line it refused, as a body read does
	if strings.HasPrefix(cause.Error(), badLocation) { // the client quotes a redirect's raw Location
		cause = errBadLocation
	}
	return &url.Error{Op: ue.Op, URL: URL(ue.URL), Err: cause}
}

// BodyError is err, an error from reading an HTTP body (an answer's, or a client's request whose
// trailer the server parsed), without a header or trailer line the transport refused: textproto
// quotes the whole line, which can hold a cookie or a code. Go's client keeps only the text of an
// error that ends in its Client.Timeout, so that text is matched too, and the timeout is kept. Any
// other error is left as it is.
func BodyError(err error) error {
	if err == nil || !errors.As(err, new(textproto.ProtocolError)) && !strings.Contains(err.Error(), refusedLine) {
		return err
	}
	if ne := net.Error(nil); errors.As(err, &ne) && ne.Timeout() {
		return timedOut{errBadHeader}
	}
	return errBadHeader
}

const (
	badLocation = "failed to parse Location header"
	refusedLine = "malformed MIME header" // all three of textproto's wordings
)

// timedOut is a replaced error that was a timeout, so callers still class it as one.
type timedOut struct{ error }

func (timedOut) Timeout() bool   { return true }
func (timedOut) Temporary() bool { return true }

var (
	errNotAURL     = errors.New("not a URL")
	errBadLocation = errors.New(badLocation)
	errBadHeader   = errors.New("a malformed header or trailer line")
)

// AsGiven is raw as given, or quoted (strconv.Quote) when it holds a character that is not
// printable, such as a newline, which would start a line of its own in --print-config and could
// forge another setting's line there (#505), or a byte that is not UTF-8, which the printable test
// reads as U+FFFD and would let through (a raw 0x9b is a terminal's CSI). Config shows a value of a
// setting shown as given this way, and LooksSecret reads a value as it would be shown (#657).
func AsGiven(raw string) string {
	if !utf8.ValidString(raw) || strings.ContainsFunc(raw, func(r rune) bool { return !strconv.IsPrint(r) }) {
		return strconv.Quote(raw)
	}
	return raw
}
