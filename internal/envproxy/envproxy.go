// Package envproxy is the environment proxy: the HTTP proxy HTTPS_PROXY, HTTP_PROXY and NO_PROXY
// name, which the relay, IdP calls and doctor's self-probe go through. A setting whose credentials
// hold an unescaped character (/, ?, # and the like) is one Go misreads: it dials part of the
// credentials as the proxy host, and every transport error then quotes that address. Redact keeps
// such errors out of every log (invariant 2).
package envproxy

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/url"
)

// Cause is logged in place of an error that would quote the address Go dialled from a misread
// setting.
const Cause = "the request went through the environment's HTTP proxy, whose setting Go misread; run byward doctor"

// Proxy is the proxy a request goes through: the one the environment names, read once per process.
func Proxy(r *http.Request) (*url.URL, error) { return http.ProxyFromEnvironment(r) }

// Malformed reports whether via, a proxy Go read from the environment, is one whose credentials held
// an unescaped character: Go then splits them between the host it dials and the path, query or
// fragment, or returns an opaque URL with no host. Such a proxy's address, and any error that quotes
// it, can hold part of the credentials.
func Malformed(via *url.URL) bool {
	return via != nil && (via.Host == "" || via.Opaque != "" || via.Path != "" && via.Path != "/" || via.RawQuery != "" || via.ForceQuery || via.Fragment != "")
}

// Redact returns t, whose transport errors are replaced by an *Error when the request went through
// a proxy Go misread, judged by t's own Proxy. Any other error, and every response, passes through
// unchanged.
func Redact(t *http.Transport) http.RoundTripper { return redacting{t} }

type redacting struct{ t *http.Transport }

func (r redacting) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := r.t.RoundTrip(req)
	if err == nil || r.t.Proxy == nil {
		return resp, err
	}
	if via, perr := r.t.Proxy(req); perr != nil || !Malformed(via) {
		return resp, err
	}
	var ne net.Error
	return nil, &Error{timeout: errors.As(err, &ne) && ne.Timeout(), canceled: errors.Is(err, context.Canceled),
		deadline: errors.Is(err, context.DeadlineExceeded)}
}

// Error is a transport error through a misread proxy. It says only Cause and keeps no reference to
// the original, which quotes the address; it answers as the original did for a timeout, a
// cancellation and a passed deadline, so callers class it the same.
type Error struct{ timeout, canceled, deadline bool }

func (e *Error) Error() string { return Cause }

// Timeout reports whether the original was a timeout (net.Error).
func (e *Error) Timeout() bool { return e.timeout }

// Temporary is net.Error's deprecated method, answered as Timeout.
func (e *Error) Temporary() bool { return e.timeout }

// Is reports context.Canceled and context.DeadlineExceeded as the original did.
func (e *Error) Is(target error) bool {
	return target == context.Canceled && e.canceled || target == context.DeadlineExceeded && e.deadline
}
