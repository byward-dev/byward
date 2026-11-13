// Package envproxy is the environment proxy: the HTTP proxy HTTPS_PROXY, HTTP_PROXY and NO_PROXY
// name, which the relay, IdP calls, doctor's self-probe and trace export go through. A setting whose credentials
// hold an unescaped character (/, ?, # and the like) is one Go misreads: it dials part of the
// credentials as the proxy host, and every transport error then quotes that address. Redact keeps
// such errors out of every log (invariant 2).
package envproxy

import (
	"context"
	"errors"
	"io"
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

// Redact returns t, whose errors through a proxy Go misread, judged by t's own Proxy, are replaced
// by an *Error: a failed round trip, and a read of the response body that fails (a proxy that
// answers, then resets). Any other error, and every response through any other proxy, passes
// through unchanged. An http.Client cancels a transport it does not know, as this one is, through
// the request's Cancel channel, so a client timeout reads "request canceled (Client.Timeout …)"
// instead of "context deadline exceeded (…)", while still answering Timeout and DeadlineExceeded.
func Redact(t *http.Transport) http.RoundTripper { return redacting{t} }

type redacting struct{ t *http.Transport }

func (r redacting) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := r.t.RoundTrip(req)
	if r.t.Proxy == nil {
		return resp, err
	}
	if via, perr := r.t.Proxy(req); perr != nil || !Malformed(via) {
		return resp, err
	}
	if err != nil {
		return nil, redact(err)
	}
	resp.Body = redactedBody{resp.Body}
	return resp, nil
}

// CloseIdleConnections passes through to the transport, as http.Client expects of one.
func (r redacting) CloseIdleConnections() { r.t.CloseIdleConnections() }

// redactedBody is a response body through a misread proxy: a read error that would quote the
// address Go dialled says only Cause. io.EOF and io.ErrUnexpectedEOF quote nothing and pass through.
type redactedBody struct{ io.ReadCloser }

func (b redactedBody) Read(p []byte) (int, error) {
	n, err := b.ReadCloser.Read(p)
	if err == nil || err == io.EOF || err == io.ErrUnexpectedEOF { //nolint:errorlint // both come bare (io.EOF by contract): a wrap could quote the address
		return n, err
	}
	return n, redact(err)
}

func (b redactedBody) Close() error {
	if err := b.ReadCloser.Close(); err != nil {
		return redact(err)
	}
	return nil
}

// redact is err as an *Error: the cause alone, answering as err did for a timeout, a cancellation
// and a passed deadline.
func redact(err error) *Error {
	var ne net.Error
	return &Error{timeout: errors.As(err, &ne) && ne.Timeout(), canceled: errors.Is(err, context.Canceled),
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
