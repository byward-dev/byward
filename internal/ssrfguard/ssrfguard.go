// Package ssrfguard fetches client-supplied URLs (CIMD documents, jwks_uri) so that they can only
// reach public HTTPS servers (ADR-0008 §4, AGENTS.md "SSRF guard"; quality-lenses invariant 4).
//
// The address is checked when the connection is dialled, after DNS resolution, so a name that
// resolves to a private address is refused even if it resolved to a public one a moment earlier
// (DNS rebinding). Redirects are never followed, no environment proxy is used, and the body is
// read up to a limit.
package ssrfguard

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"time"

	"code.dny.dev/ssrf"
)

// Limits (ADR-0008 §4).
const (
	// DefaultTimeout bounds one fetch, from dial to the last body byte.
	DefaultTimeout = 5 * time.Second
	// MaxHeaderBytes bounds the response headers.
	MaxHeaderBytes = 16 << 10
)

// ErrRefused means the URL or the address it resolved to is not a public HTTPS endpoint.
var ErrRefused = errors.New("ssrfguard: refused")

// ErrTooLarge means the body exceeded the caller's limit.
var ErrTooLarge = errors.New("ssrfguard: response too large")

// StatusError is a response other than 200 OK, redirects included (they are never followed). URL
// is the fetched URL without its query.
type StatusError struct {
	Code int
	URL  string
}

func (e *StatusError) Error() string {
	return fmt.Sprintf("ssrfguard: %s answered HTTP status %d", e.URL, e.Code)
}

// Transient reports whether err is worth retrying later (network trouble, a timeout, a 5xx, 408 or
// 429) as opposed to a definite answer (refused, too large, another 4xx or a redirect).
func Transient(err error) bool {
	var se *StatusError
	switch {
	case err == nil, errors.Is(err, ErrRefused), errors.Is(err, ErrTooLarge):
		return false
	case errors.As(err, &se):
		return se.Code >= 500 || se.Code == http.StatusRequestTimeout || se.Code == http.StatusTooManyRequests
	}
	return true
}

// RefusedAddress reports whether err, from Get or from HTTPClient, is the guard refusing the address
// or port a URL resolved to: a definite answer, never worth retrying.
func RefusedAddress(err error) bool {
	return errors.Is(err, ErrRefused) || errors.Is(err, ssrf.ErrProhibitedIP) || errors.Is(err, ssrf.ErrProhibitedPort) ||
		errors.Is(err, ssrf.ErrProhibitedNetwork) || errors.Is(err, ssrf.ErrInvalidHostPort)
}

// Response is a fetched 200 OK.
type Response struct {
	Header http.Header
	Body   []byte
}

// Config tunes a Fetcher. The zero value is the production configuration.
type Config struct {
	// Timeout bounds one fetch; zero means DefaultTimeout.
	Timeout time.Duration
	// RootCAs and Dial are test hooks for packages that need a fake HTTPS server: production
	// wiring never sets them. Dial replaces the guarded dialer, so tests of the guard itself live
	// in this package.
	RootCAs *x509.CertPool
	Dial    func(ctx context.Context, network, addr string) (net.Conn, error)
}

// Fetcher performs guarded GET requests.
type Fetcher struct {
	client  *http.Client
	timeout time.Duration
}

// New returns a Fetcher.
func New(c Config) *Fetcher {
	if c.Timeout == 0 {
		c.Timeout = DefaultTimeout
	}
	dial := c.Dial
	if dial == nil {
		dial = (&net.Dialer{Timeout: c.Timeout, Control: ssrf.New(ssrf.WithPorts(443)).Safe}).DialContext
	}
	t := &http.Transport{
		Proxy:                  nil, // an environment proxy would dial on our behalf, past the guard
		DialContext:            dial,
		TLSClientConfig:        &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: c.RootCAs},
		TLSHandshakeTimeout:    c.Timeout,
		ResponseHeaderTimeout:  c.Timeout,
		MaxResponseHeaderBytes: MaxHeaderBytes,
		DisableCompression:     true, // the size limit applies to the bytes we read
		ForceAttemptHTTP2:      true,
		MaxIdleConns:           16,
		IdleConnTimeout:        90 * time.Second,
	}
	return &Fetcher{timeout: c.Timeout, client: &http.Client{Transport: t,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}
}

// HTTPClient is the guarded client, for fetchers with their own size and status rules (a jwks_uri
// through idp.Fetcher). The guard applies at dial: only public addresses on port 443.
func (f *Fetcher) HTTPClient() *http.Client { return f.client }

// Get fetches rawURL and returns its body if the status is 200 and the body is at most maxBytes.
// Only https URLs on the default port are fetched; userinfo is refused.
func (f *Fetcher) Get(ctx context.Context, rawURL string, maxBytes int64) (*Response, error) {
	u, err := url.Parse(rawURL)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || (u.Port() != "" && u.Port() != "443") {
		return nil, fmt.Errorf("%w: %s is not an https URL on port 443", ErrRefused, redact(rawURL))
	}
	ctx, cancel := context.WithTimeout(ctx, f.timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrRefused, err)
	}
	req.Header.Set("Accept", "application/json")
	res, err := f.client.Do(req)
	if err != nil {
		if errors.Is(err, ssrf.ErrProhibitedIP) || errors.Is(err, ssrf.ErrProhibitedPort) || errors.Is(err, ssrf.ErrProhibitedNetwork) || errors.Is(err, ssrf.ErrInvalidHostPort) {
			return nil, fmt.Errorf("%w: %s resolves to a non-public address", ErrRefused, redact(rawURL))
		}
		return nil, fmt.Errorf("ssrfguard: fetching %s: %w", redact(rawURL), withoutURL(err))
	}
	defer func() { _ = res.Body.Close() }()
	if res.StatusCode != http.StatusOK {
		return nil, &StatusError{Code: res.StatusCode, URL: redact(rawURL)}
	}
	body, err := io.ReadAll(io.LimitReader(res.Body, maxBytes+1))
	if err != nil {
		return nil, fmt.Errorf("ssrfguard: reading %s: %w", redact(rawURL), withoutURL(err))
	}
	if int64(len(body)) > maxBytes {
		return nil, fmt.Errorf("%w: %s is larger than %d bytes", ErrTooLarge, redact(rawURL), maxBytes)
	}
	return &Response{Header: res.Header, Body: body}, nil
}

// withoutURL drops the full request URL the HTTP client puts in its errors (*url.Error), so a
// query never reaches a log; the cause is kept.
func withoutURL(err error) error {
	var ue *url.Error
	if errors.As(err, &ue) {
		return ue.Err
	}
	return err
}

// redact keeps scheme, host and path: queries never reach logs (ADR-0009 §8).
func redact(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return "<invalid URL>"
	}
	return u.Scheme + "://" + u.Host + u.EscapedPath()
}
