// Package relay is the HTTP upstream: a byte-transparent reverse proxy built on
// `httputil.ReverseProxy.Rewrite`, never `Director` (ADR-0003, ADR-0018 §6–7).
package relay

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/textproto"
	"net/url"
	"strings"
	"time"

	"github.com/byward-dev/byward/internal/logging"
)

// stripped are removed from every inbound request before anything of ours is set (invariant 16):
// credentials (`DPoP` is a proof bound to the client's token, which never reaches the upstream),
// forwarding headers (any `X-Forwarded-*`), and the browser headers the proxy has
// already checked. `Origin` and `Sec-Fetch-*` would make SDK servers with their own cross-origin
// protection reject requests the proxy allowed (TS `createMcpExpressApp`, Go
// `http.CrossOriginProtection`). Names are compared with `_` read as `-`, because some upstream
// frameworks treat the two alike (the oauth2-proxy CVE-2025-64484 bypass).
var stripped = map[string]bool{"Authorization": true, "Dpop": true, "Forwarded": true, "Origin": true}

var errUpstreamRefused = errors.New("upstream refused the proxy and the request id is unknown")

// errUpstreamUpgrade: the upstream switched protocols. MCP never does, and the raw connection it
// would leave would bypass the session binding and every later check, so the client gets 502.
var errUpstreamUpgrade = errors.New("upstream switched protocols")

// errUpstreamRedirect: the upstream answered with a redirect. Passed on, it would send the MCP
// client to an address that is not the proxy, often the upstream's own; it almost always means
// BYWARD_UPSTREAM_URL is not the upstream's MCP endpoint (http where it wants https, a missing
// trailing slash), so the client gets 502 and the log names where the upstream pointed.
var errUpstreamRedirect = errors.New("upstream redirected the request")

// Option configures the relay.
type Option func(*options)

type options struct {
	inject        []func(context.Context, http.Header)
	strip         map[string]bool // more headers removed from every inbound request
	headerTimeout time.Duration
	proxy         func(*http.Request) (*url.URL, error) // Proxy; tests give their own
}

// WithInject adds a function that sets headers on every upstream request, after the inbound
// request's credentials and forwarding headers are gone (invariant 16), in the order given: the
// tracing propagator and the identity assertion. Without one, an inbound `traceparent` passes
// unchanged.
func WithInject(inject func(context.Context, http.Header)) Option {
	return func(o *options) { o.inject = append(o.inject, inject) }
}

// WithStripped removes more headers from every inbound request, compared as the built-in ones are
// (case-insensitive, `_` read as `-`): the header the identity assertion travels in, so a client
// can never supply one (ADR-0016 §4).
func WithStripped(names ...string) Option {
	return func(o *options) {
		for _, n := range names {
			o.strip[canonical(n)] = true
		}
	}
}

// WithResponseHeaderTimeout bounds how long the upstream may take to send its response headers
// (ADR-0018 §7); a request that waits longer is answered with a timeout error. Zero means no
// limit. A streamed body is not limited once its headers have arrived.
func WithResponseHeaderTimeout(d time.Duration) Option {
	return func(o *options) { o.headerTimeout = d }
}

// New returns a handler relaying each request to target, the upstream's MCP endpoint URL: the
// request path is replaced by target's path; the query is kept.
func New(log *slog.Logger, target *url.URL, opts ...Option) http.Handler {
	o := options{strip: map[string]bool{}, proxy: Proxy}
	for _, f := range opts {
		f(&o)
	}
	t := *target
	rp := &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.Out.URL.Scheme, pr.Out.URL.Host = t.Scheme, t.Host
			pr.Out.URL.Path, pr.Out.URL.RawPath = t.Path, t.RawPath
			pr.Out.Host = ""
			strip(pr.Out.Header, o.strip)
			// An MCP client's request trailers never reach the upstream: they are a second set of
			// headers, sent after the body, that the strip above never sees. ReverseProxy drops the
			// client's Trailer header, but Clone keeps the announced names, which the Transport would
			// announce and send on; their values would follow whenever the body was read before this
			// point. No MCP transport uses request trailers.
			pr.Out.Trailer = nil
			// Never ask the upstream to switch protocols: MCP never does, and the raw connection would
			// bypass the session binding. ReverseProxy puts a client's upgrade back after dropping the
			// hop-by-hop headers, so Connection holds only the upgrade by now.
			pr.Out.Header.Del("Upgrade")
			pr.Out.Header.Del("Connection")
			// A token in the query never reaches the upstream, with or without authentication.
			pr.Out.URL.RawQuery = withoutAccessToken(pr.Out.URL.RawQuery)
			// Ours, after the strip: trace context (the body, `params._meta`, is never touched) and the
			// identity assertion.
			for _, inject := range o.inject {
				inject(pr.In.Context(), pr.Out.Header)
			}
		},
		Transport: &http.Transport{
			Proxy:                 o.proxy,
			DialContext:           (&net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
			ForceAttemptHTTP2:     true,
			MaxIdleConnsPerHost:   64,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: time.Second,
			ResponseHeaderTimeout: o.headerTimeout,
		},
		FlushInterval: -1, // MCP responses may stream; never hold bytes back
		// The proxy owns CORS, HSTS and the auth challenge on the MCP endpoint. An upstream's CORS headers
		// would duplicate Access-Control-Allow-Origin (browsers reject that), and its
		// WWW-Authenticate would send clients to an authorization server that is not ours. An
		// upstream 401 or 403 is a refusal of the proxy, answered per ADR-0025 (refusal.go).
		ModifyResponse: func(res *http.Response) error {
			if res.StatusCode == http.StatusSwitchingProtocols {
				return errUpstreamUpgrade // answered 502, with none of the upstream's headers
			}
			if isRedirect(res.StatusCode) {
				ctx := res.Request.Context()
				log.ErrorContext(ctx, "upstream redirected the request", "request_id", logging.RequestID(ctx), "status", res.StatusCode,
					"reason", redirectHint(res))
				return errUpstreamRedirect
			}
			dropTrailers(res)
			for k := range res.Header {
				if strings.HasPrefix(k, "Access-Control-") {
					delete(res.Header, k)
				}
			}
			res.Header.Del("WWW-Authenticate")
			// Strict-Transport-Security is the proxy's, from its public URL (#225): an upstream's
			// would come first, or alone after an informational response, and browsers keep only the
			// first (RFC 6797 §8.1).
			res.Header.Del("Strict-Transport-Security")
			if res.StatusCode != http.StatusUnauthorized && res.StatusCode != http.StatusForbidden {
				return nil
			}
			ctx := res.Request.Context()
			status := res.StatusCode
			c, _ := ctx.Value(captureKey{}).(*capture)
			o := translate(res, c)
			hint := "upstream denied the proxy's identity; check the roles or groups it requires"
			if status == http.StatusUnauthorized {
				hint = "upstream rejected the proxy's credential; check the upstream credential"
			}
			log.ErrorContext(ctx, "upstream refused the request", "request_id", logging.RequestID(ctx),
				"status", status, "reason", hint+"; "+string(o))
			if o == outcomeUnanswerable {
				return errUpstreamRefused
			}
			return nil
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			// A chunked body over the limit only fails while it is being relayed.
			if mbe := (*http.MaxBytesError)(nil); errors.As(err, &mbe) {
				http.Error(w, "request body too large", http.StatusRequestEntityTooLarge)
				return
			}
			if errors.Is(err, errUpstreamRefused) {
				http.Error(w, "upstream refused the proxy", http.StatusBadGateway)
				return
			}
			if errors.Is(err, errUpstreamRedirect) {
				http.Error(w, "upstream unavailable", http.StatusBadGateway)
				return
			}
			if isHeaderTimeout(r.Context(), err) {
				out := answerTimeout(r.Context(), w, r.Method)
				log.ErrorContext(r.Context(), "upstream did not answer in time", "request_id", logging.RequestID(r.Context()),
					"reason", "no response headers within "+o.headerTimeout.String()+"; "+string(out))
				return
			}
			cause := []any{"error", err}
			if via, perr := o.proxy(r); perr == nil && MalformedProxy(via) {
				// The error would quote the address Go dialled, which is part of the proxy's
				// credentials (invariant 2): name the cause instead.
				cause = []any{"reason", "the request went through the environment's HTTP proxy, whose setting Go misread; run byward doctor"}
			}
			log.WarnContext(r.Context(), "upstream error", append([]any{"request_id", logging.RequestID(r.Context())}, cause...)...)
			// Never echo upstream internals (invariant 15).
			http.Error(w, "upstream unavailable", http.StatusBadGateway)
		},
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c := &capture{}
		if r.Body != nil && r.Body != http.NoBody {
			r.Body = teeBody{io.TeeReader(r.Body, c), r.Body}
		}
		rp.ServeHTTP(&informational{ResponseWriter: w, ours: w.Header().Clone()}, r.WithContext(traceWrite(context.WithValue(r.Context(), captureKey{}, c))))
	})
}

// informationalHeaders are the only headers an upstream's informational (1xx) response may carry to
// the MCP client: Link for 103 Early Hints, and Mcp-Session-Id, which the session binding then seals.
var informationalHeaders = map[string]bool{"Link": true, "Mcp-Session-Id": true}

// informational is the ResponseWriter the relay hands ReverseProxy. ReverseProxy forwards an
// upstream's 1xx from a client-trace hook, past ModifyResponse: it copies the upstream's headers into
// this writer, writes the code, then clears the whole header map. So this is the one place to:
//   - keep only informationalHeaders on a 1xx;
//   - drop an interim 101, which an HTTP/2 upstream can send through that hook, never through
//     ModifyResponse's refusal; written, it would end the response before the final one;
//   - on the final response, put back the headers the proxy set before the relay ran (CORS,
//     X-Request-Id) that the clear took, never over one the final response has; a body written
//     with no status first (the header-timeout answer) is a final 200 too.
type informational struct {
	http.ResponseWriter
	ours  http.Header // the proxy's own headers, as they were before the relay ran
	final bool        // the final status is written
}

func (w *informational) Write(p []byte) (int, error) {
	if !w.final {
		w.WriteHeader(http.StatusOK)
	}
	return w.ResponseWriter.Write(p)
}

func (w *informational) WriteHeader(code int) {
	h := w.Header()
	switch {
	case code == http.StatusSwitchingProtocols:
		clear(h)
		return
	case code >= 100 && code < 200:
		for k := range h {
			if !informationalHeaders[k] {
				delete(h, k)
			}
		}
	default:
		w.final = true
		for k, v := range w.ours {
			if _, ok := h[k]; !ok {
				h[k] = v
			}
		}
	}
	w.ResponseWriter.WriteHeader(code)
}

// Unwrap lets http.ResponseController reach the writer below, for flushing streamed responses.
func (w *informational) Unwrap() http.ResponseWriter { return w.ResponseWriter }

// dropTrailers keeps the upstream's response trailers from the MCP client: they are a second set of
// headers, sent after the body, that the header cleaning in ModifyResponse and the session binding
// never see, so an upstream's Mcp-Session-Id sent as a trailer would reach the client unsealed
// (invariant 13). Nil before the body announces none; the body reader fills them in at the end of
// the body, and ReverseProxy forwards what it finds after closing it, so they are dropped again on
// close.
func dropTrailers(res *http.Response) {
	res.Trailer = nil
	res.Body = trailerless{res.Body, res}
}

// trailerless is a response body that drops the response's trailers once it is closed.
type trailerless struct {
	io.ReadCloser
	res *http.Response
}

func (b trailerless) Close() error {
	err := b.ReadCloser.Close()
	b.res.Trailer = nil
	return err
}

// isRedirect reports whether an upstream status is a redirect: every 3xx except 304, which answers
// a conditional request and points nowhere.
func isRedirect(status int) bool {
	return status >= 300 && status < 400 && status != http.StatusNotModified
}

// redirectHint names where the upstream pointed, resolved against the request's URL: its scheme,
// host and path only, without path parameters, since userinfo, the query, the fragment, an opaque
// part or a `;jsessionid` could carry a secret.
func redirectHint(res *http.Response) string {
	loc, err := res.Location()
	// An @ past the host means credentials with an unescaped /, ? or #, split by the parser.
	if err != nil || loc.Opaque != "" || loc.Host == "" || strings.ContainsRune(loc.Path+loc.RawQuery+loc.Fragment, '@') {
		return "the upstream sent no usable Location; check BYWARD_UPSTREAM_URL"
	}
	path, _, _ := strings.Cut(loc.EscapedPath(), ";") // escaped: a %3B or %2F is part of the path
	return "the upstream points to " + loc.Scheme + "://" + loc.Host + path + "; if that is its MCP endpoint, set BYWARD_UPSTREAM_URL to it"
}

// Proxy is the HTTP proxy the relay sends a request through: the one the environment names
// (HTTPS_PROXY, HTTP_PROXY, NO_PROXY), read once per process.
func Proxy(r *http.Request) (*url.URL, error) { return http.ProxyFromEnvironment(r) }

// MalformedProxy reports whether via, a proxy Go read from the environment, is one whose
// credentials held an unescaped character (/, ?, # and the like): Go then splits them between the
// host it dials and the path, query or fragment, or returns an opaque URL with no host. Such a
// proxy's address, and any error that quotes it, can hold part of the credentials.
func MalformedProxy(via *url.URL) bool {
	return via != nil && (via.Host == "" || via.Opaque != "" || via.Path != "" && via.Path != "/" || via.RawQuery != "" || via.ForceQuery || via.Fragment != "")
}

// withoutAccessToken drops every access_token parameter and keeps every other byte of the query in
// its original order: url.Values.Encode would sort and re-escape it (ADR-0003, byte-transparent).
func withoutAccessToken(raw string) string {
	if !strings.Contains(raw, "access_token") && !strings.Contains(raw, "%") {
		return raw
	}
	parts := strings.Split(raw, "&")
	kept := parts[:0]
	for _, p := range parts {
		key, _, _ := strings.Cut(p, "=")
		if k, err := url.QueryUnescape(key); err == nil && k == "access_token" {
			continue
		}
		kept = append(kept, p)
	}
	return strings.Join(kept, "&")
}

func strip(h http.Header, extra map[string]bool) {
	for k := range h {
		if n := canonical(k); builtIn(n) || extra[n] {
			delete(h, k)
		}
	}
}

// builtIn reports whether the relay always removes the header named n, in canonical form.
func builtIn(n string) bool {
	return stripped[n] || hopByHop[n] || strings.HasPrefix(n, "X-Forwarded-") || strings.HasPrefix(n, "Sec-Fetch-")
}

// hopByHop are the hop-by-hop headers (RFC 9110 §7.6.1). ReverseProxy removes them by their exact
// name only, so strip removes them in every spelling (Proxy_Authorization too). Te is not among
// them: ReverseProxy keeps "Te: trailers".
var hopByHop = map[string]bool{"Connection": true, "Proxy-Connection": true, "Keep-Alive": true, "Proxy-Authenticate": true,
	"Proxy-Authorization": true, "Trailer": true, "Upgrade": true}

// Strips reports whether the relay removes the header name from every inbound request, compared
// as it compares them: by the built-in list, hop-by-hop headers included, or as one of extra (the
// names given WithStripped).
func Strips(name string, extra ...string) bool {
	n := canonical(name)
	for _, e := range extra {
		if canonical(e) == n {
			return true
		}
	}
	return builtIn(n)
}

// canonical is a header name as strip compares it: `_` read as `-`, canonical case.
func canonical(name string) string {
	return textproto.CanonicalMIMEHeaderKey(strings.ReplaceAll(name, "_", "-"))
}
