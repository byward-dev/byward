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

	"github.com/corker/mcp-authproxy/internal/logging"
)

// stripped are removed from every inbound request before anything of ours is set (invariant 16):
// credentials, forwarding headers (any `X-Forwarded-*`), and the browser headers the proxy has
// already checked. `Origin` and `Sec-Fetch-*` would make SDK servers with their own cross-origin
// protection reject requests the proxy allowed (TS `createMcpExpressApp`, Go
// `http.CrossOriginProtection`). Names are compared with `_` read as `-`, because some upstream
// frameworks treat the two alike (the oauth2-proxy CVE-2025-64484 bypass).
var stripped = map[string]bool{"Authorization": true, "Forwarded": true, "Origin": true}

var errUpstreamRefused = errors.New("upstream refused the proxy and the request id is unknown")

// New returns a handler relaying each request to target, the upstream's MCP endpoint URL: the
// request path is replaced by target's path; the query is kept.
func New(log *slog.Logger, target *url.URL) http.Handler {
	t := *target
	rp := &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.Out.URL.Scheme, pr.Out.URL.Host = t.Scheme, t.Host
			pr.Out.URL.Path, pr.Out.URL.RawPath = t.Path, t.RawPath
			pr.Out.Host = ""
			strip(pr.Out.Header)
			// A token in the query never reaches the upstream, with or without authentication.
			pr.Out.URL.RawQuery = withoutAccessToken(pr.Out.URL.RawQuery)
		},
		Transport: &http.Transport{
			Proxy:                 http.ProxyFromEnvironment,
			DialContext:           (&net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
			ForceAttemptHTTP2:     true,
			MaxIdleConnsPerHost:   64,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: time.Second,
		},
		FlushInterval: -1, // MCP responses may stream; never hold bytes back
		// The proxy owns CORS and the auth challenge on the MCP endpoint. An upstream's CORS headers
		// would duplicate Access-Control-Allow-Origin (browsers reject that), and its
		// WWW-Authenticate would send clients to an authorization server that is not ours. An
		// upstream 401 or 403 is a refusal of the proxy, answered per ADR-0025 (refusal.go).
		ModifyResponse: func(res *http.Response) error {
			for k := range res.Header {
				if strings.HasPrefix(k, "Access-Control-") {
					delete(res.Header, k)
				}
			}
			res.Header.Del("WWW-Authenticate")
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
			log.WarnContext(r.Context(), "upstream error", "request_id", logging.RequestID(r.Context()), "error", err)
			// Never echo upstream internals (invariant 15).
			http.Error(w, "upstream unavailable", http.StatusBadGateway)
		},
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c := &capture{}
		if r.Body != nil && r.Body != http.NoBody {
			r.Body = teeBody{io.TeeReader(r.Body, c), r.Body}
		}
		rp.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), captureKey{}, c)))
	})
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

func strip(h http.Header) {
	for k := range h {
		n := textproto.CanonicalMIMEHeaderKey(strings.ReplaceAll(k, "_", "-"))
		if stripped[n] || strings.HasPrefix(n, "X-Forwarded-") || strings.HasPrefix(n, "Sec-Fetch-") {
			delete(h, k)
		}
	}
}
