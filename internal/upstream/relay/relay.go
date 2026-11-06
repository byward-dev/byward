// Package relay is the HTTP upstream: a byte-transparent reverse proxy built on
// `httputil.ReverseProxy.Rewrite`, never `Director` (ADR-0003, ADR-0018 §6–7).
package relay

import (
	"errors"
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

// Caps toward the upstream (ADR-0018 §7); beyond them the proxy answers 503. Long-lived `GET`
// streams have their own cap so idle legacy-era streams can never use up the slots tool calls need.
const (
	MaxInFlight = 64
	MaxStreams  = 256
)

// stripped are removed from every inbound request before anything of ours is set (invariant 16).
// `X-Forwarded-*` is matched by prefix below; hop-by-hop headers are removed by ReverseProxy.
var stripped = []string{"Authorization", "Forwarded"}

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
		},
		Transport: &http.Transport{
			Proxy:                 http.ProxyFromEnvironment,
			DialContext:           (&net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
			ForceAttemptHTTP2:     true,
			MaxIdleConnsPerHost:   MaxInFlight,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: time.Second,
		},
		// The proxy owns CORS on the MCP endpoint (internal/origin); an upstream's own CORS headers
		// would duplicate Access-Control-Allow-Origin, which browsers reject.
		ModifyResponse: func(res *http.Response) error {
			for k := range res.Header {
				if strings.HasPrefix(k, "Access-Control-") {
					delete(res.Header, k)
				}
			}
			return nil
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			// A chunked body over the limit only fails while it is being relayed.
			if mbe := (*http.MaxBytesError)(nil); errors.As(err, &mbe) {
				http.Error(w, "request body too large", http.StatusRequestEntityTooLarge)
				return
			}
			log.WarnContext(r.Context(), "upstream error", "request_id", logging.RequestID(r.Context()), "error", err)
			// Never echo upstream internals (invariant 15).
			http.Error(w, "upstream unavailable", http.StatusBadGateway)
		},
	}
	requests, streams := make(chan struct{}, MaxInFlight), make(chan struct{}, MaxStreams)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sem := requests
		if r.Method == http.MethodGet {
			sem = streams
		}
		select {
		case sem <- struct{}{}:
			defer func() { <-sem }()
		default:
			w.Header().Set("Retry-After", "1")
			http.Error(w, "upstream busy", http.StatusServiceUnavailable)
			return
		}
		rp.ServeHTTP(w, r)
	})
}

func strip(h http.Header) {
	for _, k := range stripped {
		h.Del(k)
	}
	for k := range h {
		if strings.HasPrefix(textproto.CanonicalMIMEHeaderKey(k), "X-Forwarded-") {
			delete(h, k)
		}
	}
}
