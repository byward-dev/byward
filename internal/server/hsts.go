package server

import (
	"net/http"
	"net/url"
)

// hstsValue keeps browsers on https for a year (RFC 6797). There is no includeSubDomains or
// preload: byward does not own the parent domain (#225).
const hstsValue = "max-age=31536000"

// strictTransport sets Strict-Transport-Security on every response when the public URL is https,
// however TLS ends (at byward or at an ingress). It is decided from BYWARD_PUBLIC_URL only, never
// from the request (r.TLS, X-Forwarded-Proto), like the cookies and the issuer; a browser ignores
// the header on a response it got over plain http (RFC 6797 §8.1).
func strictTransport(publicURL *url.URL, next http.Handler) http.Handler {
	if publicURL.Scheme != "https" {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Strict-Transport-Security", hstsValue)
		next.ServeHTTP(w, r)
	})
}
