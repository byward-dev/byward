package logging

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"strings"
)

type clientIPKey struct{}

// ClientAddress resolves each request's client address once (ADR-0018 §6): when the TCP peer is a
// trusted proxy, the rightmost `X-Forwarded-For` entry that is not a trusted proxy; otherwise the
// peer. Request logs, audit records and rate limits all read it through RemoteIP, so they agree.
// With no trusted proxies (the default) forwarded headers are ignored.
func ClientAddress(trusted []netip.Prefix, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), clientIPKey{}, clientIP(trusted, r))))
	})
}

// RemoteIP is the client address resolved by ClientAddress, or the TCP peer when the request did
// not pass through it.
func RemoteIP(r *http.Request) string {
	if ip, ok := r.Context().Value(clientIPKey{}).(string); ok {
		return ip
	}
	return peer(r)
}

func peer(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func clientIP(trusted []netip.Prefix, r *http.Request) string {
	p := peer(r)
	if !isTrusted(trusted, p) {
		return p
	}
	var hops []string
	for _, v := range r.Header.Values("X-Forwarded-For") {
		hops = append(hops, strings.Split(v, ",")...)
	}
	client := p
	for i := len(hops) - 1; i >= 0; i-- {
		a, err := parseHop(strings.TrimSpace(hops[i]))
		if err != nil {
			// A broken chain is not trusted past this point: the last trusted hop is the client.
			return client
		}
		client = a.Unmap().WithZone("").String()
		if !isTrusted(trusted, client) {
			return client
		}
	}
	return client
}

// parseHop reads one X-Forwarded-For entry: an address, or one with a port as some proxies append
// (Azure Application Gateway sends "203.0.113.5:43210"), or a bracketed IPv6 address.
func parseHop(s string) (netip.Addr, error) {
	if a, err := netip.ParseAddr(s); err == nil {
		return a, nil
	}
	if ap, err := netip.ParseAddrPort(s); err == nil {
		return ap.Addr(), nil
	}
	if strings.HasPrefix(s, "[") && strings.HasSuffix(s, "]") {
		return netip.ParseAddr(s[1 : len(s)-1])
	}
	return netip.Addr{}, errors.New("not an address")
}

func isTrusted(trusted []netip.Prefix, ip string) bool {
	a, err := netip.ParseAddr(ip)
	if err != nil {
		return false
	}
	a = a.Unmap()
	for _, p := range trusted {
		if p.Contains(a) {
			return true
		}
	}
	return false
}
