package server

import (
	"context"
	"fmt"
	"net/http"
	"net/netip"
	"strconv"
	"strings"

	"github.com/byward-dev/byward/internal/config"
	"github.com/byward-dev/byward/internal/doctor"
	"github.com/byward-dev/byward/internal/resource"
)

// setIdentityHeaders writes the user the guard admitted into the plain identity headers (ADR-0016
// §5), from the same identity the assertion is minted from. A claim the identity does not carry
// (not opted in, or absent for this user) gets no header; a list keeps every item, an empty one
// too.
//
// Email: the same value the assertion carries, from the access token's sealed claims, where the
// broker decides whether an email is asserted at all (ADR-0016, 2026-11-07 amendment); its
// verification goes with it, exactly as the assertion's email_verified does.
func setIdentityHeaders(ctx context.Context, h http.Header) {
	id, ok := resource.IdentityFrom(ctx)
	if !ok { // withAssertion has already refused the request
		return
	}
	// A list keeps every item, an empty one too, so it decodes to exactly the assertion's claim.
	list := func(name string, items []string) {
		if len(items) == 0 {
			return
		}
		enc := make([]string, len(items))
		for i, v := range items {
			enc[i] = percentEncode(v)
		}
		h.Set(name, strings.Join(enc, ","))
	}
	one := func(name, v string) {
		if v != "" {
			h.Set(name, percentEncode(v))
		}
	}
	one(config.HeaderSubject, id.Subject)
	one(config.HeaderClientID, id.ClientID)
	list(config.HeaderRoles, id.Roles)
	list(config.HeaderGroups, id.Groups)
	one(config.HeaderEmail, id.Email)
	if id.Email != "" {
		h.Set(config.HeaderEmailVerified, strconv.FormatBool(id.EmailVerified))
	}
	one(config.HeaderName, id.Name)
}

// percentEncode encodes every UTF-8 byte outside RFC 3986's unreserved set, so no value can carry
// a comma, a line break or anything else that would change the header; any URL decoder
// (decodeURIComponent, urllib.parse.unquote) reads it back.
func percentEncode(s string) string {
	const hex = "0123456789ABCDEF"
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if 'a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' || '0' <= c && c <= '9' || c == '-' || c == '.' || c == '_' || c == '~' {
			b.WriteByte(c)
			continue
		}
		b.WriteByte('%')
		b.WriteByte(hex[c>>4])
		b.WriteByte(hex[c&15])
	}
	return b.String()
}

// cgnat is RFC 6598 shared address space: carrier-grade NAT, also used by overlay networks.
var cgnat = netip.MustParsePrefix("100.64.0.0/10")

// notPublic reports whether a is an address the internet cannot reach directly: loopback,
// private, link-local or shared (CGNAT).
func notPublic(a netip.Addr) bool {
	return a.IsLoopback() || a.IsPrivate() || a.IsLinkLocalUnicast() || cgnat.Contains(a)
}

// identityHeadersResult is doctor's hint for the upstream's host for BYWARD_IDENTITY_HEADERS (ADR-0016 §5): the plain
// headers are safe only when the upstream is reachable through the proxy alone, which doctor cannot
// see; an upstream host with a public address, or one it cannot resolve, gets a warning.
func identityHeadersResult(ctx context.Context, host string, resolve func(context.Context, string) ([]netip.Addr, error)) doctor.Result {
	const hint = "a hint, not a guarantee: doctor sees addresses, not who can reach them"
	r := doctor.Result{Class: doctor.ClassProxy, Name: "identity headers", Status: doctor.Pass,
		Fix: "keep the upstream reachable only through this proxy (a private network or a network policy), or turn BYWARD_IDENTITY_HEADERS off and verify the assertion instead (docs/how-to/plain-identity-headers.md)"}
	addrs := []netip.Addr{}
	if a, err := netip.ParseAddr(host); err == nil {
		addrs = append(addrs, a)
	} else {
		ctx, cancel := context.WithTimeout(ctx, probeTimeout)
		defer cancel()
		if addrs, err = resolve(ctx, host); err != nil || len(addrs) == 0 {
			r.Status, r.Message = doctor.Warn, fmt.Sprintf("plain identity headers are on, and the upstream host %s does not resolve here (%v), so doctor cannot tell whether it is public (%s)", host, err, hint)
			return r
		}
	}
	for _, a := range addrs {
		if a = a.Unmap(); !notPublic(a) {
			r.Status, r.Message = doctor.Warn, fmt.Sprintf("plain identity headers are on, and the upstream host %s has the public address %s: whoever reaches it directly can send any identity (%s)", host, a, hint)
			return r
		}
	}
	r.Message, r.Fix = fmt.Sprintf("plain identity headers are on; the upstream host %s has only loopback, private, link-local or shared addresses (%s)", host, hint), ""
	return r
}
