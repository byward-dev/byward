package server

import (
	"context"
	"net/http"
	"strings"

	"github.com/byward-dev/byward/internal/config"
	"github.com/byward-dev/byward/internal/resource"
)

// setIdentityHeaders writes the user the guard admitted into the plain identity headers (ADR-0016
// §5), from the same identity the assertion is minted from. A claim the identity does not carry
// (not opted in, or absent for this user) gets no header, never an empty one.
//
// Email: the same value the assertion carries, from the access token's sealed claims; #151 decides
// when an unverified email is dropped there, for both.
func setIdentityHeaders(ctx context.Context, h http.Header) {
	id, ok := resource.IdentityFrom(ctx)
	if !ok { // withAssertion has already refused the request
		return
	}
	set := func(name string, values ...string) {
		var enc []string
		for _, v := range values {
			if v != "" {
				enc = append(enc, percentEncode(v))
			}
		}
		if len(enc) > 0 {
			h.Set(name, strings.Join(enc, ","))
		}
	}
	set(config.HeaderSubject, id.Subject)
	set(config.HeaderClientID, id.ClientID)
	set(config.HeaderRoles, id.Roles...)
	set(config.HeaderGroups, id.Groups...)
	set(config.HeaderEmail, id.Email)
	set(config.HeaderName, id.Name)
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
