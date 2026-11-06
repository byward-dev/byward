package registration

import (
	"fmt"
	"net/url"
	"strings"
)

// CIMD limits (ADR-0008 §4; draft-ietf-oauth-client-id-metadata-document-03 §10.11).
const (
	MaxCIMDURLLen   = 512
	MaxCIMDDocBytes = 5 << 10
)

// cimdURLError explains why a client ID is not an acceptable Client ID Metadata Document URL.
type cimdURLError struct{ Reason string }

func (e *cimdURLError) Error() string { return "client ID metadata document URL: " + e.Reason }

// IsCIMDURL reports whether id looks like a CIMD client ID (an https URL), valid or not, so the
// registry chain knows which registry owns it.
func IsCIMDURL(id string) bool { return strings.HasPrefix(id, "https://") }

// ValidateCIMDURL applies draft -03 §3 to a client ID, compared as written (no normalisation):
// https, a host, a path other than "/", no userinfo, dot segments, query or fragment. Stricter than
// the draft: a query is refused (its SHOULD NOT), the host is plain ASCII (clients send IDNs in
// their xn-- form), and only port 443 is fetched (the SSRF guard).
func ValidateCIMDURL(id string) error {
	reject := func(r string) error { return &cimdURLError{Reason: r} }
	switch {
	case len(id) > MaxCIMDURLLen:
		return reject(fmt.Sprintf("longer than %d characters", MaxCIMDURLLen))
	case !IsCIMDURL(id):
		return reject("must start with https://")
	case strings.ContainsFunc(id, func(r rune) bool { return r <= ' ' || r >= 0x7f }):
		return reject("must be printable ASCII")
	case strings.Contains(id, "#"):
		return reject("must not have a fragment")
	case strings.Contains(id, "?"):
		return reject("must not have a query")
	}
	u, err := url.Parse(id)
	if err != nil || u.Host == "" || u.Opaque != "" {
		return reject("not an absolute URL")
	}
	if u.User != nil {
		return reject("must not contain user information")
	}
	if p := u.Port(); p != "" && p != "443" {
		return reject("only port 443 is fetched")
	}
	path := u.EscapedPath()
	if path == "" || path == "/" {
		return reject("must have a path other than /")
	}
	for _, seg := range strings.Split(path, "/") {
		if s, err := url.PathUnescape(seg); err != nil || s == "." || s == ".." {
			return reject("must not contain . or .. path segments")
		}
	}
	return nil
}

// cimdHost is the lower-cased host of a valid CIMD URL, for trust decisions and display.
func cimdHost(id string) string {
	u, _ := url.Parse(id)
	return strings.ToLower(u.Hostname())
}

// parseCIMD validates a document fetched from id (draft -03 §4-6, ADR-0008 §2, ADR-0009): the
// shared metadata rules, with every redirect URI required to pass and client_id equal to the URL.
// The error is for operator logs; the client only ever sees invalid_client.
func parseCIMD(id string, body []byte) (*clientMetadata, error) {
	d, err := decodeMetadata(body)
	if err != nil {
		return nil, err
	}
	if d.ClientID != id {
		return nil, fmt.Errorf("client_id %q does not match the document URL", d.ClientID)
	}
	m, _, err := validateMetadata(d, allRedirects)
	return m, err
}
