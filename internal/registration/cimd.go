package registration

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"slices"
	"strings"
	"unicode"

	"github.com/byward-dev/byward/internal/idp"
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

// cimdDocument is the JSON of a Client ID Metadata Document. RawMessage fields are only checked
// for presence.
type cimdDocument struct {
	ClientID                 string          `json:"client_id"`
	ClientName               string          `json:"client_name"`
	RedirectURIs             []string        `json:"redirect_uris"`
	GrantTypes               []string        `json:"grant_types"`
	ResponseTypes            []string        `json:"response_types"`
	TokenEndpointAuthMethod  string          `json:"token_endpoint_auth_method"`
	TokenEndpointAuthMethods []string        `json:"token_endpoint_auth_methods_supported"`
	JWKS                     json.RawMessage `json:"jwks"`
	JWKSURI                  string          `json:"jwks_uri"`
	ClientSecret             json.RawMessage `json:"client_secret"`
	ClientSecretExpiresAt    json.RawMessage `json:"client_secret_expires_at"`
}

// cimdMetadata is a validated document: what the broker uses.
type cimdMetadata struct {
	name      string
	redirects []string
	grants    []string // the supported subset, authorization_code always among them
	methods   []AuthMethod
	jwks      idp.StaticKeys // a registered JWK Set, when given inline
	jwksURI   string
}

// symmetric are the methods based on a shared secret, which a CIMD client must not use (§4.1).
var symmetric = []string{"client_secret_basic", "client_secret_post", "client_secret_jwt"}

// parseCIMD validates a document fetched from id (draft -03 §4-6, ADR-0008 §2, ADR-0009). The
// error is for operator logs; the client only ever sees invalid_client.
func parseCIMD(id string, body []byte) (*cimdMetadata, error) {
	var d cimdDocument
	dec := json.NewDecoder(bytes.NewReader(body))
	if err := dec.Decode(&d); err != nil {
		return nil, fmt.Errorf("not a JSON object: %w", err)
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, errors.New("trailing data after the JSON object")
	}
	if d.ClientID != id {
		return nil, fmt.Errorf("client_id %q does not match the document URL", d.ClientID)
	}
	name := strings.TrimSpace(d.ClientName)
	if name == "" || len(name) > MaxClientNameLen || strings.ContainsFunc(name, unicode.IsControl) {
		return nil, fmt.Errorf("client_name: required, at most %d characters, no control characters", MaxClientNameLen)
	}
	if err := ValidateRedirects(d.RedirectURIs); err != nil {
		return nil, err
	}
	if len(d.ClientSecret) > 0 || len(d.ClientSecretExpiresAt) > 0 {
		return nil, errors.New("client_secret: not allowed in a client metadata document")
	}
	m := &cimdMetadata{name: name, redirects: d.RedirectURIs}

	grants := d.GrantTypes
	if len(grants) == 0 {
		grants = []string{"authorization_code"}
	}
	for _, g := range []string{"authorization_code", "refresh_token"} {
		if slices.Contains(grants, g) {
			m.grants = append(m.grants, g)
		}
	}
	if !slices.Contains(m.grants, "authorization_code") {
		return nil, errors.New("grant_types: must include authorization_code")
	}
	if len(d.ResponseTypes) > 0 && !slices.Contains(d.ResponseTypes, "code") {
		return nil, errors.New("response_types: must include code")
	}

	listed := d.TokenEndpointAuthMethods
	if d.TokenEndpointAuthMethod != "" {
		listed = append([]string{d.TokenEndpointAuthMethod}, listed...)
	}
	if len(listed) == 0 {
		listed = []string{string(None)} // §5: not RFC 7591's client_secret_basic default
	}
	for _, l := range listed {
		switch {
		case slices.Contains(symmetric, l):
			return nil, fmt.Errorf("token_endpoint_auth_method: %s uses a shared secret, which a metadata document cannot carry", l)
		case (l == string(None) || l == string(PrivateKeyJWT)) && !slices.Contains(m.methods, AuthMethod(l)):
			m.methods = append(m.methods, AuthMethod(l))
		}
	}
	if len(m.methods) == 0 {
		return nil, errors.New("token_endpoint_auth_method: none of the listed methods is supported (none, private_key_jwt)")
	}

	switch {
	case len(d.JWKS) > 0 && d.JWKSURI != "":
		return nil, errors.New("jwks, jwks_uri: give one, not both")
	case d.JWKSURI != "":
		if u, err := url.Parse(d.JWKSURI); err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Fragment != "" {
			return nil, errors.New("jwks_uri: must be an https URL")
		}
		m.jwksURI = d.JWKSURI
	case len(d.JWKS) > 0:
		keys, err := parseClientJWKS(d.JWKS)
		if err != nil {
			return nil, err
		}
		m.jwks = keys
	case slices.Contains(m.methods, PrivateKeyJWT):
		return nil, errors.New("jwks: required for private_key_jwt (or jwks_uri)")
	}
	return m, nil
}
