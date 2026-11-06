package registration

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"
	"unicode"

	"github.com/byward-dev/byward/internal/idp"
)

// metadataDocument is client metadata as JSON: a Client ID Metadata Document or an RFC 7591
// registration request. RawMessage fields are only checked for presence, except jwks.
type metadataDocument struct {
	ClientID                 string          `json:"client_id,omitempty"`
	ClientName               string          `json:"client_name"`
	RedirectURIs             []string        `json:"redirect_uris"`
	GrantTypes               []string        `json:"grant_types,omitempty"`
	ResponseTypes            []string        `json:"response_types,omitempty"`
	TokenEndpointAuthMethod  string          `json:"token_endpoint_auth_method,omitempty"`
	TokenEndpointAuthMethods []string        `json:"token_endpoint_auth_methods_supported,omitempty"`
	JWKS                     json.RawMessage `json:"jwks,omitempty"`
	JWKSURI                  string          `json:"jwks_uri,omitempty"`
	Scope                    string          `json:"scope,omitempty"`
	ClientSecret             json.RawMessage `json:"client_secret,omitempty"`
	ClientSecretExpiresAt    json.RawMessage `json:"client_secret_expires_at,omitempty"`
}

// clientMetadata is validated metadata: what the broker uses. CIMD and DCR clients share these
// rules on purpose, so the two cannot drift apart (ADR-0008 §2, §4).
type clientMetadata struct {
	name      string
	redirects []string
	grants    []string // the supported subset, authorization_code always among them
	methods   []AuthMethod
	jwks      idp.StaticKeys // a registered JWK Set, when given inline
	jwksRaw   json.RawMessage
	jwksURI   string
}

// redirectRule is how validateMetadata treats redirect URIs that fail ADR-0009.
type redirectRule int

const (
	// allRedirects refuses the metadata if any redirect URI fails (CIMD: the document is the
	// client's own statement).
	allRedirects redirectRule = iota
	// passingRedirects keeps the URIs that pass and reports the rest (DCR, RFC 7591 §3.2.2 lets the
	// server substitute values); the metadata is refused only if none passes.
	passingRedirects
)

// ErrInvalidRedirectURI marks a refusal caused by the redirect URIs, which RFC 7591 §3.2.2 reports
// as invalid_redirect_uri rather than invalid_client_metadata.
var ErrInvalidRedirectURI = errors.New("invalid redirect URIs")

// symmetric are the methods based on a shared secret, which a CIMD or DCR client must not use.
var symmetric = []string{"client_secret_basic", "client_secret_post", "client_secret_jwt"}

// decodeMetadata reads one JSON object with nothing after it.
func decodeMetadata(body []byte) (metadataDocument, error) {
	var d metadataDocument
	dec := json.NewDecoder(bytes.NewReader(body))
	if err := dec.Decode(&d); err != nil {
		// The reason reaches the client (error_description): name the field, never a Go type.
		var te *json.UnmarshalTypeError
		if errors.As(err, &te) && te.Field != "" {
			return metadataDocument{}, fmt.Errorf("%s: wrong JSON type (%s)", te.Field, te.Value)
		}
		if errors.As(err, &te) {
			return metadataDocument{}, fmt.Errorf("not a JSON object (%s)", te.Value)
		}
		return metadataDocument{}, fmt.Errorf("not a JSON object: %w", err)
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return metadataDocument{}, errors.New("trailing data after the JSON object")
	}
	return d, nil
}

// validateMetadata applies the shared client metadata rules (draft -03 §4-6, ADR-0008 §2,
// ADR-0009). With passingRedirects it also returns the redirect URIs it dropped.
func validateMetadata(d metadataDocument, rule redirectRule) (*clientMetadata, []string, error) {
	name := strings.TrimSpace(d.ClientName)
	if name == "" || len(name) > MaxClientNameLen || strings.ContainsFunc(name, unicode.IsControl) {
		return nil, nil, fmt.Errorf("client_name: required, at most %d characters, no control characters", MaxClientNameLen)
	}
	redirects, dropped := d.RedirectURIs, []string(nil)
	if rule == passingRedirects {
		redirects, dropped = passing(d.RedirectURIs)
	}
	if err := ValidateRedirects(redirects); err != nil {
		switch {
		case rule == passingRedirects && len(redirects) == 0 && len(dropped) > 0:
			return nil, dropped, fmt.Errorf("%w: no redirect URI passes the redirect policy (ADR-0009): https, or http on a loopback host; no custom schemes", ErrInvalidRedirectURI)
		case rule == passingRedirects:
			return nil, dropped, fmt.Errorf("%w: %v", ErrInvalidRedirectURI, err)
		}
		return nil, nil, err
	}
	if len(d.ClientSecret) > 0 || len(d.ClientSecretExpiresAt) > 0 {
		return nil, nil, errors.New("client_secret: not allowed in client metadata")
	}
	m := &clientMetadata{name: name, redirects: redirects}

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
		return nil, nil, errors.New("grant_types: must include authorization_code")
	}
	if len(d.ResponseTypes) > 0 && !slices.Contains(d.ResponseTypes, "code") {
		return nil, nil, errors.New("response_types: must include code")
	}

	listed := d.TokenEndpointAuthMethods
	if d.TokenEndpointAuthMethod != "" {
		listed = append([]string{d.TokenEndpointAuthMethod}, listed...)
	}
	if len(listed) == 0 {
		// Draft -03 §5; for DCR this substitutes RFC 7591's client_secret_basic default, as the
		// broker never issues a secret (ADR-0008 §2), and the response says so.
		listed = []string{string(None)}
	}
	for _, l := range listed {
		switch {
		case slices.Contains(symmetric, l):
			return nil, nil, fmt.Errorf("token_endpoint_auth_method: %s uses a shared secret, which this proxy never issues", l)
		case (l == string(None) || l == string(PrivateKeyJWT)) && !slices.Contains(m.methods, AuthMethod(l)):
			m.methods = append(m.methods, AuthMethod(l))
		}
	}
	if len(m.methods) == 0 {
		return nil, nil, errors.New("token_endpoint_auth_method: none of the listed methods is supported (none, private_key_jwt)")
	}

	switch {
	case len(d.JWKS) > 0 && d.JWKSURI != "":
		return nil, nil, errors.New("jwks, jwks_uri: give one, not both")
	case d.JWKSURI != "":
		if u, err := url.Parse(d.JWKSURI); err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Fragment != "" {
			return nil, nil, errors.New("jwks_uri: must be an https URL")
		}
		m.jwksURI = d.JWKSURI
	case len(d.JWKS) > 0:
		keys, err := parseClientJWKS(d.JWKS)
		if err != nil {
			return nil, nil, err
		}
		m.jwks, m.jwksRaw = keys, d.JWKS
	case slices.Contains(m.methods, PrivateKeyJWT):
		return nil, nil, errors.New("jwks: required for private_key_jwt (or jwks_uri)")
	}
	return m, dropped, nil
}

// passing splits redirect URIs into those that pass ADR-0009 (unique, in order) and the rest.
func passing(uris []string) (kept, dropped []string) {
	for _, u := range uris {
		if ValidateRedirect(u) == nil && !slices.Contains(kept, u) {
			kept = append(kept, u)
		} else {
			dropped = append(dropped, u)
		}
	}
	return kept, dropped
}

// metadataClient is a client registered by its own metadata (CIMD or DCR): the validated metadata
// and how it authenticates.
type metadataClient struct {
	clientAuth
	name      string
	redirects []string
	grants    []string // the client's grant types the broker supports
	trust     TrustLevel
	deny      *Denylist
}

// newMetadataClient builds the client for validated metadata; keys at a jwks_uri are fetched with
// keysClient (the SSRF guard's) and held to the registered-key rules.
func newMetadataClient(id string, m *clientMetadata, trust TrustLevel, deny *Denylist, keysClient *http.Client, jti JTICache, now func() time.Time) metadataClient {
	c := metadataClient{name: m.name, redirects: m.redirects, grants: m.grants, trust: trust, deny: deny,
		clientAuth: clientAuth{id: id, methods: m.methods, jti: jti}}
	switch {
	case m.jwksURI != "":
		c.keys = clientKeys{idp.NewKeySet(&idp.Fetcher{Client: keysClient}, m.jwksURI, now)}
	case len(m.jwks.Keys) > 0:
		c.keys = m.jwks
	}
	return c
}

func (c *metadataClient) ID() string                { return c.id }
func (c *metadataClient) Name() string              { return c.name }
func (c *metadataClient) Trust() TrustLevel         { return c.trust }
func (c *metadataClient) AuthMethods() []AuthMethod { return append([]AuthMethod(nil), c.methods...) }

// AllowsRefresh is true only if the client registered the refresh_token grant (draft -03 §6).
func (c *metadataClient) AllowsRefresh() bool { return slices.Contains(c.grants, "refresh_token") }

// RedirectAllowed applies ADR-0009, then the operator's denylist of redirect hosts (ADR-0008 §9).
func (c *metadataClient) RedirectAllowed(redirectURI string) error {
	if err := MatchRedirect(c.redirects, redirectURI); err != nil {
		return err
	}
	if c.deny.DeniesRedirect(redirectURI) {
		return &RedirectError{Reason: ReasonDenied, Registered: c.redirects, Sent: redirectURI}
	}
	return nil
}
