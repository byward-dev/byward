package registration

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/byward-dev/byward/internal/store"
)

// Dynamic client registration rules (ADR-0008 §2-3).
const (
	// DCRLifetime is how long a registration lives after its last use (sliding).
	DCRLifetime = 90 * 24 * time.Hour
	// DCRRenewal is the smallest extension worth a store write: a client in daily use renews about
	// once a day, not on every refresh.
	DCRRenewal = 24 * time.Hour
	// MaxDCRClients is the default cap on live registrations (ADR-0008 §3).
	MaxDCRClients = 10000
	// DCRIDPrefix starts every dynamically issued client ID, so the registry chain can tell it from a
	// static or CIMD client ID without a store lookup.
	DCRIDPrefix = "dcr-"
)

// Registration refusals (RFC 7591 §3.2.2). The error text is for operator logs.
var (
	// ErrInvalidClientMetadata: the metadata breaks a rule; the client gets invalid_client_metadata.
	// A refusal caused by the redirect URIs wraps ErrInvalidRedirectURI instead.
	ErrInvalidClientMetadata = errors.New("invalid client metadata")
	// ErrRegistrationsFull: the cap on live registrations is reached (503).
	ErrRegistrationsFull = errors.New("registration: too many client registrations")
)

// DCRConfig configures dynamic client registration.
type DCRConfig struct {
	Store store.Clients
	// KeysClient fetches jwks_uri; it must be the SSRF guard's client.
	KeysClient *http.Client
	JTI        JTICache
	Now        func() time.Time
	// Scopes are the scopes a client may register; others are dropped from the registration.
	Scopes []string
	// Max caps live registrations; zero means MaxDCRClients.
	Max int
	// Deny is the operator's denylist of redirect hosts; nil denies nothing.
	Deny *Denylist
}

// DCRRegistry registers clients (RFC 7591) and resolves them by their issued client ID.
type DCRRegistry struct{ cfg DCRConfig }

// NewDCRRegistry returns a DCR registry.
func NewDCRRegistry(c DCRConfig) *DCRRegistry {
	if c.Max == 0 {
		c.Max = MaxDCRClients
	}
	return &DCRRegistry{cfg: c}
}

// Registered is a new registration: the response body (RFC 7591 §3.2.1) and the redirect URIs that
// were dropped because they fail the redirect policy, without their query, so safe to log
// (ADR-0009 §8).
type Registered struct {
	ClientID string
	Response []byte
	Dropped  []string
}

// registeredDocument is what a registration stores and returns: every registered field
// (RFC 7591 §3.2.1), with the values the broker substituted.
type registeredDocument struct {
	ClientID                string          `json:"client_id"`
	ClientIDIssuedAt        int64           `json:"client_id_issued_at"`
	ClientName              string          `json:"client_name"`
	RedirectURIs            []string        `json:"redirect_uris"`
	GrantTypes              []string        `json:"grant_types"`
	ResponseTypes           []string        `json:"response_types"`
	TokenEndpointAuthMethod string          `json:"token_endpoint_auth_method"`
	JWKS                    json.RawMessage `json:"jwks,omitempty"`
	JWKSURI                 string          `json:"jwks_uri,omitempty"`
	Scope                   string          `json:"scope,omitempty"`
}

// Register validates a registration request with the shared metadata rules, keeping the redirect
// URIs that pass ADR-0009, and stores it. A refusal wraps ErrInvalidRedirectURI or
// ErrInvalidClientMetadata; a full store is ErrRegistrationsFull; a store failure wraps
// ErrUnavailable.
func (r *DCRRegistry) Register(ctx context.Context, body []byte) (*Registered, error) {
	d, err := decodeMetadata(body)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidClientMetadata, err)
	}
	// A client_id in the request is ignored: the broker issues one (registeredDocument).
	d.TokenEndpointAuthMethods = nil // an OIDC/CIMD field: RFC 7591 registers one method
	m, dropped, err := validateMetadata(d, passingRedirects)
	switch {
	case errors.Is(err, ErrInvalidRedirectURI):
		return nil, err
	case err != nil:
		return nil, fmt.Errorf("%w: %v", ErrInvalidClientMetadata, err)
	}
	for _, u := range m.redirects {
		if r.cfg.Deny.DeniesRedirect(u) {
			return nil, fmt.Errorf("%w: %s returns to a host on the operator's denylist", ErrInvalidRedirectURI, withoutQuery(u))
		}
	}
	now := r.cfg.Now()
	id := newClientID()
	doc := registeredDocument{ClientID: id, ClientIDIssuedAt: now.Unix(), ClientName: m.name, RedirectURIs: m.redirects,
		GrantTypes: m.grants, ResponseTypes: []string{"code"}, TokenEndpointAuthMethod: string(m.methods[0]),
		JWKS: m.jwksRaw, JWKSURI: m.jwksURI, Scope: r.supported(d.Scope)}
	stored, err := json.Marshal(doc)
	if err != nil {
		return nil, err
	}
	err = r.cfg.Store.CreateClient(ctx, store.Client{ID: id, Metadata: stored, CreatedAt: now, ExpiresAt: now.Add(DCRLifetime)}, r.cfg.Max)
	switch {
	case errors.Is(err, store.ErrFull):
		return nil, ErrRegistrationsFull
	case err != nil:
		return nil, fmt.Errorf("%w: storing a client registration: %v", ErrUnavailable, err)
	}
	for i, u := range dropped {
		dropped[i] = withoutQuery(u)
	}
	return &Registered{ClientID: id, Response: stored, Dropped: dropped}, nil
}

// supported keeps the requested scopes the broker offers, in order and once each.
func (r *DCRRegistry) supported(scope string) string {
	var kept []string
	for _, s := range strings.Fields(scope) {
		if slices.Contains(r.cfg.Scopes, s) && !slices.Contains(kept, s) {
			kept = append(kept, s)
		}
	}
	return strings.Join(kept, " ")
}

// Client returns a registered client. An unknown, expired or unreadable registration is
// ErrUnknownClient (never ErrMetadataRefused: nothing was refused); a store failure wraps
// ErrUnavailable.
func (r *DCRRegistry) Client(ctx context.Context, id string) (Client, error) {
	if !strings.HasPrefix(id, DCRIDPrefix) {
		return nil, ErrUnknownClient
	}
	rec, err := r.cfg.Store.Client(ctx, id)
	switch {
	case errors.Is(err, store.ErrNotFound):
		return nil, ErrUnknownClient
	case err != nil:
		return nil, fmt.Errorf("%w: loading a client registration: %v", ErrUnavailable, err)
	case !r.cfg.Now().Before(rec.ExpiresAt):
		return nil, fmt.Errorf("%w: client registration expired", ErrUnknownClient)
	}
	// The stored registration goes through the same decoder and rules as a new one, so a rule added
	// later also applies to registrations made before it.
	d, err := decodeMetadata(rec.Metadata)
	if err != nil {
		return nil, fmt.Errorf("%w: stored registration: %v", ErrUnknownClient, err)
	}
	m, _, err := validateMetadata(d, allRedirects)
	if err != nil {
		return nil, fmt.Errorf("%w: stored registration: %v", ErrUnknownClient, err)
	}
	return &dcrClient{metadataClient: newMetadataClient(id, m, NotVerified, r.cfg.Deny, r.cfg.KeysClient, r.cfg.JTI, r.cfg.Now), clients: r.cfg.Store}, nil
}

// dcrClient is a dynamically registered client: never vouched for (ADR-0008 §8).
type dcrClient struct {
	metadataClient
	clients store.Clients
}

// RecordUse renews the registration's sliding expiry and marks it used, so it is not collected as
// never used (ADR-0008 §3). The broker calls it when the client redeems a code or refreshes.
func (c *dcrClient) RecordUse(ctx context.Context, now time.Time) error {
	return c.clients.UseClient(ctx, c.id, now, now.Add(DCRLifetime), DCRRenewal)
}

// newClientID is DCRIDPrefix and 128 random bits.
func newClientID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return DCRIDPrefix + base64.RawURLEncoding.EncodeToString(b)
}
