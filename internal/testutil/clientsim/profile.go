// Package clientsim reproduces how closed MCP clients behave against the proxy, from verified
// behaviour (ADR-0024 §2), so a regression shows up in `mise run test` instead of at release. A
// Profile is versioned data: what one client does at the version it was checked at, each fact with
// its source or marked assumed. SignIn drives the proxy the way that client does. Open-source clients
// run for real in the integration lane instead (ADR-0024 §3).
package clientsim

// Registration is how a client gets its client ID at the broker.
type Registration string

// Registrations a profile can use.
const (
	Static Registration = "static" // pre-registered by the operator (docs/reference/static-clients.md)
	CIMD   Registration = "cimd"   // a Client ID Metadata Document URL as the client ID (ADR-0008)
	DCR    Registration = "dcr"    // RFC 7591 registration at the advertised registration_endpoint (ADR-0008)
)

// Fact is one recorded behaviour and where it comes from. A fact nobody has checked says so:
// Source is "assumed, unverified" and the profile follows the MCP specification there.
type Fact struct {
	What   string
	Source string
}

// Assumed marks a behaviour no source confirms; the profile then follows the MCP specification.
const Assumed = "assumed, unverified"

// Profile is one closed client at one verified version, mapped to its compatibility-matrix cell
// (docs/quality-lenses.md).
type Profile struct {
	Client  string
	Version string // the client version or date the behaviour was checked at
	Cell    string // the compatibility-matrix cell this profile tests

	Registration Registration
	// ClientID is a static client's ID.
	ClientID string
	// Document is the client's clientdocs fixture name: a CIMD client's document, whose URL is its
	// client ID, or a DCR client's registration request (testdata/dcr).
	Document string
	// RedirectURI is the redirect URI as the client sends it.
	RedirectURI string
	// ProtocolVersion is the MCP revision the client sends in initialize.
	ProtocolVersion string
	// Discovery lists the protected resource metadata paths the client requests, in order; the first
	// that answers 200 wins. A path ending in "/" gets the MCP endpoint's path appended (the RFC 9728
	// path-inserted form).
	Discovery []string
	// UsesChallenge: the client first fetches the resource_metadata URL from the 401's
	// WWW-Authenticate, and uses Discovery only without one.
	UsesChallenge bool
	// ASMetadata lists the authorization server metadata names the client tries, in order, at the
	// first authorization_servers entry (RFC 8414 §3.1): "oauth-authorization-server",
	// "openid-configuration".
	ASMetadata []string
	// CIMDNeedsNone: the client picks CIMD only if the metadata also lists "none" as a token
	// endpoint auth method.
	CIMDNeedsNone bool
	// PrivateKeyJWT: the client authenticates at /token with a signed client assertion (RFC 7523)
	// when the server offers it, instead of as a public client. The server test supports it for
	// CIMD clients, whose document names the jwks_uri.
	PrivateKeyJWT bool
	// ChecksIss: the client rejects an authorization response whose iss is not the metadata issuer
	// (RFC 9207).
	ChecksIss bool
	// NeedsIssSupported: the client uses its client ID only if the metadata sets
	// authorization_response_iss_parameter_supported (RFC 9207 §3).
	NeedsIssSupported bool
	// SendsResource: the client sends the RFC 8707 resource parameter on /authorize and /token.
	SendsResource bool
	// AddsOfflineAccess: the client appends offline_access when the authorization server metadata
	// lists it in scopes_supported.
	AddsOfflineAccess bool
	// Treats403AsAuthFailure: on 403 the client drops its token or registration and signs in again,
	// so a refusal that reached it as a 403 would loop.
	Treats403AsAuthFailure bool

	Facts []Fact
}
