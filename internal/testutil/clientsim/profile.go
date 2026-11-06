// Package clientsim reproduces how closed MCP clients behave against the proxy, from verified
// behaviour (ADR-0024 §2), so a regression shows up in `mise run test` instead of at release. A
// Profile is versioned data: what one client does at the version it was checked at, each fact with
// its source or marked assumed. Run drives the proxy the way that client does. Open-source clients
// run for real in the integration lane instead (ADR-0024 §3).
package clientsim

// Registration is how a client gets its client ID at the broker.
type Registration string

// Registrations a profile can use.
const (
	Static Registration = "static" // pre-registered by the operator (docs/reference/static-clients.md)
	CIMD   Registration = "cimd"   // a Client ID Metadata Document URL as the client ID (ADR-0008)
	DCR    Registration = "dcr"    // dynamic client registration (RFC 7591)
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
	// ClientID is the static client's ID, or, for CIMD, the clientdocs fixture name whose URL is
	// the client ID.
	ClientID string
	// RedirectURI is the redirect URI as the client sends it.
	RedirectURI string
	// Discovery lists the well-known paths the client requests, in order, before it signs in; the
	// first that answers 200 wins. A path ending in "/" gets the MCP endpoint's path appended
	// (the RFC 9728 path-inserted form).
	Discovery []string
	// UsesChallenge: the client reads resource_metadata from the 401's WWW-Authenticate.
	UsesChallenge bool
	// FirstAuthorizationServerOnly: of several authorization_servers the client uses the first and
	// never falls back.
	FirstAuthorizationServerOnly bool
	// CIMDNeedsNone: the client picks CIMD only if the metadata also lists "none" as a token
	// endpoint auth method.
	CIMDNeedsNone bool
	// PrivateKeyJWT: the client authenticates at /token with a signed client assertion (RFC 7523)
	// instead of as a public client.
	PrivateKeyJWT bool
	// SendsResource: the client sends the RFC 8707 resource parameter on /authorize and /token.
	SendsResource bool
	// Scope is the scope parameter the client sends; empty sends none.
	Scope string
	// Treats403AsAuthFailure: on 403 the client drops its token or registration and signs in again,
	// so a refusal that reached it as a 403 would loop.
	Treats403AsAuthFailure bool
	// HeadersHelperOn401: the client re-runs its headersHelper command on 401 (Claude Code).
	HeadersHelperOn401 bool

	Facts []Fact
}
