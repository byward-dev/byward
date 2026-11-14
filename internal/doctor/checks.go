package doctor

import "slices"

// Check is one check doctor can report. The only checks are the ones declared below, in the order
// docs/reference/commands.md lists them; its table is generated from Checks, so a check added
// here must be described there (BYWARD_UPDATE_REFERENCE=1 go test ./internal/doctor/).
type Check struct {
	class Class
	name  string
}

// checks is every declared check, in declaration order.
var checks []Check

func declare(class Class, name string) Check {
	c := Check{class: class, name: name}
	checks = append(checks, c)
	return c
}

// Checks lists every check doctor can report, in the order the reference lists them.
func Checks() []Check { return slices.Clone(checks) }

// Class is the check's class.
func (c Check) Class() Class { return c.class }

// Name is the check's name, as reports show it.
func (c Check) Name() string { return c.name }

// NewResult is a result of the check whose status, message and fix the caller sets.
func (c Check) NewResult() Result { return Result{Class: c.class, Name: c.name} }

// Result is one outcome of the check.
func (c Check) Result(s Status, message, fix string) Result {
	return Result{Class: c.class, Name: c.name, Status: s, Message: message, Fix: fix}
}

// The checks, in the order the reference lists them.
var (
	CheckTLSCertificateExpiry         = declare(ClassProxy, "TLS certificate expiry")
	CheckTLSCertificateNames          = declare(ClassProxy, "TLS certificate names")
	CheckUpstream                     = declare(ClassProxy, "upstream")
	CheckTrustStore                   = declare(ClassProxy, "trust store")
	CheckUpstreamHop                  = declare(ClassProxy, "upstream hop")
	CheckIdentityHeaders              = declare(ClassProxy, "identity headers")
	CheckConfiguration                = declare(ClassProxy, "configuration")
	CheckResourceMetadataPathInserted = declare(ClassProxy, "protected resource metadata (path-inserted)")
	CheckResourceMetadataRoot         = declare(ClassProxy, "protected resource metadata (root)")
	CheckServerMetadataRFC8414        = declare(ClassProxy, "authorization server metadata (RFC 8414)")
	CheckServerMetadataOpenID         = declare(ClassProxy, "authorization server metadata (OpenID)")
	CheckUnauthenticatedMCPRequest    = declare(ClassProxy, "unauthenticated MCP request")
	CheckHostHeader                   = declare(ClassProxy, "Host header")
	CheckIdentityAssertionKeys        = declare(ClassProxy, "identity assertion keys (discovery)")
	CheckAuthentication               = declare(ClassProxy, "authentication")
	CheckDiscovery                    = declare(ClassIdP, "discovery")
	CheckClientCredential             = declare(ClassIdP, "client credential")
	CheckEntraTenant                  = declare(ClassIdP, "entra tenant")
	CheckEntraSigningKeys             = declare(ClassIdP, "entra signing keys")
	CheckEntraAppAndCredential        = declare(ClassIdP, "entra app and credential")
	CheckEntraAccessToken             = declare(ClassIdP, "entra access token")
	CheckEntraIdtypClaim              = declare(ClassIdP, "entra idtyp claim")
	CheckEntraRedirectURI             = declare(ClassIdP, "entra redirect URI")
	CheckEntraAppRoles                = declare(ClassIdP, "entra app roles")
	CheckClientSecretExpiry           = declare(ClassIdP, "client secret expiry")
	CheckClientCertificateExpiry      = declare(ClassIdP, "client certificate expiry")
)
