package config

import (
	"flag"
	"net/netip"
	"net/url"
	"strings"
	"time"

	"github.com/byward-dev/byward/internal/logging"
)

// Config is the validated configuration.
type Config struct {
	PublicURL   *url.URL
	UpstreamURL *url.URL // nil for a stdio upstream
	// UpstreamHeaderTimeout bounds the wait for the HTTP upstream's response headers.
	UpstreamHeaderTimeout time.Duration
	// UpstreamCredential is the operator's header value for the HTTP upstream, sent in
	// UpstreamCredentialHeader (ADR-0016 §7); "" when there is none. Never logged.
	UpstreamCredential, UpstreamCredentialHeader string
	// UpstreamStripHeaders are the operator's extra request headers the relay removes, canonical.
	UpstreamStripHeaders []string
	// A stdio upstream (ADR-0003): its argv, the operator env of its processes (a secret setting's
	// values: the proxy puts none in an error or a log, though the upstream's own stderr is logged as
	// written) and its caps.
	UpstreamCommand                    []string
	UpstreamEnv                        map[string]string
	StdioMaxProcesses, StdioMaxPerUser int
	// StdioStreamIdleTimeout lets the stdio caps evict a process held only by quiet streams; 0 never.
	StdioStreamIdleTimeout time.Duration
	Listen                 string
	InternalListen         string // "" when the internal listener is off
	// AllowedOrigins are origins as browsers serialize them (browserOrigin, host.Origin), the form
	// origin.Origins compares a browser's Origin header in once folded the same way (ADR-0032 A3).
	AllowedOrigins []string
	AllowedHosts   []string
	// TrustedProxies are masked, with IPv4-mapped prefixes unmapped, since logging.ClientAddress
	// compares unmapped peers.
	TrustedProxies []netip.Prefix

	// TLSCertFile and TLSKeyFile serve TLS on the public listener (#183); both "" when it is plain
	// HTTP, as behind an ingress that terminates TLS.
	TLSCertFile, TLSKeyFile string

	// OAuthRateLimits is requests per minute per client address, by endpoint name.
	OAuthRateLimits       map[string]int
	Scope                 string
	ResourceName          string
	ResourceDocumentation string
	LogFormat             string
	Dev                   bool
	// NoAuth serves the upstream with no authentication (ADR-0027).
	NoAuth bool
	// The broker (slice 1.2): Entra as the IdP, static clients.
	EntraTenant       string
	EntraClientID     string
	EntraClientSecret string
	// EntraFederatedTokenFile replaces the client secret with a federated token, re-read on every
	// token request (ADR-0012 §5); exactly one of it, the client secret and EntraClientCertificate is
	// set.
	EntraFederatedTokenFile string
	// EntraClientCertificate is the PEM of the app's certificate and its key, the third credential
	// form; Load checks only that it is the one set, the IdP adapter parses it.
	EntraClientCertificate string
	// EntraClientSecretExpiresAt is zero when the operator did not say.
	EntraClientSecretExpiresAt time.Time
	// IdP is the IdP adapter: "entra", "oidc" or an OIDC preset (OIDCPresets); it also names the
	// callback path (/callback/<IdP>), audit records and metrics.
	IdP string
	// The generic OIDC adapter (IdP other than entra; ADR-0011 §2).
	OIDCIssuer string
	// OIDCLoopbackHTTP lets the oidc adapter use the http issuer on a loopback host, and http
	// endpoints on loopback with it: --dev only, and set together with its relaxation, so the
	// adapter is relaxed exactly when the startup log says so (security invariant 12, #355).
	OIDCLoopbackHTTP bool
	OIDCClientID     string
	OIDCClientSecret string
	OIDCClientKey    string // PEM, for private_key_jwt
	OIDCClientKeyID  string
	// OIDCClientKeyAlg is the client assertion's algorithm; "" means the key type's default (PS256 for
	// RSA, ES256 for EC P-256) (#306).
	OIDCClientKeyAlg string
	OIDCScopes       []string
	OIDCSubjectClaim string
	// OIDCRolesClaim and OIDCGroupsClaim are the ID token claims roles and groups are read from;
	// default `roles` and `groups` for every preset (#286).
	OIDCRolesClaim, OIDCGroupsClaim string
	OIDCName                        string
	KeysDir                         string
	// The identity assertion for the HTTP upstream (ADR-0016): its signing keys, the header that
	// carries it and the optional claims it asserts (a subset of AssertionClaimNames).
	AssertionKeysDir string
	AssertionHeader  string
	AssertionClaims  []string
	// IdentityHeaders also sends the user in the plain IdentityHeaderNames headers (ADR-0016 §5).
	IdentityHeaders bool
	// AssertionUnverifiedEmail asserts an opted-in email the IdP does not vouch for, too.
	AssertionUnverifiedEmail bool
	// OBOScopes are the downstream API's scopes for On-Behalf-Of (ADR-0017); empty means off.
	OBOScopes []string
	// OBOHeader carries the downstream token to the HTTP upstream.
	OBOHeader         string
	StaticClientsFile string
	// StaticClientsFileNamed: the operator set the path, so the file must exist; the default may be
	// absent when CIMD or DCR is on.
	StaticClientsFileNamed bool
	// The access gate (slice 1.5, ADR-0015); validated by gate.New when the broker is wired.
	GateTenants, GateRoles, GateGroups, GateEmailDomains, GateHostedDomains []string
	// AppTokens is "entra" when the MCP endpoint accepts Entra app-only tokens, else "off"
	// (ADR-0022); AppRoles and AppClientIDs are the app gate.
	AppTokens              string
	AppRoles, AppClientIDs []string
	GateAllowEmpty         bool
	// Consent page wording (ADR-0010 §4).
	OperatorName     string
	ScopeDescription string
	// The store (slice 1.3): SQLite in StoreDir, its restore counter in StoreCounterFile. The
	// key, client and store paths default to paths in DataDir.
	DataDir          string
	StoreDir         string
	StoreCounterFile string
	// StorePostgresDSN selects the PostgreSQL store instead of SQLite (#227): the connection
	// string, read from its secret file. It holds a password: never log it.
	StorePostgresDSN string
	RefreshGrace     time.Duration
	// Client ID Metadata Documents (slice 2.1, ADR-0008 §4, §8).
	CIMD                               bool
	CIMDTrustedHosts, CIMDAllowedHosts []string
	// Dynamic client registration (slice 2.2, ADR-0008 §2-3) and the client denylist (§9).
	DCR            bool
	ClientDenylist []string
	// InContainer is set when the proxy runs in a container (/.dockerenv or /run/.containerenv)
	// with its own network namespace; host networking does not count (see ownNetwork).
	InContainer bool

	Values *Values
	// ListWarnings are the host lists' entries that their check cannot tell apart once folded (ADR-0032
	// R7): two that name the same host or origin, or one that names a host always allowed anyway (the
	// public URL's own; a trusted CIMD host in the allowed list). They load, as a warning: two
	// spellings of one host do no harm. The client denylist's warnings are DenylistWarnings, which
	// take registration's key.
	ListWarnings []ListWarning
	// Relaxations lists every relaxation in effect (--dev, --insecure-no-auth), for the startup log
	// and check --offline (security invariant 12).
	Relaxations []string
}

// Actions are command-line-only flags that do something instead of running the proxy.
type Actions struct {
	Version     bool
	JSON        bool
	PrintConfig bool
}

// Load resolves and validates the configuration.
func Load(args, environ []string, readFile readFileFunc) (*Config, Actions, error) {
	var act Actions
	vals, err := resolve(registry, args, environ, readFile, func(fs *flag.FlagSet) {
		fs.BoolVar(&act.Version, "version", false, "print version and build information")
		fs.BoolVar(&act.JSON, "json", false, "with --version: print JSON")
		fs.BoolVar(&act.PrintConfig, "print-config", false, "print the effective configuration and exit")
	})
	if err != nil {
		return nil, act, err
	}
	if act.Version {
		return nil, act, nil
	}
	c, err := validate(vals, inContainer(readFile), true)
	return c, act, err
}

// LoadEnvironment resolves and validates the configuration of a command that takes no arguments,
// such as `byward jwks`: settings come from the environment only, so its errors never suggest a stdio
// upstream command after -- (#499).
func LoadEnvironment(environ []string, readFile readFileFunc) (*Config, error) {
	vals, err := resolve(registry, nil, environ, readFile, nil)
	if err != nil {
		return nil, err
	}
	return validate(vals, inContainer(readFile), false)
}

// authSettings validate authenticated mode's settings, in this order; a feature with settings of its
// own adds its check here.
var authSettings = []func(*Config, *Values) []error{
	(*Config).consent,
	(*Config).idp,
	(*Config).gate,
	(*Config).appTokens,
	(*Config).paths,
	(*Config).storeBackend,
	(*Config).refreshGrace,
	(*Config).assertion,
	(*Config).clientSources,
}

// dependentAuthSettings run after every header setting, the upstream credential's included, for
// checks that compare against them.
var dependentAuthSettings = []func(*Config, *Values) []error{
	(*Config).onBehalfOf,
}

// validate checks the resolved settings. container says byward runs in a container; dashes says the
// command takes a stdio upstream command after --, so an error may suggest one.
func validate(v *Values, container, dashes bool) (*Config, error) {
	c := &Config{Values: v, ResourceName: parseText(v.value("resource-name")), InContainer: container}
	var errs []error
	var errWord error
	if c.LogFormat, errWord = parseWord(v.value("log-format"), "json", "text"); errWord != nil {
		errs = append(errs, errWord)
	}
	if c.Scope, errWord = parseScope(v.value("scope")); errWord != nil {
		errs = append(errs, errWord)
	}
	// Parsed straight into the field: --dev is read only as Config.Dev, where the guard test counts
	// every reader (#355).
	var err error
	if c.Dev, err = v.boolean("dev"); err != nil {
		errs = append(errs, err)
	}
	noAuth, err := v.boolean("insecure-no-auth")
	if err != nil {
		errs = append(errs, err)
	}
	c.NoAuth = noAuth
	if c.Dev {
		// The server skips its check of secret file permissions in development mode (ADR-0018 §11).
		c.Relaxations = append(c.Relaxations, "secret file permissions are not checked")
	}

	if relaxed, err := checkInlineSecrets(v, c.Dev); err != nil {
		errs = append(errs, err)
	} else if relaxed != "" {
		c.Relaxations = append(c.Relaxations, relaxed)
	}

	c.PublicURL, err = parsePublicURL(v.value("public-url"))
	if err != nil {
		errs = append(errs, err)
	} else {
		if c.PublicURL.Scheme == "http" {
			switch {
			case !c.Dev && !c.NoAuth:
				errs = append(errs, errorf("%s: http on loopback needs --dev", v.NameAsGiven("public-url")))
			default:
				c.Relaxations = append(c.Relaxations, "http public URL on loopback")
			}
		}
	}
	errs = append(errs, c.upstream(v, dashes)...)
	errs = append(errs, c.tls(v)...)

	if c.Listen, err = parseListen(v.value("listen"), "host:port such as 127.0.0.1:8080"); err != nil {
		errs = append(errs, err)
	}
	if !v.empty("internal-listen") {
		if c.InternalListen, err = parseListen(v.value("internal-listen"), "host:port such as 127.0.0.1:9090, or empty"); err != nil {
			errs = append(errs, err)
		} else if c.InternalListen == c.Listen && !strings.HasSuffix(c.Listen, ":0") {
			errs = append(errs, errorf("%s: must differ from %s; metrics and probes never share the public listener", v.NameAsGiven("internal-listen"), v.NameAsGiven("listen")))
		}
	}
	var originErrs []error
	c.AllowedOrigins, originErrs = parseOrigins(v.value("allowed-origins"))
	errs = append(errs, originErrs...)
	if c.TrustedProxies, err = parseProxies(v.value("trusted-proxies")); err != nil {
		errs = append(errs, err)
	}
	var rateErrs []error
	c.OAuthRateLimits, rateErrs = parseRateLimits(v.value("oauth-rate-limits"))
	errs = append(errs, rateErrs...)
	var hostErrs []error
	c.AllowedHosts, hostErrs = parseAllowedHosts(v.value("allowed-hosts"))
	errs = append(errs, hostErrs...)
	if c.PublicURL != nil { // a refused entry makes validate return no Config, so no place is ever wrong
		c.ListWarnings = append(c.ListWarnings, c.browserListWarnings()...)
	}
	if c.ResourceDocumentation, err = parseResourceDocumentation(v.value("resource-documentation")); err != nil {
		errs = append(errs, err)
	}
	if c.NoAuth && c.PublicURL != nil {
		errs = append(errs, checkNoAuth(c, v)...)
	}
	if c.NoAuth && v.stdioUpstream() {
		c.Relaxations = append(c.Relaxations, "stdio upstream without authentication: anyone who can reach the proxy starts upstream processes, bounded only by "+
			v.NameAsGiven("stdio-max-processes")+", and every process runs as the same anonymous user")
	}
	if !c.NoAuth {
		for _, check := range authSettings {
			errs = append(errs, check(c, v)...)
		}
		c.ListWarnings = append(c.ListWarnings, c.serverListWarnings()...) // a refused entry makes validate return no Config
	}
	errs = append(errs, c.upstreamCredential(v)...)
	if !c.NoAuth {
		for _, check := range dependentAuthSettings {
			errs = append(errs, check(c, v)...)
		}
	}
	errs = append(errs, c.headerClashes()...)
	if len(errs) > 0 {
		msgs := make([]string, 0, len(errs))
		for _, e := range errs {
			msgs = append(msgs, e.Error())
		}
		return nil, &configError{msg: strings.Join(msgs, "; ")}
	}
	return c, nil
}

// Origin is the public URL's origin as browsers send it (browserOrigin).
func (c *Config) Origin() string { return browserOrigin(c.PublicURL) }

// ShownUpstreamURL is the HTTP upstream's URL as doctor names it: through BYWARD_UPSTREAM_URL's
// shape, as the proxy parsed it, not as given (Values.display), so it is the URL the identity
// assertion's aud names. A Config built by hand, without Values, shows it as Hidden.
func (c *Config) ShownUpstreamURL() string {
	if !c.Values.holds("upstream-url") || c.UpstreamURL == nil {
		return logging.Hidden
	}
	return lookup("upstream-url").shape.display(c.UpstreamURL.String())
}

// ShownIssuer is the oidc IdP's issuer as doctor names it: through BYWARD_OIDC_ISSUER's shape, or,
// when that is unset, the preset's own issuer (OIDCDefaultIssuers), which is byward's.
func (c *Config) ShownIssuer() string {
	switch {
	case !c.Values.holds("oidc-issuer"):
		return logging.Hidden
	case !c.Values.empty("oidc-issuer"):
		return c.Values.display("oidc-issuer")
	}
	return c.OIDCIssuer
}

// Issuer is the broker's issuer, derived once from the public URL: its scheme, host and port.
func (c *Config) Issuer() string { return c.PublicURL.Scheme + "://" + c.PublicURL.Host }
