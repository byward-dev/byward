package config

import (
	"flag"
	"net"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"
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
	// A stdio upstream (ADR-0003): its argv, the operator env of its processes and its caps.
	UpstreamCommand                    []string
	UpstreamEnv                        map[string]string
	StdioMaxProcesses, StdioMaxPerUser int
	// StdioStreamIdleTimeout lets the stdio caps evict a process held only by quiet streams; 0 never.
	StdioStreamIdleTimeout time.Duration
	Listen                 string
	InternalListen         string // "" when the internal listener is off
	AllowedOrigins         []string
	AllowedHosts           []string
	TrustedProxies         []netip.Prefix

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
	OIDCIssuer       string
	OIDCClientID     string
	OIDCClientSecret string
	OIDCClientKey    string // PEM, for private_key_jwt
	OIDCClientKeyID  string
	OIDCScopes       []string
	OIDCSubjectClaim string
	OIDCName         string
	KeysDir          string
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
	// Relaxations lists what --dev relaxed, for the startup log.
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
	c, err := validate(vals, inContainer(readFile))
	return c, act, err
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

func validate(v *Values, container bool) (*Config, error) {
	c := &Config{Values: v, Listen: v.get("listen"), InternalListen: v.get("internal-listen"), Scope: v.get("scope"),
		ResourceName: v.get("resource-name"), ResourceDocumentation: v.get("resource-documentation"),
		LogFormat: v.get("log-format"), InContainer: container}
	var errs []error
	dev, err := strconv.ParseBool(v.get("dev"))
	if err != nil {
		errs = append(errs, errorf("%s: want true or false, got %q", Setting{Name: "dev"}.Env(), v.get("dev")))
	}
	c.Dev = dev
	noAuth, err := strconv.ParseBool(v.get("insecure-no-auth"))
	if err != nil {
		errs = append(errs, errorf("%s: want true or false, got %q", Setting{Name: "insecure-no-auth"}.Env(), v.get("insecure-no-auth")))
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

	c.PublicURL, err = ParsePublicURL(v.get("public-url"))
	if err != nil {
		errs = append(errs, err)
	} else {
		if c.PublicURL.Scheme == "http" {
			switch {
			case !c.Dev && !c.NoAuth:
				errs = append(errs, errorf("BYWARD_PUBLIC_URL: http on loopback needs --dev"))
			default:
				c.Relaxations = append(c.Relaxations, "http public URL on loopback")
			}
		}
	}
	errs = append(errs, c.upstream(v)...)
	errs = append(errs, c.tls(v)...)
	c.UpstreamHeaderTimeout, err = parseHeaderTimeout(v.get("upstream-header-timeout"))
	if err != nil {
		errs = append(errs, err)
	}

	if _, _, err := net.SplitHostPort(c.Listen); err != nil {
		errs = append(errs, errorf("BYWARD_LISTEN: want host:port, got %q", c.Listen))
	}
	if c.InternalListen != "" {
		if _, _, err := net.SplitHostPort(c.InternalListen); err != nil {
			errs = append(errs, errorf("BYWARD_INTERNAL_LISTEN: want host:port or empty, got %q", c.InternalListen))
		} else if c.InternalListen == c.Listen && !strings.HasSuffix(c.Listen, ":0") {
			errs = append(errs, errorf("BYWARD_INTERNAL_LISTEN: must differ from BYWARD_LISTEN; metrics and probes never share the public listener"))
		}
	}
	for _, o := range splitList(v.get("allowed-origins")) {
		n, err := normalizeOrigin(o)
		if err != nil {
			errs = append(errs, errorf("BYWARD_ALLOWED_ORIGINS: %v", err))
			continue
		}
		c.AllowedOrigins = append(c.AllowedOrigins, n)
	}
	c.TrustedProxies, err = parseProxies(v.get("trusted-proxies"))
	if err != nil {
		errs = append(errs, err)
	}
	c.OAuthRateLimits, err = parseRateLimits(v.get("oauth-rate-limits"))
	if err != nil {
		errs = append(errs, err)
	}
	for _, h := range splitList(v.get("allowed-hosts")) {
		if strings.ContainsAny(h, "/ ") {
			errs = append(errs, errorf("BYWARD_ALLOWED_HOSTS: %q is not a host[:port]", h))
			continue
		}
		if err := asciiHost(h); err != nil {
			errs = append(errs, errorf("BYWARD_ALLOWED_HOSTS: %v", err))
			continue
		}
		c.AllowedHosts = append(c.AllowedHosts, strings.ToLower(h))
	}
	if c.LogFormat != "json" && c.LogFormat != "text" {
		errs = append(errs, errorf("BYWARD_LOG_FORMAT: want json or text, got %q", c.LogFormat))
	}
	if c.Scope == "" || strings.ContainsAny(c.Scope, " \"\\") {
		errs = append(errs, errorf("BYWARD_SCOPE: want one scope token, got %q", c.Scope))
	}
	if d := c.ResourceDocumentation; d != "" {
		if _, err := parseURL("resource-documentation", d); err != nil {
			errs = append(errs, err)
		}
	}
	if c.NoAuth && c.PublicURL != nil {
		errs = append(errs, checkNoAuth(c, v)...)
	}
	if c.NoAuth && c.UpstreamCommand != nil {
		c.Relaxations = append(c.Relaxations, "stdio upstream without authentication: anyone who can reach the proxy starts upstream processes, bounded only by BYWARD_STDIO_MAX_PROCESSES, and every process runs as the same anonymous user")
	}
	if !c.NoAuth {
		for _, check := range authSettings {
			errs = append(errs, check(c, v)...)
		}
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

// Origin is the public URL's origin as browsers send it: lower case, default port dropped.
func (c *Config) Origin() string {
	host := strings.ToLower(c.PublicURL.Hostname())
	if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	defaultPort := map[string]string{"http": "80", "https": "443"}[c.PublicURL.Scheme]
	if p := c.PublicURL.Port(); p != "" && p != defaultPort {
		host += ":" + p
	}
	return c.PublicURL.Scheme + "://" + host
}

// Issuer is the broker's issuer, derived once from the public URL: its scheme, host and port.
func (c *Config) Issuer() string { return c.PublicURL.Scheme + "://" + c.PublicURL.Host }
