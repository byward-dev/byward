package config

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/byward-dev/byward/internal/ratelimit"
)

// registry is every setting the proxy reads, in the order the effective configuration is printed.
var registry = []Setting{
	{Name: "public-url", Help: "public URL of the MCP endpoint exactly as users enter it, e.g. https://mcp.example.com/mcp; an internationalized host in its ASCII (xn--) form"},
	{Name: "upstream-url", Help: "URL of the HTTP upstream MCP server; or set a stdio upstream with upstream-command"},
	{Name: "upstream-header-timeout", Default: "5m", Help: "how long the HTTP upstream may take to send its response headers; a request that waits longer gets a JSON-RPC timeout error, and a streamed response is not limited once its headers arrive; 1s to 1h (ADR-0018 §7)"},
	{Name: "upstream-command", Help: "stdio upstream: the command as a JSON array, e.g. [\"/usr/local/bin/server\",\"--flag\"], never run through a shell; or give it after -- on the command line (docs/how-to/stdio-upstream.md)"},
	{Name: "upstream-env", Secret: true, Help: "stdio upstream: KEY=VALUE lines set in the environment of each upstream process, besides the inherited PATH, HOME, USER, LOGNAME, TMPDIR, TZ, LANG and LC_* (ADR-0016 §6); values are never logged"},
	{Name: "stdio-max-processes", Default: "64", Help: "stdio upstream: most upstream processes alive at once; when full, the least recently used idle one is stopped (ADR-0003 §5)"},
	{Name: "stdio-max-processes-per-user", Default: "8", Help: "stdio upstream: most upstream processes one user has alive at once; when full, that user's least recently used idle one is stopped"},
	{Name: "listen", Default: "127.0.0.1:8080", Help: "address to listen on; public addresses only when configured"},
	{Name: "allowed-origins", Help: "comma-separated Origin values allowed on the MCP endpoint (scheme://host[:port]); an internationalized host in its ASCII (xn--) form"},
	{Name: "allowed-hosts", Help: "comma-separated extra Host values accepted besides the public URL's host; an internationalized host in its ASCII (xn--) form"},
	{Name: "scope", Default: "mcp", Help: "the scope advertised in protected resource metadata and 401 challenges"},
	{Name: "resource-name", Help: "human-readable resource name in protected resource metadata"},
	{Name: "resource-documentation", Help: "documentation URL in protected resource metadata"},
	{Name: "log-format", Default: "json", Help: "log format: json or text"},
	{Name: "trusted-proxies", Help: "comma-separated CIDRs or addresses of reverse proxies whose X-Forwarded-For is trusted for the client address (ADR-0018 §6); empty trusts none"},
	{Name: "oauth-rate-limits", Help: "per-minute limits per client address on OAuth endpoints, e.g. authorize=60,token=120 (ADR-0018 §8); unset endpoints keep their defaults"},
	{Name: "internal-listen", Default: "127.0.0.1:9090", Help: "address of the internal listener for /metrics, /livez and /readyz (ADR-0018 §10); empty turns it off"},
	{Name: "entra-tenant", Auth: true, Help: "Entra tenant ID (a GUID) of the IdP app"},
	{Name: "entra-client-id", Auth: true, Help: "application (client) ID of the IdP app registration"},
	{Name: "entra-client-secret", Auth: true, Secret: true, Help: "client secret of the IdP app"},
	{Name: "entra-client-secret-expires-at", Auth: true, Help: "when the client secret expires, as a date (2027-11-06) or an RFC 3339 time; the proxy warns at startup and doctor warns from 30 days before (ADR-0012 §10)"},
	{Name: "data-dir", Auth: true, Default: "/var/lib/byward", Help: "data directory, an absolute path; the keys, clients and store settings default to paths in it (ADR-0007 §6, docs/how-to/state.md)"},
	{Name: "keys-dir", Auth: true, Help: "directory of sealing keys; each file is one key, its name the key ID; default: keys in the data directory (docs/how-to/sealing-keys.md)"},
	{Name: "static-clients-file", Auth: true, Help: "JSON file of pre-registered MCP clients; default: clients.json in the data directory (docs/reference/static-clients.md)"},
	{Name: "gate-tenants", Auth: true, Help: "access gate: comma-separated Entra tenant IDs allowed to sign in (docs/how-to/access-gate.md)"},
	{Name: "gate-roles", Auth: true, Help: "access gate: comma-separated app roles; users need at least one (docs/how-to/access-gate.md)"},
	{Name: "gate-groups", Auth: true, Help: "access gate: comma-separated group IDs; users need one, and groups overage denies (docs/how-to/access-gate.md)"},
	{Name: "gate-email-domains", Auth: true, Help: "access gate: comma-separated domains of a verified email; generic OIDC IdPs only, so not usable with Entra (the only IdP so far) (docs/how-to/access-gate.md)"},
	{Name: "gate-hosted-domains", Auth: true, Help: "access gate: comma-separated Google Workspace domains (hd claim); Google only, so not usable with Entra (the only IdP so far) (docs/how-to/access-gate.md)"},
	{Name: "dcr", Auth: true, Bool: true, Default: "true", Help: "accept Dynamic Client Registration at /register (Cursor, Gemini CLI) and advertise it; false turns it off (docs/how-to/dcr.md)"},
	{Name: "client-denylist", Auth: true, Help: "comma-separated CIMD client IDs (https URLs) and redirect host names refused for CIMD and DCR clients (docs/how-to/dcr.md)"},
	{Name: "cimd", Auth: true, Bool: true, Default: "true", Help: "accept MCP clients identified by a Client ID Metadata Document URL (Claude, VS Code) and advertise it; false turns it off (docs/how-to/cimd.md)"},
	{Name: "cimd-trusted-hosts", Auth: true, Help: "comma-separated hosts whose client metadata documents you vouch for: their apps show as trusted by you on the consent page (docs/how-to/cimd.md)"},
	{Name: "cimd-allowed-hosts", Auth: true, Help: "comma-separated hosts allowed to publish client metadata documents besides the trusted ones; empty allows any host (docs/how-to/cimd.md)"},
	{Name: "gate-allow-empty", Auth: true, Bool: true, Default: "false", Help: "allow an empty access gate for a Google or generic OIDC IdP (anyone with an account can sign in); no effect with Entra (docs/how-to/access-gate.md)"},
	{Name: "operator-name", Auth: true, Help: "who runs this proxy, shown on the consent page, e.g. Contoso IT"},
	{Name: "scope-description", Auth: true, Help: "what the scope lets an app do, in plain words for the consent page, e.g. Read and query your team's dashboards"},
	{Name: "store-dir", Auth: true, Help: "state directory of the SQLite store, an absolute path, created with mode 0700; the directory to back up; default: state in the data directory (ADR-0007, docs/how-to/state.md)"},
	{Name: "store-counter-file", Auth: true, Help: "restore-detection counter file, an absolute path outside the state directory and its backups; default: store-writes next to the keys directory (ADR-0007 §9)"},
	{Name: "refresh-grace", Auth: true, Default: "30s", Help: "how long a just-rotated refresh token is still accepted, for a client retrying a lost response; 0s to 60s (ADR-0006 §4)"},
	{Name: "insecure-no-auth", Bool: true, Default: "false", Help: "no authentication at all, for trying the proxy out and for tests; loopback only (ADR-0027)"},
	{Name: "dev", Bool: true, Default: "false", Help: "development mode: enables the relaxations it logs at startup"},
}

// Config is the validated configuration.
type Config struct {
	PublicURL   *url.URL
	UpstreamURL *url.URL // nil for a stdio upstream
	// UpstreamHeaderTimeout bounds the wait for the HTTP upstream's response headers.
	UpstreamHeaderTimeout time.Duration
	// A stdio upstream (ADR-0003): its argv, the operator env of its processes and its caps.
	UpstreamCommand                    []string
	UpstreamEnv                        map[string]string
	StdioMaxProcesses, StdioMaxPerUser int
	Listen                             string
	InternalListen                     string // "" when the internal listener is off
	AllowedOrigins                     []string
	AllowedHosts                       []string
	TrustedProxies                     []netip.Prefix
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
	// EntraClientSecretExpiresAt is zero when the operator did not say.
	EntraClientSecretExpiresAt time.Time
	KeysDir                    string
	StaticClientsFile          string
	// StaticClientsFileNamed: the operator set the path, so the file must exist; the default may be
	// absent when CIMD or DCR is on.
	StaticClientsFileNamed bool
	// The access gate (slice 1.5, ADR-0015); validated by gate.New when the broker is wired.
	GateTenants, GateRoles, GateGroups, GateEmailDomains, GateHostedDomains []string
	GateAllowEmpty                                                          bool
	// Consent page wording (ADR-0010 §4).
	OperatorName     string
	ScopeDescription string
	// The store (slice 1.3): SQLite in StoreDir, its restore counter in StoreCounterFile. The
	// key, client and store paths default to paths in DataDir.
	DataDir          string
	StoreDir         string
	StoreCounterFile string
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

// errHelp is returned for -h/--help.
var errHelp = flag.ErrHelp

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
		c.EntraTenant, c.EntraClientID, c.EntraClientSecret = v.get("entra-tenant"), v.get("entra-client-id"), v.get("entra-client-secret")
		c.OperatorName, c.ScopeDescription = v.get("operator-name"), v.get("scope-description")
		errs = append(errs, checkText("operator-name", c.OperatorName, 80)...)
		errs = append(errs, checkText("scope-description", c.ScopeDescription, 200)...)
		for _, s := range []string{"entra-tenant", "entra-client-id", "entra-client-secret"} {
			if v.get(s) == "" {
				env := Setting{Name: s}.Env()
				if s == "entra-client-secret" {
					env += "_FILE"
				}
				errs = append(errs, errorf("%s is required (or set BYWARD_INSECURE_NO_AUTH to try the proxy without sign-in)", env))
			}
		}
		c.GateTenants, c.GateRoles, c.GateGroups = splitList(v.get("gate-tenants")), splitList(v.get("gate-roles")), splitList(v.get("gate-groups"))
		c.GateEmailDomains, c.GateHostedDomains = splitList(v.get("gate-email-domains")), splitList(v.get("gate-hosted-domains"))
		// A gate list that is set but names nothing would silently open the gate.
		for _, s := range []string{"gate-tenants", "gate-roles", "gate-groups", "gate-email-domains", "gate-hosted-domains"} {
			if raw := v.get(s); raw != "" && len(splitList(raw)) == 0 {
				errs = append(errs, errorf("%s is set but lists nothing; remove it or give at least one entry", Setting{Name: s}.Env()))
			}
		}
		if c.GateAllowEmpty, err = strconv.ParseBool(v.get("gate-allow-empty")); err != nil {
			errs = append(errs, errorf("%s: want true or false, got %q", Setting{Name: "gate-allow-empty"}.Env(), v.get("gate-allow-empty")))
		}
		errs = append(errs, c.paths(v)...)
		errs = append(errs, c.refreshGrace(v)...)
		if c.DCR, err = strconv.ParseBool(v.get("dcr")); err != nil {
			errs = append(errs, errorf("%s: want true or false, got %q", Setting{Name: "dcr"}.Env(), v.get("dcr")))
		}
		if raw := v.get("client-denylist"); raw != "" {
			if c.ClientDenylist = splitList(raw); len(c.ClientDenylist) == 0 {
				errs = append(errs, errorf("%s is set but lists nothing; remove it or give at least one entry", Setting{Name: "client-denylist"}.Env()))
			}
		}
		if c.CIMD, err = strconv.ParseBool(v.get("cimd")); err != nil {
			errs = append(errs, errorf("%s: want true or false, got %q", Setting{Name: "cimd"}.Env(), v.get("cimd")))
		}
		for _, s := range []struct {
			name string
			dst  *[]string
		}{{"cimd-trusted-hosts", &c.CIMDTrustedHosts}, {"cimd-allowed-hosts", &c.CIMDAllowedHosts}} {
			env, raw := Setting{Name: s.name}.Env(), v.get(s.name)
			*s.dst = splitList(raw)
			switch {
			case raw != "" && len(*s.dst) == 0:
				errs = append(errs, errorf("%s is set but lists nothing; remove it or give at least one host", env))
			case raw != "" && !c.CIMD:
				errs = append(errs, errorf("%s has no effect while BYWARD_CIMD is false; remove one of them", env))
			}
			for i, h := range *s.dst {
				if err := asciiHost(h); err != nil {
					errs = append(errs, errorf("%s: %v", env, err))
				} else if strings.ContainsAny(h, "/:*@ ") || !strings.Contains(h, ".") {
					errs = append(errs, errorf("%s: %q is not a host name such as claude.ai (no scheme, port, path or wildcard)", env, h))
				}
				(*s.dst)[i] = strings.ToLower(h)
			}
		}
		errs = append(errs, c.secretExpiry(v)...)
		if t := c.EntraTenant; t != "" && !isGUID(t) {
			errs = append(errs, errorf("BYWARD_ENTRA_TENANT: want the tenant ID, a GUID such as 00000000-0000-0000-0000-000000000000, got %q", t))
		}
	}
	if len(errs) > 0 {
		msgs := make([]string, 0, len(errs))
		for _, e := range errs {
			msgs = append(msgs, e.Error())
		}
		return nil, &configError{msg: strings.Join(msgs, "; ")}
	}
	return c, nil
}

// upstream reads the upstream: an HTTP URL or a stdio command, exactly one of them.
func (c *Config) upstream(v *Values) []error {
	urlEnv, cmdEnv, envEnv := Setting{Name: "upstream-url"}.Env(), Setting{Name: "upstream-command"}.Env(), Setting{Name: "upstream-env"}.Env()+"_FILE"
	raw := v.get("upstream-command")
	if raw == "" {
		if v.get("upstream-env") != "" {
			return []error{errorf("%s is set, but there is no stdio upstream: set %s too", envEnv, cmdEnv)}
		}
		u, err := parseURL("upstream-url", v.get("upstream-url"))
		if err != nil {
			return []error{errorf("%s (or %s, or a command after --)", err.Error(), cmdEnv)}
		}
		c.UpstreamURL = u
		return nil
	}
	var errs []error
	if v.get("upstream-url") != "" {
		errs = append(errs, errorf("%s and %s are both set: an upstream is either HTTP or stdio", urlEnv, cmdEnv))
	}
	if v.command != nil {
		c.UpstreamCommand = append([]string(nil), v.command...)
	} else if err := json.Unmarshal([]byte(raw), &c.UpstreamCommand); err != nil {
		c.UpstreamCommand = nil
	}
	if len(c.UpstreamCommand) == 0 || c.UpstreamCommand[0] == "" {
		errs = append(errs, errorf("%s: want a JSON array of strings whose first element is the program, e.g. [\"/usr/local/bin/server\",\"--flag\"], got %q", cmdEnv, raw))
	}
	env, err := parseEnvLines(v.get("upstream-env"))
	if err != nil {
		errs = append(errs, errorf("%s: %v", envEnv, err))
	}
	c.UpstreamEnv = env
	limits := []struct {
		name string
		dst  *int
	}{{"stdio-max-processes", &c.StdioMaxProcesses}, {"stdio-max-processes-per-user", &c.StdioMaxPerUser}}
	for _, l := range limits {
		n, err := strconv.Atoi(v.get(l.name))
		if err != nil || n < 1 || n > 10000 {
			errs = append(errs, errorf("%s: want a whole number from 1 to 10000, got %q", Setting{Name: l.name}.Env(), v.get(l.name)))
			continue
		}
		*l.dst = n
	}
	if c.StdioMaxPerUser > c.StdioMaxProcesses && c.StdioMaxProcesses > 0 {
		errs = append(errs, errorf("%s (%d) must not exceed %s (%d)", Setting{Name: "stdio-max-processes-per-user"}.Env(), c.StdioMaxPerUser,
			Setting{Name: "stdio-max-processes"}.Env(), c.StdioMaxProcesses))
	}
	return errs
}

// parseEnvLines reads KEY=VALUE lines; blank lines and lines starting with # are skipped. Errors
// name the line, never its value.
func parseEnvLines(raw string) (map[string]string, error) {
	if raw == "" {
		return nil, nil
	}
	env := map[string]string{}
	for i, line := range strings.Split(raw, "\n") {
		line = strings.TrimSuffix(line, "\r")
		if strings.TrimSpace(line) == "" || strings.HasPrefix(strings.TrimSpace(line), "#") {
			continue
		}
		k, val, ok := strings.Cut(line, "=")
		if !ok || k == "" || strings.TrimSpace(k) != k {
			return nil, fmt.Errorf("line %d: want KEY=VALUE", i+1)
		}
		if _, dup := env[k]; dup {
			return nil, fmt.Errorf("line %d: %s is set twice", i+1, k)
		}
		env[k] = val
	}
	return env, nil
}

// checkText limits page wording: no control or format characters (bidi overrides), at most max
// characters.
func checkText(name, s string, max int) []error {
	env := Setting{Name: name}.Env()
	if strings.ContainsFunc(s, func(r rune) bool { return unicode.IsControl(r) || unicode.Is(unicode.Cf, r) }) {
		return []error{errorf("%s: must not contain control or formatting characters", env)}
	}
	if n := utf8.RuneCountInString(s); n > max {
		return []error{errorf("%s: at most %d characters, got %d", env, max, n)}
	}
	return nil
}

// within reports whether path is dir or inside it.
func within(dir, path string) bool {
	rel, err := filepath.Rel(dir, path)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

// maxRefreshGrace is the upper bound of ADR-0006 §4 (range 0–60 s).
const maxRefreshGrace = 60 * time.Second

// paths resolves the data directory and the paths that default into it: keys, static clients,
// the store and its restore counter (ADR-0007 §6, §9). No path is relative to the working directory.
func (c *Config) paths(v *Values) []error {
	var errs []error
	c.DataDir = v.get("data-dir")
	if !filepath.IsAbs(c.DataDir) {
		return []error{errorf("BYWARD_DATA_DIR: want an absolute path (no paths relative to the working directory, ADR-0007 §6), got %q", c.DataDir)}
	}
	or := func(name, def string) string {
		if p := v.get(name); p != "" {
			return p
		}
		return filepath.Join(c.DataDir, def)
	}
	c.KeysDir, c.StaticClientsFile, c.StoreDir = or("keys-dir", "keys"), or("static-clients-file", "clients.json"), or("store-dir", "state")
	c.StaticClientsFileNamed = v.get("static-clients-file") != ""
	if !filepath.IsAbs(c.StoreDir) {
		errs = append(errs, errorf("BYWARD_STORE_DIR: want an absolute path (no paths relative to the working directory, ADR-0007 §6), got %q", c.StoreDir))
	}
	c.StoreCounterFile = v.get("store-counter-file")
	if c.StoreCounterFile == "" {
		// Next to the keys: outside the state directory, so a restored backup of it is detected.
		c.StoreCounterFile = filepath.Join(filepath.Dir(filepath.Clean(c.KeysDir)), "store-writes")
	}
	switch {
	case !filepath.IsAbs(c.StoreCounterFile):
		errs = append(errs, errorf("BYWARD_STORE_COUNTER_FILE: want an absolute path, got %q (the default is derived from BYWARD_KEYS_DIR, so set an absolute keys directory or this setting)", c.StoreCounterFile))
	case filepath.IsAbs(c.StoreDir) && within(c.StoreDir, c.StoreCounterFile):
		errs = append(errs, errorf("BYWARD_STORE_COUNTER_FILE: %s is inside BYWARD_STORE_DIR %s, so a restored backup of the state directory would restore it too and go undetected; keep the keys directory outside the state directory, or set this to a path outside it", c.StoreCounterFile, c.StoreDir))
	}
	return errs
}

// Bounds of the upstream response-header timeout: long enough for any tool call that answers
// with plain JSON (its headers come only when the tool finishes), short enough to free the slot.
const (
	minHeaderTimeout = time.Second
	maxHeaderTimeout = time.Hour
)

func parseHeaderTimeout(raw string) (time.Duration, error) {
	d, err := time.ParseDuration(raw)
	switch {
	case err != nil:
		return 0, errorf("BYWARD_UPSTREAM_HEADER_TIMEOUT: want a duration such as 5m, got %q", raw)
	case d < minHeaderTimeout || d > maxHeaderTimeout:
		return 0, errorf("BYWARD_UPSTREAM_HEADER_TIMEOUT: want 1s to 1h, got %s", d)
	}
	return d, nil
}

// secretExpiry parses the client secret's end date: a date (midnight UTC) or an RFC 3339 time,
// such as the endDateTime that `az ad app credential list` prints.
func (c *Config) secretExpiry(v *Values) []error {
	raw := v.get("entra-client-secret-expires-at")
	if raw == "" {
		return nil
	}
	for _, layout := range []string{time.DateOnly, time.RFC3339} {
		if t, err := time.Parse(layout, raw); err == nil {
			c.EntraClientSecretExpiresAt = t.UTC()
			return nil
		}
	}
	return []error{errorf("%s: want a date such as 2027-11-06 or an RFC 3339 time, got %q", Setting{Name: "entra-client-secret-expires-at"}.Env(), raw)}
}

// refreshGrace parses the refresh-token grace window (ADR-0006 §4: 0 to 60 s).
func (c *Config) refreshGrace(v *Values) []error {
	grace, err := time.ParseDuration(v.get("refresh-grace"))
	switch {
	case err != nil:
		return []error{errorf("BYWARD_REFRESH_GRACE: want a duration such as 30s, got %q", v.get("refresh-grace"))}
	case grace < 0 || grace > maxRefreshGrace:
		return []error{errorf("BYWARD_REFRESH_GRACE: want 0s to 60s, got %s", grace)}
	}
	c.RefreshGrace = grace
	return nil
}

func isGUID(s string) bool {
	if len(s) != 36 {
		return false
	}
	for i, r := range s {
		switch {
		case i == 8 || i == 13 || i == 18 || i == 23:
			if r != '-' {
				return false
			}
		case !strings.ContainsRune("0123456789abcdefABCDEF", r):
			return false
		}
	}
	return true
}

// inContainer reports whether the proxy runs in a container (Docker or Podman marker file) that
// has its own network namespace. With host networking (`--network host`) a 0.0.0.0 listener binds
// the host's interfaces, so that does not count.
func inContainer(readFile readFileFunc) bool {
	if readFile == nil {
		return false
	}
	for _, p := range []string{"/.dockerenv", "/run/.containerenv"} {
		if _, err := readFile(p); err == nil {
			return ownNetwork(readFile)
		}
	}
	return false
}

// ownNetwork reports whether every network interface is one a container's own namespace has:
// lo, ethN, and the kernel's tunnel placeholders. Anything else (docker0, bond0, wlan0, br-…) or
// an unreadable list means host networking, and the answer is no: the check fails closed.
// Measured 2026-11-06 on Docker 28.4: bridge shows lo, eth0 and the placeholders; host adds
// docker0, bond0, dummy0, teql0 and services1.
func ownNetwork(readFile readFileFunc) bool {
	b, err := readFile("/proc/self/net/dev")
	if err != nil {
		return false
	}
	placeholders := map[string]bool{"lo": true, "tunl0": true, "gre0": true, "gretap0": true, "erspan0": true,
		"ip_vti0": true, "ip6_vti0": true, "sit0": true, "ip6tnl0": true, "ip6gre0": true}
	lines := strings.Split(string(b), "\n")
	if len(lines) < 3 {
		return false
	}
	for _, l := range lines[2:] {
		name, _, ok := strings.Cut(l, ":")
		if !ok {
			continue
		}
		name = strings.TrimSpace(name)
		if placeholders[name] {
			continue
		}
		if rest, isEth := strings.CutPrefix(name, "eth"); isEth && rest != "" && strings.Trim(rest, "0123456789") == "" && virtual(readFile, name) {
			continue
		}
		return false
	}
	return true
}

// virtual reports whether an interface has a peer (veth, macvlan, ipvlan: iflink differs from
// ifindex). A host's physical NIC, as seen with host networking, has iflink == ifindex; that, or
// an unreadable value, answers no. Measured on Docker 28.4: bridge eth0 ifindex=11 iflink=25,
// host-network eth0 ifindex=4 iflink=4.
func virtual(readFile readFileFunc, name string) bool {
	index, err1 := readFile("/sys/class/net/" + name + "/ifindex")
	link, err2 := readFile("/sys/class/net/" + name + "/iflink")
	i, l := strings.TrimSpace(string(index)), strings.TrimSpace(string(link))
	return err1 == nil && err2 == nil && i != "" && l != "" && i != l
}

// checkNoAuth fences --insecure-no-auth in (ADR-0027): the public URL is loopback, the listen
// address is loopback unless the proxy runs in a container, the Host and Origin allowlists stay
// loopback-only, and no authentication setting is present.
func checkNoAuth(c *Config, v *Values) []error {
	const env = "BYWARD_INSECURE_NO_AUTH"
	var errs []error
	if !isLoopback(c.PublicURL.Hostname()) {
		errs = append(errs, errorf("%s: BYWARD_PUBLIC_URL must be a loopback URL, e.g. http://localhost:8080/mcp", env))
	}
	host, port, err := net.SplitHostPort(c.Listen)
	switch {
	case err != nil:
		errs = append(errs, errorf("%s: BYWARD_LISTEN must be a loopback host:port such as 127.0.0.1:8080", env))
	case isLoopback(host):
	case c.InContainer:
		// The host port is the public URL's; the container port is the listen address's.
		hostPort := c.PublicURL.Port()
		if hostPort == "" {
			hostPort = map[string]string{"http": "80", "https": "443"}[c.PublicURL.Scheme]
		}
		c.Relaxations = append(c.Relaxations, fmt.Sprintf(
			"listening on %s inside a container: publish the port on loopback only, e.g. docker run -p 127.0.0.1:%s:%s; anyone who can reach the published port can use the upstream", c.Listen, hostPort, port))
	default:
		errs = append(errs, errorf("%s: BYWARD_LISTEN must be a loopback address such as 127.0.0.1:8080 (non-loopback only inside a container with its own network, not --network host)", env))
	}
	for _, h := range c.AllowedHosts {
		if hn, _, err := net.SplitHostPort(h); !isLoopback(strings.Trim(h, "[]")) && (err != nil || !isLoopback(hn)) {
			errs = append(errs, errorf("%s: BYWARD_ALLOWED_HOSTS may only list loopback hosts, got %q", env, h))
		}
	}
	for _, o := range c.AllowedOrigins {
		if u, err := url.Parse(o); err != nil || !isLoopback(u.Hostname()) {
			errs = append(errs, errorf("%s: BYWARD_ALLOWED_ORIGINS may only list loopback origins, got %q", env, o))
		}
	}
	for _, val := range v.Effective() {
		if val.Setting.Auth && val.Source != SourceDefault {
			errs = append(errs, errorf("%s cannot be combined with %s: remove one of them", env, val.Setting.Env()))
		}
	}
	if len(errs) == 0 {
		c.Relaxations = append(c.Relaxations, "AUTHENTICATION IS OFF: anyone who can reach "+c.PublicURL.String()+" can use the upstream, and the upstream receives no identity")
	}
	return errs
}

// checkInlineSecrets rejects secrets given directly in env; development mode accepts them and
// reports the relaxation instead.
func checkInlineSecrets(v *Values, dev bool) (relaxation string, err error) {
	secrets := v.inlineSecrets()
	switch {
	case len(secrets) == 0:
		return "", nil
	case !dev:
		return "", errorf("%s: secrets must come from a file (%s_FILE)", strings.Join(secrets, ", "), secrets[0])
	default:
		return "inline secrets accepted: " + strings.Join(secrets, ", "), nil
	}
}

// ParsePublicURL validates the public URL of the MCP endpoint, as `byward init entra` also needs it:
// absolute, an ASCII host, a path without a trailing slash, no query or fragment, and https unless
// the host is loopback (which the proxy itself accepts only with --dev).
func ParsePublicURL(raw string) (*url.URL, error) {
	u, err := parseURL("public-url", raw)
	if err != nil {
		return nil, err
	}
	var errs []string
	if err := asciiHost(u.Hostname()); err != nil {
		errs = append(errs, fmt.Sprintf("BYWARD_PUBLIC_URL: %v", err))
	}
	if u.Path == "" || strings.HasSuffix(u.Path, "/") {
		errs = append(errs, fmt.Sprintf("BYWARD_PUBLIC_URL: give the MCP endpoint path without a trailing slash, e.g. https://%s/mcp", u.Host))
	}
	if u.RawQuery != "" || u.Fragment != "" {
		errs = append(errs, "BYWARD_PUBLIC_URL: must not have a query or fragment")
	}
	if u.Scheme == "http" && !isLoopback(u.Hostname()) {
		errs = append(errs, "BYWARD_PUBLIC_URL: must use https (http is allowed only for loopback hosts with --dev)")
	}
	if len(errs) > 0 {
		return nil, &configError{msg: strings.Join(errs, "; ")}
	}
	return u, nil
}

// RedirectURL is the IdP callback the proxy registers for idpName under publicURL.
func RedirectURL(publicURL *url.URL, idpName string) string {
	return (&Config{PublicURL: publicURL}).Issuer() + "/callback/" + idpName
}

func parseURL(name, raw string) (*url.URL, error) {
	env := Setting{Name: name}.Env()
	if raw == "" {
		return nil, errorf("%s is required", env)
	}
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" || u.User != nil {
		return nil, errorf("%s: want an absolute http(s) URL without credentials, got %q", env, raw)
	}
	return u, nil
}

// Bounds of a configured OAuth rate limit (ADR-0018 Consequences: configurable within bounds). There
// is no off switch.
const (
	minRateLimit = 1
	maxRateLimit = 10000
)

func parseRateLimits(raw string) (map[string]int, error) {
	out := ratelimit.Defaults()
	for _, item := range splitList(raw) {
		name, val, ok := strings.Cut(item, "=")
		name = strings.TrimSpace(name)
		if _, known := out[name]; !ok || !known {
			return nil, errorf("BYWARD_OAUTH_RATE_LIMITS: %q is not endpoint=per-minute for one of %s", item, strings.Join(ratelimit.Endpoints, ", "))
		}
		n, err := strconv.Atoi(strings.TrimSpace(val))
		if err != nil || n < minRateLimit || n > maxRateLimit {
			return nil, errorf("BYWARD_OAUTH_RATE_LIMITS: %s must be a whole number from %d to %d per minute, got %q", name, minRateLimit, maxRateLimit, val)
		}
		out[name] = n
	}
	return out, nil
}

func parseProxies(raw string) ([]netip.Prefix, error) {
	var out []netip.Prefix
	for _, item := range splitList(raw) {
		p, err := netip.ParsePrefix(item)
		if err != nil {
			a, aerr := netip.ParseAddr(item)
			if aerr != nil {
				return nil, errorf("BYWARD_TRUSTED_PROXIES: %q is not a CIDR or an IP address", item)
			}
			p = netip.PrefixFrom(a.Unmap(), a.Unmap().BitLen())
		}
		out = append(out, p.Masked())
	}
	return out, nil
}

func splitList(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// normalizeOrigin returns scheme://host[:port] in lower case, the form browsers send.
func normalizeOrigin(o string) (string, error) {
	u, err := url.Parse(o)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" || u.Path != "" || u.RawQuery != "" || u.User != nil {
		return "", fmt.Errorf("%q is not an origin (scheme://host[:port])", o)
	}
	if err := asciiHost(u.Hostname()); err != nil {
		return "", err
	}
	return strings.ToLower(u.Scheme + "://" + u.Host), nil
}

// asciiHost refuses a host with non-ASCII characters. Browsers and MCP clients send an
// internationalized host in its ASCII (xn--) form in Host, Origin and every URL they compare
// (WHATWG URL "domain to ASCII", RFC 6454 §7.3), so a Unicode host here could never match them.
func asciiHost(host string) error {
	if strings.ContainsFunc(host, func(r rune) bool { return r >= 0x80 }) {
		return fmt.Errorf("the host %q is not ASCII; give its ASCII (xn--) form, which is what browsers and MCP clients send", host)
	}
	return nil
}

func isLoopback(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
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

// IsHelp reports whether err asks for usage.
func IsHelp(err error) bool { return errors.Is(err, errHelp) }

// Usage writes the generated settings reference.
func Usage() string {
	var b strings.Builder
	b.WriteString("Usage: byward [flags] [-- stdio-upstream-command [args...]]\n\nSettings (flag / env, default):\n")
	for _, s := range registry {
		flagName := "--" + s.Name
		env := s.Env()
		if s.Secret {
			flagName += "-file"
			env += "_FILE"
		}
		fmt.Fprintf(&b, "  %s / %s", flagName, env)
		if s.Default != "" {
			fmt.Fprintf(&b, " (default %s)", s.Default)
		}
		fmt.Fprintf(&b, "\n      %s\n", s.Help)
	}
	b.WriteString("\nActions:\n  --version [--json]\n  --print-config\n")
	return b.String()
}

// Reference renders the settings reference in Markdown; docs/reference/settings.md is generated
// from it and a test keeps the file current.
func reference() string {
	var b strings.Builder
	b.WriteString("# Settings reference\n\nGenerated from the settings registry (`internal/config`); do not edit by hand.\n")
	b.WriteString("Run `BYWARD_UPDATE_REFERENCE=1 go test ./internal/config/` after changing a setting.\n\n")
	b.WriteString("Precedence: flag > environment > default. Secrets are read only from files.\n\n")
	b.WriteString("| Flag | Environment | Default | Description |\n|---|---|---|---|\n")
	for _, s := range registry {
		flagName, env := "--"+s.Name, s.Env()
		if s.Secret {
			flagName += "-file"
			env += "_FILE"
		}
		def := s.Default
		if def == "" {
			def = "—"
		}
		fmt.Fprintf(&b, "| `%s` | `%s` | %s | %s |\n", flagName, env, def, s.Help)
	}
	b.WriteString("\nActions: `--version [--json]`, `--print-config`, `--help`.\n")
	b.WriteString("Commands (`check --offline`, `doctor`, `init entra`): [commands reference](commands.md).\n\n")
	b.WriteString("Exit codes: 0 success, 1 runtime error, 2 configuration error; `doctor` adds 4, 8 and 12.\n")
	return b.String()
}
