package config

import (
	"errors"
	"flag"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
)

// registry is every setting the proxy reads, in the order the effective configuration is printed.
var registry = []Setting{
	{Name: "public-url", Help: "public URL of the MCP endpoint exactly as users enter it, e.g. https://mcp.example.com/mcp"},
	{Name: "upstream-url", Help: "URL of the HTTP upstream MCP server"},
	{Name: "listen", Default: "127.0.0.1:8080", Help: "address to listen on; public addresses only when configured"},
	{Name: "allowed-origins", Help: "comma-separated Origin values allowed on the MCP endpoint (scheme://host[:port])"},
	{Name: "allowed-hosts", Help: "comma-separated extra Host values accepted besides the public URL's host"},
	{Name: "scope", Default: "mcp", Help: "the scope advertised in protected resource metadata and 401 challenges"},
	{Name: "resource-name", Help: "human-readable resource name in protected resource metadata"},
	{Name: "resource-documentation", Help: "documentation URL in protected resource metadata"},
	{Name: "log-format", Default: "json", Help: "log format: json or text"},
	{Name: "internal-listen", Default: "127.0.0.1:9090", Help: "address of the internal listener for /metrics, /livez and /readyz (ADR-0018 §10); empty turns it off"},
	{Name: "entra-tenant", Auth: true, Help: "Entra tenant ID (a GUID) of the IdP app"},
	{Name: "entra-client-id", Auth: true, Help: "application (client) ID of the IdP app registration"},
	{Name: "entra-client-secret", Auth: true, Secret: true, Help: "client secret of the IdP app"},
	{Name: "keys-dir", Auth: true, Help: "directory of sealing keys; each file is one key, its name the key ID (docs/how-to/sealing-keys.md)"},
	{Name: "static-clients-file", Auth: true, Help: "JSON file of pre-registered MCP clients (docs/reference/static-clients.md)"},
	{Name: "insecure-no-auth", Bool: true, Default: "false", Help: "no authentication at all, for trying the proxy out and for tests; loopback only (ADR-0027)"},
	{Name: "dev", Bool: true, Default: "false", Help: "development mode: enables the relaxations it logs at startup"},
}

// Config is the validated configuration.
type Config struct {
	PublicURL             *url.URL
	UpstreamURL           *url.URL
	Listen                string
	InternalListen        string // "" when the internal listener is off
	AllowedOrigins        []string
	AllowedHosts          []string
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
	KeysDir           string
	StaticClientsFile string
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

	if relaxed, err := checkInlineSecrets(v, c.Dev); err != nil {
		errs = append(errs, err)
	} else if relaxed != "" {
		c.Relaxations = append(c.Relaxations, relaxed)
	}

	c.PublicURL, err = parseURL("public-url", v.get("public-url"))
	if err != nil {
		errs = append(errs, err)
	} else {
		if c.PublicURL.Path == "" || strings.HasSuffix(c.PublicURL.Path, "/") {
			errs = append(errs, errorf("MCP_AUTHPROXY_PUBLIC_URL: give the MCP endpoint path without a trailing slash, e.g. https://%s/mcp", c.PublicURL.Host))
		}
		if c.PublicURL.RawQuery != "" || c.PublicURL.Fragment != "" {
			errs = append(errs, errorf("MCP_AUTHPROXY_PUBLIC_URL: must not have a query or fragment"))
		}
		if c.PublicURL.Scheme == "http" {
			switch {
			case !isLoopback(c.PublicURL.Hostname()):
				errs = append(errs, errorf("MCP_AUTHPROXY_PUBLIC_URL: must use https (http is allowed only for loopback hosts with --dev)"))
			case !c.Dev && !c.NoAuth:
				errs = append(errs, errorf("MCP_AUTHPROXY_PUBLIC_URL: http on loopback needs --dev"))
			default:
				c.Relaxations = append(c.Relaxations, "http public URL on loopback")
			}
		}
	}
	c.UpstreamURL, err = parseURL("upstream-url", v.get("upstream-url"))
	if err != nil {
		errs = append(errs, err)
	}

	if _, _, err := net.SplitHostPort(c.Listen); err != nil {
		errs = append(errs, errorf("MCP_AUTHPROXY_LISTEN: want host:port, got %q", c.Listen))
	}
	if c.InternalListen != "" {
		if _, _, err := net.SplitHostPort(c.InternalListen); err != nil {
			errs = append(errs, errorf("MCP_AUTHPROXY_INTERNAL_LISTEN: want host:port or empty, got %q", c.InternalListen))
		} else if c.InternalListen == c.Listen && !strings.HasSuffix(c.Listen, ":0") {
			errs = append(errs, errorf("MCP_AUTHPROXY_INTERNAL_LISTEN: must differ from MCP_AUTHPROXY_LISTEN; metrics and probes never share the public listener"))
		}
	}
	for _, o := range splitList(v.get("allowed-origins")) {
		n, err := normalizeOrigin(o)
		if err != nil {
			errs = append(errs, errorf("MCP_AUTHPROXY_ALLOWED_ORIGINS: %v", err))
			continue
		}
		c.AllowedOrigins = append(c.AllowedOrigins, n)
	}
	for _, h := range splitList(v.get("allowed-hosts")) {
		if strings.ContainsAny(h, "/ ") {
			errs = append(errs, errorf("MCP_AUTHPROXY_ALLOWED_HOSTS: %q is not a host[:port]", h))
			continue
		}
		c.AllowedHosts = append(c.AllowedHosts, strings.ToLower(h))
	}
	if c.LogFormat != "json" && c.LogFormat != "text" {
		errs = append(errs, errorf("MCP_AUTHPROXY_LOG_FORMAT: want json or text, got %q", c.LogFormat))
	}
	if c.Scope == "" || strings.ContainsAny(c.Scope, " \"\\") {
		errs = append(errs, errorf("MCP_AUTHPROXY_SCOPE: want one scope token, got %q", c.Scope))
	}
	if d := c.ResourceDocumentation; d != "" {
		if _, err := parseURL("resource-documentation", d); err != nil {
			errs = append(errs, err)
		}
	}
	if c.NoAuth && c.PublicURL != nil {
		errs = append(errs, checkNoAuth(c, v)...)
	}
	if !c.NoAuth {
		c.EntraTenant, c.EntraClientID, c.EntraClientSecret = v.get("entra-tenant"), v.get("entra-client-id"), v.get("entra-client-secret")
		c.KeysDir, c.StaticClientsFile = v.get("keys-dir"), v.get("static-clients-file")
		for _, s := range []string{"entra-tenant", "entra-client-id", "entra-client-secret", "keys-dir", "static-clients-file"} {
			if v.get(s) == "" {
				env := Setting{Name: s}.Env()
				if s == "entra-client-secret" {
					env += "_FILE"
				}
				errs = append(errs, errorf("%s is required (or set MCP_AUTHPROXY_INSECURE_NO_AUTH to try the proxy without sign-in)", env))
			}
		}
		if t := c.EntraTenant; t != "" && !isGUID(t) {
			errs = append(errs, errorf("MCP_AUTHPROXY_ENTRA_TENANT: want the tenant ID, a GUID such as 00000000-0000-0000-0000-000000000000, got %q", t))
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
	const env = "MCP_AUTHPROXY_INSECURE_NO_AUTH"
	var errs []error
	if !isLoopback(c.PublicURL.Hostname()) {
		errs = append(errs, errorf("%s: MCP_AUTHPROXY_PUBLIC_URL must be a loopback URL, e.g. http://localhost:8080/mcp", env))
	}
	host, port, err := net.SplitHostPort(c.Listen)
	switch {
	case err != nil:
		errs = append(errs, errorf("%s: MCP_AUTHPROXY_LISTEN must be a loopback host:port such as 127.0.0.1:8080", env))
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
		errs = append(errs, errorf("%s: MCP_AUTHPROXY_LISTEN must be a loopback address such as 127.0.0.1:8080 (non-loopback only inside a container with its own network, not --network host)", env))
	}
	for _, h := range c.AllowedHosts {
		if hn, _, err := net.SplitHostPort(h); !isLoopback(strings.Trim(h, "[]")) && (err != nil || !isLoopback(hn)) {
			errs = append(errs, errorf("%s: MCP_AUTHPROXY_ALLOWED_HOSTS may only list loopback hosts, got %q", env, h))
		}
	}
	for _, o := range c.AllowedOrigins {
		if u, err := url.Parse(o); err != nil || !isLoopback(u.Hostname()) {
			errs = append(errs, errorf("%s: MCP_AUTHPROXY_ALLOWED_ORIGINS may only list loopback origins, got %q", env, o))
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
	return strings.ToLower(u.Scheme + "://" + u.Host), nil
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
	b.WriteString("Usage: mcp-authproxy [flags]\n\nSettings (flag / env, default):\n")
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
	b.WriteString("Run `MCP_AUTHPROXY_UPDATE_REFERENCE=1 go test ./internal/config/` after changing a setting.\n\n")
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
	b.WriteString("\nActions: `--version [--json]`, `--print-config`, `--help`.\n\n")
	b.WriteString("Exit codes: 0 success, 1 runtime error, 2 configuration error.\n")
	return b.String()
}
