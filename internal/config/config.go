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
	{Name: "dev", Bool: true, Default: "false", Help: "development mode: enables the relaxations it logs at startup"},
}

// Config is the validated configuration.
type Config struct {
	PublicURL             *url.URL
	UpstreamURL           *url.URL
	Listen                string
	AllowedOrigins        []string
	AllowedHosts          []string
	Scope                 string
	ResourceName          string
	ResourceDocumentation string
	LogFormat             string
	Dev                   bool

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
	c, err := validate(vals)
	return c, act, err
}

func validate(v *Values) (*Config, error) {
	c := &Config{Values: v, Listen: v.get("listen"), Scope: v.get("scope"),
		ResourceName: v.get("resource-name"), ResourceDocumentation: v.get("resource-documentation"),
		LogFormat: v.get("log-format")}
	var errs []error
	dev, err := strconv.ParseBool(v.get("dev"))
	if err != nil {
		errs = append(errs, errorf("%s: want true or false, got %q", Setting{Name: "dev"}.Env(), v.get("dev")))
	}
	c.Dev = dev

	if secrets := v.inlineSecrets(); len(secrets) > 0 {
		if !c.Dev {
			errs = append(errs, errorf("%s: secrets must come from a file (%s_FILE)", strings.Join(secrets, ", "), secrets[0]))
		} else {
			c.Relaxations = append(c.Relaxations, "inline secrets accepted: "+strings.Join(secrets, ", "))
		}
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
			case !c.Dev:
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
	if len(errs) > 0 {
		msgs := make([]string, 0, len(errs))
		for _, e := range errs {
			msgs = append(msgs, e.Error())
		}
		return nil, &configError{msg: strings.Join(msgs, "; ")}
	}
	return c, nil
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
