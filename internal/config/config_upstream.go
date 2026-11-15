package config

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"golang.org/x/net/http/httpguts"
)

// upstream reads the upstream: an HTTP URL or a stdio command, exactly one of them.
func (c *Config) upstream(v *Values) []error {
	urlEnv, cmdEnv, envEnv := Setting{Name: "upstream-url"}.Env(), Setting{Name: "upstream-command"}.Env(), Setting{Name: "upstream-env"}.Env()+"_FILE"
	raw := v.get("upstream-command")
	errs := offModeSettings(v, raw != "")
	if raw == "" {
		u, err := parseURL("upstream-url", v.get("upstream-url"))
		if err != nil {
			return append(errs, errorf("%s (or %s, or a command after --)", err.Error(), cmdEnv))
		}
		c.UpstreamURL = u
		strip, stripErrs := stripHeaders(v.get("upstream-strip-headers"))
		c.UpstreamStripHeaders = strip
		return append(errs, stripErrs...)
	}
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
	d, err := parseStreamIdleTimeout(v.get("stdio-stream-idle-timeout"))
	if err != nil {
		errs = append(errs, err)
	}
	c.StdioStreamIdleTimeout = d
	if c.StdioMaxPerUser > c.StdioMaxProcesses && c.StdioMaxProcesses > 0 {
		errs = append(errs, errorf("%s (%d) must not exceed %s (%d)", Setting{Name: "stdio-max-processes-per-user"}.Env(), c.StdioMaxPerUser,
			Setting{Name: "stdio-max-processes"}.Env(), c.StdioMaxProcesses))
	}
	return errs
}

// offModeSettings refuses each setting given for the upstream mode that is off: a stdio upstream's
// settings with an HTTP upstream, an HTTP upstream's with a stdio one. A setting left at its default
// is never refused. The registry's groups say which mode a setting is for. The selectors
// (upstream-url, upstream-command) keep their own "both set" error, and upstream-credential its own
// hint (upstreamCredential).
func offModeSettings(v *Values, stdio bool) []error {
	off, mode, other, selector := GroupStdioUpstream, "HTTP", "a stdio upstream", Setting{Name: "upstream-command"}.Env()
	if stdio {
		off, mode, other, selector = GroupHTTPUpstream, "stdio", "an HTTP upstream", Setting{Name: "upstream-url"}.Env()
	}
	var errs []error
	for _, val := range v.Effective() {
		s := val.Setting
		if s.Group != off || val.Source == SourceDefault || s.Name == "upstream-url" || s.Name == "upstream-command" || s.Name == "upstream-credential" {
			continue
		}
		errs = append(errs, errorf("%s is set, but the upstream is %s: it applies only to %s (%s); remove it", spelled(val), mode, other, selector))
	}
	return errs
}

// spelled names a setting as the operator gave it: the flag, the file setting or the environment
// variable.
func spelled(val Value) string {
	switch {
	case val.From != "":
		return val.From
	case val.Source == SourceFlag:
		return "--" + val.Setting.Name
	}
	return val.Setting.Env()
}

// minStreamIdleTimeout is the shortest stdio-stream-idle-timeout other than 0 (off): a stream quiet
// for less is not idle.
const minStreamIdleTimeout = time.Minute

func parseStreamIdleTimeout(raw string) (time.Duration, error) {
	env := Setting{Name: "stdio-stream-idle-timeout"}.Env()
	d, err := time.ParseDuration(raw)
	switch {
	case raw == "0":
		return 0, nil
	case err != nil:
		return 0, errorf("%s: want a duration such as 10m, or 0 to keep quiet streams, got %q", env, raw)
	case d != 0 && d < minStreamIdleTimeout: // negative too
		return 0, errorf("%s: want 0 or at least 1m, got %s", env, d)
	}
	return d, nil
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

// maxUpstreamCredential bounds the credential: it travels in a header on every request.
const maxUpstreamCredential = 4 << 10

// upstreamCredential reads the operator's upstream credential (ADR-0016 §7): only for an HTTP
// upstream, a header value without control characters, in a header that is not the assertion's.
// Errors never contain the value.
func (c *Config) upstreamCredential(v *Values) []error {
	fileEnv, hEnv := Setting{Name: "upstream-credential"}.Env()+"_FILE", Setting{Name: "upstream-credential-header"}.Env()
	val, header := v.byKey["upstream-credential"], v.byKey["upstream-credential-header"]
	if val.Source == SourceDefault {
		if header.Source != SourceDefault && c.UpstreamCommand == nil { // with stdio: offModeSettings refuses it
			return []error{errorf("%s is set, but there is no credential: set %s too, or remove it", hEnv, fileEnv)}
		}
		return nil
	}
	if c.UpstreamCommand != nil {
		return []error{errorf("%s is for an HTTP upstream; give a stdio upstream its credential with BYWARD_UPSTREAM_ENV_FILE", fileEnv)}
	}
	var errs []error
	switch cred := val.Raw; {
	case cred == "":
		errs = append(errs, errorf("%s: the file is empty", val.From))
	case len(cred) > maxUpstreamCredential:
		errs = append(errs, errorf("%s: the credential is longer than %d bytes", val.From, maxUpstreamCredential))
	case strings.ContainsFunc(cred, func(r rune) bool { return r != '\t' && (r < 0x20 || r == 0x7f) }):
		errs = append(errs, errorf("%s: the credential must be one header value on one line, without control characters", val.From))
	case cred != strings.TrimSpace(cred):
		errs = append(errs, errorf("%s: the credential starts or ends with white space", val.From))
	default:
		c.UpstreamCredential = cred
	}
	h, err := upstreamHeader(v, "upstream-credential-header", "X-Api-Key")
	if err != nil {
		return append(errs, err)
	}
	c.UpstreamCredentialHeader = h
	return errs
}

// mcpHeaders are the request headers MCP and its transport need at the upstream, so the operator
// may not strip them: MCPRequestHeaders and the transport's own. The 2026-07-28 revision also
// requires every Mcp-Param-* header to be forwarded (MCPParamPrefix).
var mcpHeaders = withMCPHeaders(map[string]bool{"Accept": true, "Content-Type": true, "Content-Length": true, "Transfer-Encoding": true, "Host": true})

// stripHeaders reads BYWARD_UPSTREAM_STRIP_HEADERS: header names, canonical with _ read as -, the
// way the relay compares them.
func stripHeaders(raw string) ([]string, []error) {
	env := Setting{Name: "upstream-strip-headers"}.Env()
	var out []string
	var errs []error
	for _, n := range splitList(raw) {
		h := CanonicalHeader(n)
		switch {
		case strings.ContainsRune(n, '*'):
			errs = append(errs, errorf("%s: %q: exact names only; list each header of a family by name", env, n))
		case !httpguts.ValidHeaderFieldName(n):
			errs = append(errs, errorf("%s: %q is not a header name; list exact names, such as X-Argocd-Base-Url", env, n))
		case mcpHeaders[h] || strings.HasPrefix(h, MCPParamPrefix):
			errs = append(errs, errorf("%s: %s is a header MCP needs at the upstream; remove it from the list", env, h))
		case h == "Traceparent" || h == "Tracestate":
			errs = append(errs, errorf("%s: %s cannot be stripped: with tracing on, the proxy sets it from the inbound trace context; remove it from the list", env, h))
		default:
			out = append(out, h)
		}
	}
	return out, errs
}
