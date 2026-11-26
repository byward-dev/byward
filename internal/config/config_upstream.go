package config

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"golang.org/x/net/http/httpguts"
)

// upstream reads the upstream: an HTTP URL or a stdio command, exactly one of them. dashes says the
// command takes a stdio upstream command after --, so the URL's error also names a command after --.
func (c *Config) upstream(v *Values, dashes bool) []error {
	urlName, commandName := v.NameAsGiven("upstream-url"), v.CommandNameAsGiven()
	raw := parseText(v.value("upstream-command"))
	var errs []error
	if v.httpUpstream() || v.stdioUpstream() { // with none or both, the "required" or "both set" error says enough
		errs = offModeSettings(v)
	}
	if raw == "" {
		if v.httpUpstream() { // the HTTP upstream's own settings, each reported even beside a malformed URL
			d, err := parseHeaderTimeout(v.value("upstream-header-timeout"))
			if err != nil {
				errs = append(errs, err)
			}
			c.UpstreamHeaderTimeout = d
			strip, stripErrs := parseStripHeaders(v.value("upstream-strip-headers"))
			c.UpstreamStripHeaders = strip
			errs = append(errs, stripErrs...)
		}
		u, err := parseUpstreamURL(v.value("upstream-url"))
		switch {
		case err != nil && dashes:
			return append(errs, errorf("%s (or %s, or a command after --)", err.Error(), commandName))
		case err != nil:
			return append(errs, errorf("%s (or %s)", err.Error(), commandName))
		}
		c.UpstreamURL = u
		return errs
	}
	if !v.empty("upstream-url") { // no mode chosen, so neither mode's settings are read
		return []error{errorf("%s and %s are both set: an upstream is either HTTP or stdio", urlName, commandName)}
	}
	command, err := parseUpstreamCommand(v.value("upstream-command"), v.command)
	if err != nil {
		errs = append(errs, err)
	}
	c.UpstreamCommand = command
	env, err := parseEnvLines(parseText(v.value("upstream-env")))
	if err != nil {
		errs = append(errs, errorf("%s: want KEY=VALUE lines, each key once; got %v", v.NameAsGiven("upstream-env"), err)) // as given: the file setting, or inline under --dev
	}
	c.UpstreamEnv = env
	limits := []struct {
		name string
		dst  *int
	}{{"stdio-max-processes", &c.StdioMaxProcesses}, {"stdio-max-processes-per-user", &c.StdioMaxPerUser}}
	for _, l := range limits {
		n, err := parseWholeNumber(v.value(l.name), 1, 10000)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		*l.dst = n
	}
	d, err := parseStreamIdleTimeout(v.value("stdio-stream-idle-timeout"))
	if err != nil {
		errs = append(errs, err)
	}
	c.StdioStreamIdleTimeout = d
	if c.StdioMaxPerUser > c.StdioMaxProcesses && c.StdioMaxProcesses > 0 {
		errs = append(errs, errorf("%s (%d) must not exceed %s (%d)", v.NameAsGiven("stdio-max-processes-per-user"), c.StdioMaxPerUser,
			v.NameAsGiven("stdio-max-processes"), c.StdioMaxProcesses))
	}
	return errs
}

// parseUpstreamCommand reads BYWARD_UPSTREAM_COMMAND: a JSON array of strings whose first element is
// the program, or the command given after -- (argv), which resolve holds in the value as such an
// array too. A refused one is never shown: a command line can carry a token as an argument.
func parseUpstreamCommand(val Value, argv []string) ([]string, error) {
	var command []string
	if argv != nil {
		command = append([]string(nil), argv...)
	} else if err := json.Unmarshal([]byte(val.Given.raw()), &command); err != nil {
		command = nil
	}
	switch {
	case argv != nil && (len(command) == 0 || command[0] == ""): // given after --, so named in its own terms: no JSON was typed
		return nil, errorf("the command after --: want the program first; got an empty program")
	case len(command) == 0 || command[0] == "":
		return nil, refusedForm(val, whole, val.Given.raw(), `a JSON array of strings whose first element is the program, such as ["/usr/local/bin/server","--flag"]`, "it is not one")
	}
	return command, nil
}

// stdioUpstream and httpUpstream say which upstream mode the selectors choose: exactly one of
// upstream-command and upstream-url, as given, even when its value does not parse. With none or
// both, no mode is chosen. Every check in config that depends on the chosen mode reads these.
func (v *Values) stdioUpstream() bool {
	return v.selects("upstream-command") && !v.selects("upstream-url")
}

func (v *Values) httpUpstream() bool {
	return v.selects("upstream-url") && !v.selects("upstream-command")
}

// selects reports whether the upstream selector called name is given a value, read as given: empty
// reads through refusedOffMode, which reads the mode from here.
func (v *Values) selects(name string) bool { return !v.byKey[name].Given.empty() }

// CommandNameAsGiven names the stdio upstream's command as the operator gave it:
// "the command after --", which resolve keeps as if given by flag, or the flag or variable that gave
// it, or the variable to set when it is not given or there are no Values (NameAsGiven).
func (v *Values) CommandNameAsGiven() string {
	if v != nil && v.command != nil {
		return "the command after --"
	}
	return v.NameAsGiven("upstream-command")
}

// refusedOffMode reports whether the named setting is given for the upstream mode that is off, and so
// refused (offModeSettings): a stdio upstream's settings with an HTTP upstream; an HTTP upstream's,
// and those with a StdioHint, with a stdio one. A setting left at its default never is; one given is,
// a flag set to nothing included, as every check for a family that is off does (#596). A variable
// set to nothing is unset already (resolve), and a file named for a secret is given, even when it is
// not read. With no upstream, or both, there is no mode, so none is. A refused setting is not read
// (resolve) or parsed (value, empty, given, emptySecretFile); a check that reads its Source itself,
// through byKey or Effective, must skip it too, as checkNoAuth and inlineSecrets do.
func (v *Values) refusedOffMode(name string) bool {
	val := v.byKey[name]
	if val.Source == SourceDefault {
		return false
	}
	s := val.Setting
	switch {
	case v.httpUpstream():
		return s.Group == GroupStdioUpstream
	case v.stdioUpstream():
		return s.Group == GroupHTTPUpstream || s.StdioHint != ""
	}
	return false
}

// offModeSettings refuses each setting given for the upstream mode that is off (refusedOffMode),
// named as the operator gave it. Beside a stdio upstream, a setting with a StdioHint gets that text;
// every other refusal says which mode the setting is for, as httpOnlyRefusal does. The other mode's
// selector reaches here only as a flag set to nothing, as with a value there is no mode.
func offModeSettings(v *Values) []error {
	// The other mode's selector, not given here, is named as advice: the variable to set (EnvToSet), as
	// #631's offmode_test pins it.
	inUse, offMode, offSelector := "HTTP", "a stdio upstream", lookup("upstream-command").EnvToSet()
	if v.stdioUpstream() {
		inUse, offMode, offSelector = "stdio", "an HTTP upstream", lookup("upstream-url").EnvToSet()
	}
	var errs []error
	for _, val := range v.Effective() {
		s := val.Setting
		switch {
		case !v.refusedOffMode(s.Name):
		case s.StdioHint != "": // refused, so beside a stdio upstream: a stdio upstream's setting takes no hint (checkStdioHints)
			errs = append(errs, errorf(s.StdioHint, val.nameAsGiven()))
		default:
			errs = append(errs, errorf("%s is set, but the upstream is %s: it applies only to %s (%s); remove it", val.nameAsGiven(), inUse, offMode, offSelector))
		}
	}
	return errs
}

// minStreamIdleTimeout is the shortest stdio-stream-idle-timeout other than 0 (off): a stream quiet
// for less is not idle.
const minStreamIdleTimeout = time.Minute

func parseStreamIdleTimeout(val Value) (time.Duration, error) {
	return parseDuration(val, "a duration of at least 1m such as 10m, or 0 to keep quiet streams",
		func(d time.Duration) bool { return d == 0 || d >= minStreamIdleTimeout })
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
			return nil, fmt.Errorf("line %d: it is not KEY=VALUE", i+1)
		}
		if _, dup := env[k]; dup {
			return nil, fmt.Errorf("line %d: its key is set on an earlier line too", i+1)
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

func parseHeaderTimeout(val Value) (time.Duration, error) {
	return parseDuration(val, "a duration from 1s to 1h, such as 5m",
		func(d time.Duration) bool { return d >= minHeaderTimeout && d <= maxHeaderTimeout })
}

// maxUpstreamCredential bounds the credential: it travels in a header on every request.
const maxUpstreamCredential = 4 << 10

// upstreamCredential reads the operator's upstream credential (ADR-0016 §7): only for an HTTP
// upstream (beside a stdio one, its StdioHint refuses it), a header value without control
// characters, in a header that is not the assertion's. The credential's errors name it as the
// operator gave it (Value.nameAsGiven), never its value.
func (c *Config) upstreamCredential(v *Values) []error {
	credentialName, credentialHeaderName := v.NameAsGiven("upstream-credential"), v.NameAsGiven("upstream-credential-header")
	val, header := v.byKey["upstream-credential"], v.byKey["upstream-credential-header"]
	if !v.httpUpstream() { // with stdio both are off-mode settings; with no upstream or both, upstream's error says enough
		return nil
	}
	if val.Source == SourceDefault {
		if header.Source != SourceDefault {
			return []error{errorf("%s is set, but there is no credential: set %s too, or remove it", credentialHeaderName, credentialName)}
		}
		return nil
	}
	var errs []error
	emptyFile := v.emptySecretFile("upstream-credential")
	// In the one format, named as the operator gave it: the length only, never the credential.
	want := fmt.Sprintf("one header value of at most %d bytes on one line, without control characters or white space at either end", maxUpstreamCredential)
	refused := func(cred, reason string) error { return refusedForm(val, whole, cred, want, reason) } // an inline value, accepted under --dev, is named by its variable
	switch cred := parseText(val); {
	case emptyFile != nil:
		errs = append(errs, emptyFile)
	case len(cred) > maxUpstreamCredential:
		errs = append(errs, refused(cred, fmt.Sprintf("it is %d bytes long", len(cred))))
	case strings.ContainsFunc(cred, func(r rune) bool { return r != '\t' && (r < 0x20 || r == 0x7f) }):
		errs = append(errs, refused(cred, "it has a control character or a line break"))
	case cred != strings.TrimSpace(cred):
		errs = append(errs, refused(cred, "it starts or ends with white space"))
	default:
		c.UpstreamCredential = cred
	}
	h, err := parseHeaderName(v.value("upstream-credential-header"))
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

// parseStripHeaders reads BYWARD_UPSTREAM_STRIP_HEADERS: header names, canonical with _ read as -, the
// way the relay compares them.
func parseStripHeaders(val Value) ([]string, []error) {
	const want = "exact header names, such as X-Argocd-Base-Url"
	var out []string
	var errs []error
	list, at, err := parseEntries(val)
	if err != nil {
		return nil, []error{err}
	}
	for i, n := range list {
		h := CanonicalHeader(n)
		switch {
		case strings.ContainsRune(n, '*'):
			errs = append(errs, refusedForm(val, at(i), n, want, "it has a *: list each header of a family by name"))
		case strings.Contains(n, ":"):
			errs = append(errs, refusedForm(val, at(i), n, want, headerLineReason))
		case !httpguts.ValidHeaderFieldName(n):
			errs = append(errs, refusedForm(val, at(i), n, want, "it is not a header name"))
		case mcpHeaders[h]:
			errs = append(errs, refusedMeaning(val, at(i), h, want, "MCP needs it at the upstream; remove it from the list"))
		case strings.HasPrefix(h, MCPParamPrefix):
			errs = append(errs, refusedMeaning(val, at(i), "a header starting "+MCPParamPrefix, want, "MCP needs it at the upstream; remove it from the list"))
		case h == "Traceparent" || h == "Tracestate":
			errs = append(errs, refusedMeaning(val, at(i), h, want, "with tracing on, the proxy sets it from the inbound trace context; remove it from the list"))
		default:
			out = append(out, h)
		}
	}
	return out, errs
}
