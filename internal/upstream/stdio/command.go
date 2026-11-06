//go:build linux || darwin

package stdio

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// SessionDirPlaceholder in an argument or an operator env value is replaced by a temporary
// directory created for that upstream process and removed when it exits (ADR-0003 §6).
const SessionDirPlaceholder = "{session_dir}"

// Identity env names set on every upstream process (ADR-0016 §6). Operator env must not use the
// prefix, so an upstream can trust that these come from the proxy.
const (
	EnvSubject  = "MCP_AUTHPROXY_SUBJECT"
	EnvIssuer   = "MCP_AUTHPROXY_ISSUER"
	EnvEmail    = "MCP_AUTHPROXY_EMAIL"
	reservedEnv = "MCP_AUTHPROXY_"
)

// inheritedEnv is the allowlist of the proxy's own environment passed to upstream processes. The
// rest of the proxy's environment (its configuration, secrets, cloud credentials) never reaches
// them (ADR-0016 §6).
var inheritedEnv = []string{
	"PATH", "HOME", "USER", "LOGNAME", "TMPDIR", "TZ",
	"LANG", "LC_ALL", "LC_CTYPE", "LC_MESSAGES",
}

// ErrCommandNotFound is returned when the configured command is not an executable file.
var ErrCommandNotFound = errors.New("stdio upstream command not found")

// Identity is the user an upstream process acts for. Subject is the opaque user key; Email is
// set only when the operator opted in.
type Identity struct {
	Subject string
	Issuer  string
	Email   string
}

func (id Identity) validate() error {
	if id.Subject == "" || id.Issuer == "" {
		return errors.New("stdio: identity needs a subject and an issuer")
	}
	for _, v := range []string{id.Subject, id.Issuer, id.Email} {
		if strings.ContainsRune(v, 0) {
			return errors.New("stdio: identity contains a NUL byte")
		}
	}
	return nil
}

// command is a validated upstream command line.
type command struct {
	path string // resolved executable
	args []string
	env  map[string]string // operator env
}

func newCommand(argv []string, operatorEnv map[string]string, proxyEnv func(string) (string, bool)) (command, error) {
	if len(argv) == 0 || argv[0] == "" {
		return command{}, errors.New("stdio: no command configured")
	}
	for k, v := range operatorEnv {
		switch {
		case k == "" || strings.ContainsAny(k, "=\x00"):
			return command{}, fmt.Errorf("stdio: invalid env name %q", k)
		case strings.HasPrefix(strings.ToUpper(k), reservedEnv):
			return command{}, fmt.Errorf("stdio: env %s: the %s prefix is reserved for identity set by the proxy", k, reservedEnv)
		case strings.ContainsRune(v, 0):
			return command{}, fmt.Errorf("stdio: env %s contains a NUL byte", k)
		}
	}
	for _, a := range argv {
		if strings.ContainsRune(a, 0) {
			return command{}, errors.New("stdio: argument contains a NUL byte")
		}
	}
	c := command{args: argv[1:], env: operatorEnv}
	p, err := lookPath(argv[0], c.childPath(proxyEnv))
	if err != nil {
		return command{}, err
	}
	c.path = p
	return c, nil
}

// childPath is the PATH the upstream process will see; the command is resolved against it, not
// against the proxy's PATH.
func (c command) childPath(proxyEnv func(string) (string, bool)) string {
	if v, ok := c.env["PATH"]; ok {
		return v
	}
	v, _ := proxyEnv("PATH")
	return v
}

// usesSessionDir reports whether any argument or env value needs a session directory.
func (c command) usesSessionDir() bool {
	for _, a := range c.args {
		if strings.Contains(a, SessionDirPlaceholder) {
			return true
		}
	}
	for _, v := range c.env {
		if strings.Contains(v, SessionDirPlaceholder) {
			return true
		}
	}
	return false
}

// argv returns the arguments with placeholders replaced.
func (c command) argv(sessionDir string) []string {
	out := make([]string, len(c.args))
	for i, a := range c.args {
		out[i] = strings.ReplaceAll(a, SessionDirPlaceholder, sessionDir)
	}
	return out
}

// environ builds the upstream process environment: the inherited allowlist, then operator env,
// then identity. Later entries win; identity cannot be overridden.
func (c command) environ(proxyEnv func(string) (string, bool), id Identity, sessionDir string) []string {
	m := map[string]string{}
	for _, k := range inheritedEnv {
		if v, ok := proxyEnv(k); ok {
			m[k] = v
		}
	}
	for k, v := range c.env {
		m[k] = strings.ReplaceAll(v, SessionDirPlaceholder, sessionDir)
	}
	m[EnvSubject], m[EnvIssuer] = id.Subject, id.Issuer
	if id.Email != "" {
		m[EnvEmail] = id.Email
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	env := make([]string, len(keys))
	for i, k := range keys {
		env[i] = k + "=" + m[k]
	}
	return env
}

// lookPath resolves name like a shell would, but against the upstream's PATH and only through
// absolute PATH entries.
func lookPath(name, path string) (string, error) {
	if strings.Contains(name, "/") {
		if isExecutable(name) {
			return name, nil
		}
		return "", notFound(name, path)
	}
	for _, dir := range filepath.SplitList(path) {
		if !filepath.IsAbs(dir) {
			continue
		}
		if p := filepath.Join(dir, name); isExecutable(p) {
			return p, nil
		}
	}
	return "", notFound(name, path)
}

func isExecutable(p string) bool {
	fi, err := os.Stat(p)
	return err == nil && fi.Mode().IsRegular() && fi.Mode().Perm()&0o111 != 0
}

// notFound names the image pattern, because the usual cause is a runtime (node, python) that the
// proxy's image does not contain (ADR-0019 §3).
func notFound(name, path string) error {
	return fmt.Errorf("%w: %q (PATH %q). The mcp-authproxy image has no node or python runtime: "+
		"build your own image FROM the runtime and add the proxy with "+
		"COPY --from=ghcr.io/corker/mcp-authproxy:<version> /usr/local/bin/mcp-authproxy /usr/local/bin/mcp-authproxy",
		ErrCommandNotFound, name, path)
}
