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
	EnvSubject = "BYWARD_SUBJECT"
	EnvIssuer  = "BYWARD_ISSUER"
	// EnvPrincipalType is user, or client for an app-only caller (ADR-0022 §5).
	EnvPrincipalType = "BYWARD_PRINCIPAL_TYPE"
	reservedEnv      = "BYWARD_"
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

// Identity is the principal an upstream process acts for. Subject is the opaque user key;
// PrincipalType is user or client (an app-only caller), and empty only without authentication. It
// carries no email: a stdio upstream gets none (ADR-0016 §6, as amended for #330).
type Identity struct {
	Subject       string
	Issuer        string
	PrincipalType string
	// Grant and Client are the grant and MCP client of a request, for the downstream token of the
	// process that serves it (ADR-0017); they never reach the process's environment.
	Grant, Client string
}

// user identifies the principal across IdPs and kinds: a subject is unique only within its issuer,
// and a user never shares a process with an app.
func (id Identity) user() string { return id.PrincipalType + "\x00" + id.Issuer + "\x00" + id.Subject }

func (id Identity) validate() error {
	if id.Subject == "" || id.Issuer == "" {
		return errors.New("stdio: identity needs a subject and an issuer")
	}
	for _, v := range []string{id.Subject, id.Issuer, id.PrincipalType, id.Grant, id.Client} {
		if strings.ContainsRune(v, 0) {
			return errors.New("stdio: identity contains a NUL byte")
		}
	}
	return nil
}

// command is a validated upstream command line.
type command struct {
	name string            // argv[0] as configured
	path string            // resolved executable
	args []string          // after argv[0]
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
	c := command{name: argv[0], args: argv[1:], env: operatorEnv}
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

// argv returns the full argument vector, argv[0] included, with placeholders replaced.
func (c command) argv(sessionDir string) []string {
	out := []string{c.name}
	for _, a := range c.args {
		out = append(out, strings.ReplaceAll(a, SessionDirPlaceholder, sessionDir))
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
	if id.PrincipalType != "" {
		m[EnvPrincipalType] = id.PrincipalType
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
	return fmt.Errorf("%w: %q (PATH %q). The byward image has no node or python runtime: "+
		"build your own image FROM the runtime and add the proxy with "+
		"COPY --from=ghcr.io/byward-dev/byward:<version> /usr/local/bin/byward /usr/local/bin/byward",
		ErrCommandNotFound, name, path)
}
