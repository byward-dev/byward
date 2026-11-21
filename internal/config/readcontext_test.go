package config

import "slices"

// readContext is a configuration in which a setting is read: the arguments, the environment and the
// files Load is given.
type readContext struct {
	args  []string
	env   []string
	files readFileFunc
}

// readContextOf is a context where s is read: its group's base and, for some settings, what they need
// beside them (a companion setting, or the command not given after --), so a test of s reaches its
// parser and its checks. Its env is a fresh copy.
func readContextOf(s Setting) readContext {
	credFiles := func(p string) ([]byte, error) {
		if p == credFile {
			return []byte("k-123"), nil
		}
		return baseFiles(p)
	}
	switch s.Name {
	case "upstream-command": // given as itself, not after --
		return readContext{nil, stdioBase(), baseFiles}
	case "tls-cert-file":
		return readContext{nil, append(slices.Clone(base), "BYWARD_TLS_KEY_FILE=/run/tls/tls.key"), baseFiles}
	case "tls-key-file":
		return readContext{nil, append(slices.Clone(base), "BYWARD_TLS_CERT_FILE=/run/tls/tls.crt"), baseFiles}
	case "entra-federated-token-file":
		return readContext{nil, withoutSecret(), baseFiles}
	case "upstream-credential-header":
		return readContext{nil, append(slices.Clone(base), "BYWARD_UPSTREAM_CREDENTIAL_FILE="+credFile), credFiles}
	case "oidc-client-key-alg", "oidc-client-key-id":
		return readContext{nil, withAKey()(slices.Clone(oidcBase)), oidcFiles}
	}
	switch s.Group {
	case GroupStdioUpstream:
		return readContext{[]string{"--", "/bin/x"}, stdioBase(), baseFiles}
	case GroupOIDC:
		return readContext{nil, slices.Clone(oidcBase), oidcFiles}
	case GroupAppOnly:
		return readContext{nil, append(slices.Clone(base), "BYWARD_APP_TOKENS=entra", "BYWARD_APP_ROLES=r"), baseFiles}
	}
	return readContext{nil, slices.Clone(base), baseFiles}
}
