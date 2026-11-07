package config

import (
	"fmt"
	"strings"
)

// Quickstart is the minimal Entra configuration (ADR-0020 §8): the settings an operator must give,
// plus the optional secret expiry so warnings work from the first start.
type Quickstart struct {
	PublicURL, UpstreamURL, Tenant, ClientID, SecretFile, SecretExpiresAt string
	// CertificateFile, when set, is the certificate credential in place of the secret (ADR-0012 §5).
	CertificateFile string
}

// quickstartRequired are the settings the quickstart needs; ADR-0020 §8 caps them at five.
var quickstartRequired = []string{"public-url", "upstream-url", "entra-tenant", "entra-client-id", "entra-client-secret"}

// EnvFile renders q as an env file, one NAME=value per line, values as given. An empty value is
// written with a comment saying what to put there.
func (q Quickstart) EnvFile() string {
	values := map[string]string{"public-url": q.PublicURL, "upstream-url": q.UpstreamURL, "entra-tenant": q.Tenant,
		"entra-client-id": q.ClientID, "entra-client-secret": q.SecretFile}
	var b strings.Builder
	for _, name := range quickstartRequired {
		if name == "entra-client-secret" && q.CertificateFile != "" {
			name = "entra-client-certificate"
			values[name] = q.CertificateFile
		}
		s := lookup(name)
		env := s.Env()
		if s.Secret {
			env += "_FILE"
		}
		if values[name] == "" {
			fmt.Fprintf(&b, "# %s: %s\n", env, s.Help)
		}
		fmt.Fprintf(&b, "%s=%s\n", env, values[name])
	}
	if q.SecretExpiresAt != "" {
		fmt.Fprintf(&b, "%s=%s\n", Setting{Name: "entra-client-secret-expires-at"}.Env(), q.SecretExpiresAt)
	}
	return b.String()
}

// lookup is the registry entry of name; it panics on a name the registry lacks, which tests catch.
func lookup(name string) Setting {
	for _, s := range registry {
		if s.Name == name {
			return s
		}
	}
	panic("config: no setting " + name)
}
