package config

import (
	"errors"
	"flag"
	"fmt"
	"strings"
	"unicode"
)

// Group is a section of the settings reference: what an operator sets the settings in it for.
type Group string

// The groups, in the order the settings reference lists them.
const (
	GroupEndpoint           Group = "Endpoint"
	GroupIdP                Group = "IdP"
	GroupEntra              Group = "IdP: Microsoft Entra ID"
	GroupOIDC               Group = "IdP: OpenID Connect"
	GroupGate               Group = "Access gate"
	GroupClientRegistration Group = "Client registration"
	GroupAppOnly            Group = "App-only callers"
	GroupHTTPUpstream       Group = "Upstream: HTTP"
	GroupStdioUpstream      Group = "Upstream: stdio"
	GroupIdentity           Group = "Identity to the upstream"
	GroupDownstreamTokens   Group = "Downstream tokens (On-Behalf-Of)"
	GroupKeysAndStore       Group = "Sealing keys and store"
	GroupOperations         Group = "Operations"
	GroupConsent            Group = "Consent page"
	GroupDevelopment        Group = "Development and trying it out"
)

var groups = []Group{GroupEndpoint, GroupIdP, GroupEntra, GroupOIDC, GroupGate, GroupClientRegistration, GroupAppOnly,
	GroupHTTPUpstream, GroupStdioUpstream, GroupIdentity, GroupDownstreamTokens, GroupKeysAndStore, GroupOperations, GroupConsent, GroupDevelopment}

// registry is every setting the proxy reads, in the order the effective configuration is printed.
var registry = []Setting{
	{Name: "public-url", Group: GroupEndpoint, Help: "public URL of the MCP endpoint exactly as users enter it, e.g. https://mcp.example.com/mcp; an internationalized host in its ASCII (xn--) form"},
	{Name: "upstream-url", Group: GroupHTTPUpstream, Help: "URL of the HTTP upstream MCP server; or set a stdio upstream with upstream-command"},
	{Name: "upstream-header-timeout", Group: GroupHTTPUpstream, Default: "5m", Help: "how long the HTTP upstream may take to send its response headers; a request that waits longer gets a JSON-RPC timeout error, and a streamed response is not limited once its headers arrive; 1s to 1h (ADR-0018 §7)"},
	{Name: "upstream-credential", Group: GroupHTTPUpstream, Secret: true, Help: "HTTP upstream: a header value the proxy sends with every upstream request, such as an API key the upstream needs from the proxy itself; never the user's or the client's token; read at start, never logged (ADR-0016 §7, docs/how-to/upstream-credential.md)"},
	{Name: "upstream-credential-header", Group: GroupHTTPUpstream, Default: "Authorization", Help: "the header that carries upstream-credential; inbound copies are always removed; it never shares a header with the identity assertion, so with Authorization here set assertion-header to another header (ADR-0016 §7)"},
	{Name: "upstream-strip-headers", Group: GroupHTTPUpstream, Help: "HTTP upstream: comma-separated request headers removed before every upstream request, besides the built-in ones, compared in any case with _ read as -: the headers an upstream takes its settings or credentials from, such as x-argocd-base-url; exact names only, so list a family such as X-Atlassian-*-Url name by name; MCP's own headers are refused (docs/how-to/harden-a-deployment.md)"},
	{Name: "upstream-command", Group: GroupStdioUpstream, Help: "stdio upstream: the command as a JSON array, e.g. [\"/usr/local/bin/server\",\"--flag\"], never run through a shell; or give it after -- on the command line (docs/how-to/stdio-upstream.md)"},
	{Name: "upstream-env", Group: GroupStdioUpstream, Secret: true, Help: "stdio upstream: KEY=VALUE lines set in the environment of each upstream process, besides the inherited PATH, HOME, USER, LOGNAME, TMPDIR, TZ, LANG and LC_* (ADR-0016 §6); values are never logged"},
	{Name: "stdio-max-processes", Group: GroupStdioUpstream, Default: "64", Help: "stdio upstream: most upstream processes alive at once; when full, the least recently used idle one is stopped (ADR-0003 §5)"},
	{Name: "stdio-max-processes-per-user", Group: GroupStdioUpstream, Default: "8", Help: "stdio upstream: most upstream processes one user has alive at once; when full, that user's least recently used idle one is stopped"},
	{Name: "stdio-stream-idle-timeout", Group: GroupStdioUpstream, Default: "10m", Help: "stdio upstream: a process kept busy only by open streams (a legacy GET stream, a subscriptions/listen) that has had no traffic for this long can be stopped when a process cap is full; 0 keeps such processes however long they are quiet, otherwise at least 1m"},
	{Name: "listen", Group: GroupEndpoint, Default: "127.0.0.1:8080", Help: "address to listen on; public addresses only when configured"},
	{Name: "tls-cert-file", Group: GroupEndpoint, Help: "serve TLS on the listener: an absolute path to the PEM certificate, followed by any intermediates; with tls-key-file; needs an https public-url; a replaced file is served from the next connection on, with no restart (docs/how-to/tls.md)"},
	{Name: "tls-key-file", Group: GroupEndpoint, Help: "serve TLS on the listener: an absolute path to the certificate's unencrypted PEM private key, readable by the proxy's user alone or on a read-only mount; with tls-cert-file (docs/how-to/tls.md)"},
	{Name: "allowed-origins", Group: GroupEndpoint, Help: "comma-separated Origin values allowed on the MCP endpoint (scheme://host[:port]); an internationalized host in its ASCII (xn--) form"},
	{Name: "allowed-hosts", Group: GroupEndpoint, Help: "comma-separated extra Host values accepted besides the public URL's host; an internationalized host in its ASCII (xn--) form"},
	{Name: "scope", Group: GroupEndpoint, Default: "mcp", Help: "the scope advertised in protected resource metadata and 401 challenges"},
	{Name: "resource-name", Group: GroupEndpoint, Help: "human-readable resource name in protected resource metadata"},
	{Name: "resource-documentation", Group: GroupEndpoint, Help: "documentation URL in protected resource metadata"},
	{Name: "log-format", Group: GroupOperations, Default: "json", Help: "log format: json or text"},
	{Name: "trusted-proxies", Group: GroupOperations, Help: "comma-separated CIDRs or addresses of reverse proxies whose X-Forwarded-For is trusted for the client address (ADR-0018 §6); empty trusts none"},
	{Name: "oauth-rate-limits", Group: GroupOperations, Help: "per-minute limits per client address on OAuth endpoints, e.g. authorize=60,token=120 (ADR-0018 §8); unset endpoints keep their defaults"},
	{Name: "internal-listen", Group: GroupOperations, Default: "127.0.0.1:9090", Help: "address of the internal listener for /metrics, /livez and /readyz (ADR-0018 §10); empty turns it off"},
	{Name: "idp", Group: GroupIdP, Auth: true, Default: "entra", Help: "the IdP users sign in with: entra, or oidc for any OpenID Connect IdP, or one of its presets " + strings.Join(OIDCPresets, ", ") + " (ADR-0011, docs/how-to/oidc.md); the callback path is /callback/<idp>"},
	{Name: "entra-tenant", Group: GroupEntra, Auth: true, Help: "Entra tenant ID (a GUID) of the IdP app"},
	{Name: "entra-client-id", Group: GroupEntra, Auth: true, Help: "application (client) ID of the IdP app registration"},
	{Name: "entra-client-secret", Group: GroupEntra, Auth: true, Secret: true, Help: "client secret of the IdP app"},
	{Name: "entra-client-certificate", Group: GroupEntra, Auth: true, Secret: true, Help: "instead of a client secret: a PEM file with the IdP app's certificate and its unencrypted RSA private key (2048 bits or more); the certificate must be uploaded to the app registration; recommended for production (ADR-0012 §5, docs/how-to/entra-certificate.md)"},
	{Name: "entra-federated-token-file", Group: GroupEntra, Auth: true, Help: "instead of a client secret: an absolute path to a file holding a federated token (a JWT from another identity provider, such as GitHub Actions or AKS workload identity) that byward sends Entra as its client assertion, re-reading the file for every token request; the app registration needs a matching federated identity credential (ADR-0012 §5, docs/how-to/entra-federated-credential.md)"},
	{Name: "entra-client-secret-expires-at", Group: GroupEntra, Auth: true, Help: "when the client secret expires, as a date (2027-11-06) or an RFC 3339 time; the proxy warns at startup and doctor warns from 30 days before (ADR-0012 §10)"},
	{Name: "oidc-issuer", Group: GroupOIDC, Auth: true, Help: "with an oidc IdP: the issuer URL, exactly as its discovery document states it (https); " + defaultIssuersHelp()},
	{Name: "oidc-client-id", Group: GroupOIDC, Auth: true, Help: "with an oidc IdP: the client ID of the proxy's app at the IdP"},
	{Name: "oidc-client-secret", Group: GroupOIDC, Auth: true, Secret: true, Help: "with an oidc IdP: the client secret; give this or BYWARD_OIDC_CLIENT_KEY_FILE"},
	{Name: "oidc-client-key", Group: GroupOIDC, Auth: true, Secret: true, Help: "with an oidc IdP: a PEM private key (RSA or EC P-256) for private_key_jwt instead of a secret"},
	{Name: "oidc-client-key-id", Group: GroupOIDC, Auth: true, Help: "with an oidc IdP: the key ID (kid) the IdP registered for BYWARD_OIDC_CLIENT_KEY_FILE"},
	{Name: "oidc-scopes", Group: GroupOIDC, Auth: true, Help: "with an oidc IdP: comma-separated scopes to request besides openid and the preset's"},
	{Name: "oidc-subject-claim", Group: GroupOIDC, Auth: true, Default: "sub", Help: "with an oidc IdP: the claim that identifies a user; one users can change (email, preferred_username, upn, name) logs a warning"},
	{Name: "oidc-roles-claim", Group: GroupOIDC, Auth: true, Default: "roles", Help: "with an oidc IdP: the ID token claim the access gate (BYWARD_GATE_ROLES) and the identity assertion read roles from, such as a namespaced https://example.com/roles; the default is roles for every preset (docs/how-to/oidc.md)"},
	{Name: "oidc-groups-claim", Group: GroupOIDC, Auth: true, Default: "groups", Help: "with an oidc IdP: the ID token claim the access gate (BYWARD_GATE_GROUPS) and the identity assertion read groups from, such as a namespaced https://example.com/groups; the default is groups for every preset (docs/how-to/oidc.md)"},
	{Name: "oidc-name", Group: GroupOIDC, Auth: true, Help: "with an oidc IdP: its name on the consent page; default: the preset's name, or the issuer's host"},
	{Name: "data-dir", Group: GroupKeysAndStore, Auth: true, Default: "/var/lib/byward", Help: "data directory, an absolute path; the keys, clients and store settings default to paths in it (ADR-0007 §6, docs/how-to/state.md)"},
	{Name: "keys-dir", Group: GroupKeysAndStore, Auth: true, Help: "directory of sealing keys; each file is one key, its name the key ID; default: keys in the data directory (docs/how-to/sealing-keys.md)"},
	{Name: "assertion-keys-dir", Group: GroupIdentity, Auth: true, Help: "directory of the identity assertion's signing keys: PEM ECDSA P-256 files, each name the key ID; the key whose ID sorts last signs; needed with an HTTP upstream; default: assertion-keys in the data directory (docs/how-to/identity-assertion.md)"},
	{Name: "assertion-header", Group: GroupIdentity, Auth: true, Default: "Authorization", Help: "request header that carries the identity assertion to the HTTP upstream, as Bearer <JWT>; inbound copies are always removed (ADR-0016 §2)"},
	{Name: "identity-headers", Group: GroupIdentity, Auth: true, Default: "false", Help: "also send the HTTP upstream the user in plain headers (X-Byward-Subject, X-Byward-Client-Id, X-Byward-Principal-Type, and X-Byward-Roles, -Groups, -Email, -Email-Verified, -Name for the assertion's claims), percent-encoded; safe only when the upstream is reachable through this proxy alone (ADR-0016 §5, docs/how-to/plain-identity-headers.md)"},
	{Name: "obo-scopes", Group: GroupDownstreamTokens, Auth: true, Help: "On-Behalf-Of: space-separated scopes of one downstream API, e.g. https://graph.microsoft.com/User.Read; the HTTP upstream then gets a token for them in BYWARD_OBO_HEADER on every request, a stdio upstream on its token socket (BYWARD_DOWNSTREAM_TOKEN_SOCKET); empty turns it off (ADR-0017, docs/how-to/downstream-apis.md)"},
	{Name: "obo-header", Group: GroupDownstreamTokens, Auth: true, Default: "X-Byward-Downstream-Token", Help: "On-Behalf-Of: request header that carries the downstream API token to the HTTP upstream, as Bearer <token>; inbound copies are always removed (ADR-0017 §3); not for a stdio upstream"},
	{Name: "assertion-claims", Group: GroupIdentity, Auth: true, Default: "roles", Help: "comma-separated optional claims in the identity assertion: roles, groups, email, name; or none (ADR-0016 §1, docs/reference/identity-assertion.md)"},
	{Name: "assertion-unverified-email", Group: GroupIdentity, Auth: true, Bool: true, Default: "false", Help: "with email in BYWARD_ASSERTION_CLAIMS: also assert an email the IdP has not verified (Entra never verifies one), marked email_verified false; never authorize on it (docs/how-to/identity-assertion.md)"},
	{Name: "static-clients-file", Group: GroupClientRegistration, Auth: true, Help: "JSON file of pre-registered MCP clients; default: clients.json in the data directory, optional while CIMD or DCR is on; a file you name must exist (docs/reference/static-clients.md)"},
	{Name: "gate-tenants", Group: GroupGate, Auth: true, Help: "access gate: comma-separated Entra tenant IDs allowed to sign in (docs/how-to/access-gate.md)"},
	{Name: "gate-roles", Group: GroupGate, Auth: true, Help: "access gate: comma-separated app roles; users need at least one (docs/how-to/access-gate.md)"},
	{Name: "gate-groups", Group: GroupGate, Auth: true, Help: "access gate: comma-separated group IDs; users need one, and groups overage denies (docs/how-to/access-gate.md)"},
	{Name: "gate-email-domains", Group: GroupGate, Auth: true, Help: "access gate: comma-separated domains of a verified email; oidc IdPs only, never Entra (docs/how-to/access-gate.md)"},
	{Name: "gate-hosted-domains", Group: GroupGate, Auth: true, Help: "access gate: comma-separated Google Workspace domains (hd claim); BYWARD_IDP=google only; with one domain it is also sent to Google as the hd hint (docs/how-to/access-gate.md)"},
	{Name: "dcr", Group: GroupClientRegistration, Auth: true, Bool: true, Default: "true", Help: "accept Dynamic Client Registration at /register (Cursor, Gemini CLI) and advertise it; false turns it off (docs/how-to/dcr.md)"},
	{Name: "client-denylist", Group: GroupClientRegistration, Auth: true, Help: "comma-separated CIMD client IDs (https URLs) and redirect host names refused for CIMD and DCR clients (docs/how-to/dcr.md)"},
	{Name: "cimd", Group: GroupClientRegistration, Auth: true, Bool: true, Default: "true", Help: "accept MCP clients identified by a Client ID Metadata Document URL (Claude, VS Code) and advertise it; false turns it off (docs/how-to/cimd.md)"},
	{Name: "cimd-trusted-hosts", Group: GroupClientRegistration, Auth: true, Help: "comma-separated hosts whose client metadata documents you vouch for: their apps show as trusted by you on the consent page (docs/how-to/cimd.md)"},
	{Name: "cimd-allowed-hosts", Group: GroupClientRegistration, Auth: true, Help: "comma-separated hosts allowed to publish client metadata documents besides the trusted ones; empty allows any host (docs/how-to/cimd.md)"},
	{Name: "app-tokens", Group: GroupAppOnly, Auth: true, Default: "off", Help: "accept app-only tokens from headless callers at the MCP endpoint: off, or entra (BYWARD_IDP=entra only; ADR-0022, docs/how-to/app-tokens.md)"},
	{Name: "app-roles", Group: GroupAppOnly, Auth: true, Help: "with BYWARD_APP_TOKENS=entra, required: comma-separated app roles on the proxy's app; an app-only caller needs at least one (docs/how-to/app-tokens.md)"},
	{Name: "app-client-ids", Group: GroupAppOnly, Auth: true, Help: "with BYWARD_APP_TOKENS=entra: comma-separated application (client) IDs allowed to call (azp); default: any caller with a role (docs/how-to/app-tokens.md)"},
	{Name: "gate-allow-empty", Group: GroupGate, Auth: true, Bool: true, Default: "false", Help: "allow an empty access gate for a Google or generic OIDC IdP (anyone with an account can sign in); no effect with Entra (docs/how-to/access-gate.md)"},
	{Name: "operator-name", Group: GroupConsent, Auth: true, Help: "who runs this proxy, shown on the consent page, e.g. Contoso IT"},
	{Name: "scope-description", Group: GroupConsent, Auth: true, Help: "what the scope lets an app do, in plain words for the consent page, e.g. Read and query your team's dashboards"},
	{Name: "store-dir", Group: GroupKeysAndStore, Auth: true, Help: "state directory of the SQLite store, an absolute path, created with mode 0700; the directory to back up; default: state in the data directory (ADR-0007, docs/how-to/state.md)"},
	{Name: "store-postgres-dsn", Group: GroupKeysAndStore, Auth: true, Secret: true, Help: "the PostgreSQL store, for more than one replica of an HTTP upstream: a file holding the connection string (a URL or key=value pairs, pool settings such as pool_max_conns included); setting it selects PostgreSQL 15 or later instead of SQLite; sslmode=verify-full is required outside --dev; never logged (ADR-0007, docs/how-to/postgres.md)"},
	{Name: "store-counter-file", Group: GroupKeysAndStore, Auth: true, Help: "restore-detection counter file, an absolute path outside the state directory and its backups; default: store-writes next to the keys directory (ADR-0007 §9)"},
	{Name: "refresh-grace", Group: GroupOperations, Auth: true, Default: "30s", Help: "how long a just-rotated refresh token is still accepted, for a client retrying a lost response; 0s to 60s (ADR-0006 §4)"},
	{Name: "insecure-no-auth", Group: GroupDevelopment, Bool: true, Default: "false", Help: "no authentication at all, for trying the proxy out and for tests; loopback only (ADR-0027)"},
	{Name: "dev", Group: GroupDevelopment, Bool: true, Default: "false", Help: "development mode: enables the relaxations it logs at startup"},
}

// errHelp is returned for -h/--help.
var errHelp = flag.ErrHelp

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
	for _, g := range groups {
		fmt.Fprintf(&b, "- [%s](#%s)\n", g, anchor(string(g)))
	}
	for _, g := range groups {
		fmt.Fprintf(&b, "\n## %s\n\n| Flag | Environment | Default | Description |\n|---|---|---|---|\n", g)
		for _, s := range registry {
			if s.Group != g {
				continue
			}
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
	}
	b.WriteString("\n## Actions, commands and exit codes\n\nActions: `--version [--json]`, `--print-config`, `--help` ([proxy actions](commands.md#proxy-actions)).\n")
	b.WriteString("Commands: [commands reference](commands.md).\n\n")
	b.WriteString("Exit codes: 0 success, 1 runtime error, 2 configuration error; `doctor` adds 4, 8 and 12.\n\n")
	b.WriteString(otherEnvironment)
	return b.String()
}

// anchor is the link fragment GitHub gives a heading (github-slugger): lower case, everything but
// letters, marks, decimal digits, letter numbers, connector punctuation, other alphabetic characters
// (such as Ⓐ), hyphens and spaces dropped, spaces as hyphens.
func anchor(heading string) string {
	return strings.Map(func(r rune) rune {
		switch {
		case r == ' ':
			return '-'
		case r == '-' || unicode.In(r, unicode.L, unicode.M, unicode.Nd, unicode.Nl, unicode.Pc, unicode.Other_Alphabetic):
			return unicode.ToLower(r)
		}
		return -1
	}, heading)
}

// otherEnvironment is the reference's list of environment variables that are not settings: read
// by Go or a library the proxy uses, or set by the proxy for a stdio upstream process.
const otherEnvironment = `## Other environment variables

These are not settings, so ` + "`--print-config`" + ` does not show them.

| Variable | Read or set by | Meaning |
|---|---|---|
| ` + "`OTEL_*`" + ` | the proxy, through the OpenTelemetry SDK | traces, off unless ` + "`OTEL_TRACES_EXPORTER`" + ` is set ([observability](observability.md)) |
| ` + "`SSL_CERT_FILE`, `SSL_CERT_DIR`" + ` | the proxy, through Go | the CAs it trusts for outbound TLS: the IdP, the upstream, an MCP client's CIMD document and ` + "`jwks_uri`" + `, and the PostgreSQL store when its DSN has no ` + "`sslrootcert`" + ` ([private CA](../how-to/private-ca.md)) |
| ` + "`HTTPS_PROXY`, `HTTP_PROXY`, `NO_PROXY`" + ` | the proxy, through Go | the environment proxy: the relay to an HTTP upstream, IdP calls, doctor's self-probe and trace export go through it ([doctor](commands.md#checks) names it) |
| ` + "`BYWARD_SUBJECT`, `BYWARD_ISSUER`, `BYWARD_PRINCIPAL_TYPE`" + ` | set by the proxy for a stdio upstream process | who the process acts for ([stdio upstream](../how-to/stdio-upstream.md)) |
| ` + "`BYWARD_DOWNSTREAM_TOKEN_SOCKET`" + ` | set by the proxy for a stdio upstream process, read by ` + "`byward downstream-token`" + ` | the token socket the process asks for its user's downstream token |
`
