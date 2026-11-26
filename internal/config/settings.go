package config

import (
	"errors"
	"flag"
	"fmt"
	"slices"
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
	// A setting in GroupHTTPUpstream or GroupStdioUpstream is for that upstream mode only: given with
	// the other mode, it is refused at load (offModeSettings), so the group is part of validation.
	// An HTTP-only setting of another group has a StdioHint (httpOnlyRefusal, or a hint of its own);
	// one for both modes has BothUpstreams (checkClassified).
	GroupHTTPUpstream     Group = "Upstream: HTTP"
	GroupStdioUpstream    Group = "Upstream: stdio"
	GroupIdentity         Group = "Identity to the upstream"
	GroupDownstreamTokens Group = "Downstream tokens (On-Behalf-Of)"
	GroupKeysAndStore     Group = "Sealing keys and store"
	GroupOperations       Group = "Operations"
	GroupConsent          Group = "Consent page"
	GroupDevelopment      Group = "Development and trying it out"
)

var groups = []Group{GroupEndpoint, GroupIdP, GroupEntra, GroupOIDC, GroupGate, GroupClientRegistration, GroupAppOnly,
	GroupHTTPUpstream, GroupStdioUpstream, GroupIdentity, GroupDownstreamTokens, GroupKeysAndStore, GroupOperations, GroupConsent, GroupDevelopment}

// registry is every setting the proxy reads, in the order the effective configuration is printed.
var registry = []Setting{
	{Name: "public-url", shape: urlShape, Group: GroupEndpoint, Auth: NotForAuth, BothUpstreams: true, Help: "public URL of the MCP endpoint as users enter it, e.g. https://mcp.example.com/mcp, with its host as browsers write it, since they rewrite any other spelling: a host name in lower case (mcp.example.com, not MCP.Example.com); an internationalized host in its ASCII (xn--) form; an IP address as browsers write it (127.0.0.1, not 127.1; [2001:db8::1], not [2001:DB8:0::1]); no other host ending in a number (mcp.10), which browsers refuse; a host name of letters, digits, - . and _ only; and no default port (https://mcp.example.com, not https://mcp.example.com:443), which browsers drop"},
	{Name: "upstream-url", shape: urlShape, Group: GroupHTTPUpstream, Auth: NotForAuth, Help: "URL of the HTTP upstream MCP server, its host name of letters, digits, - . and _ only; or set a stdio upstream with upstream-command"},
	{Name: "upstream-header-timeout", shape: asGivenShape, Group: GroupHTTPUpstream, Auth: NotForAuth, Default: "5m", Help: "how long the HTTP upstream may take to send its response headers; a request that waits longer gets a JSON-RPC timeout error, and a streamed response is not limited once its headers arrive; 1s to 1h (ADR-0018 §7)"},
	{Name: "upstream-credential", shape: secretShape, Group: GroupHTTPUpstream, Auth: NotForAuth, StdioHint: "%[1]s is for an HTTP upstream; give a stdio upstream its credential with BYWARD_UPSTREAM_ENV_FILE",
		Help: "HTTP upstream: a header value the proxy sends with every upstream request, such as an API key the upstream needs from the proxy itself; never the user's or the client's token; read at start, never logged (ADR-0016 §7, docs/how-to/upstream-credential.md)"},
	{Name: "upstream-credential-header", shape: asGivenShape, Group: GroupHTTPUpstream, Auth: NotForAuth, Default: "Authorization", Help: "the header that carries upstream-credential; inbound copies are always removed; it never shares a header with the identity assertion, so with Authorization here set assertion-header to another header (ADR-0016 §7)"},
	{Name: "upstream-strip-headers", shape: asGivenShape, Group: GroupHTTPUpstream, Auth: NotForAuth, Help: "HTTP upstream: comma-separated request headers removed before every upstream request, besides the built-in ones, compared in any case with _ read as -: the headers an upstream takes its settings or credentials from, such as x-argocd-base-url; exact names only, so list a family such as X-Atlassian-*-Url name by name; MCP's own headers are refused (docs/how-to/harden-a-deployment.md)"},
	{Name: "upstream-command", shape: commandShape, Group: GroupStdioUpstream, Auth: NotForAuth, Help: "stdio upstream: the command as a JSON array, e.g. [\"/usr/local/bin/server\",\"--flag\"], never run through a shell; or give it after -- on the command line (docs/how-to/stdio-upstream.md)"},
	{Name: "upstream-env", shape: secretShape, Group: GroupStdioUpstream, Auth: NotForAuth, Help: "stdio upstream: KEY=VALUE lines set in the environment of each upstream process, besides the inherited PATH, HOME, USER, LOGNAME, TMPDIR, TZ, LANG, LC_ALL, LC_CTYPE and LC_MESSAGES (ADR-0016 §6); values are never logged"},
	{Name: "stdio-max-processes", shape: asGivenShape, Group: GroupStdioUpstream, Auth: NotForAuth, Default: "64", Help: "stdio upstream: most upstream processes alive at once; when full, the least recently used idle one is stopped (ADR-0003 §5)"},
	{Name: "stdio-max-processes-per-user", shape: asGivenShape, Group: GroupStdioUpstream, Auth: NotForAuth, Default: "8", Help: "stdio upstream: most upstream processes one user has alive at once; when full, that user's least recently used idle one is stopped"},
	{Name: "stdio-stream-idle-timeout", shape: asGivenShape, Group: GroupStdioUpstream, Auth: NotForAuth, Default: "10m", Help: "stdio upstream: a process kept busy only by open streams (a legacy GET stream, a subscriptions/listen) that has had no traffic for this long can be stopped when a process cap is full; 0 keeps such processes however long they are quiet, otherwise at least 1m"},
	{Name: "listen", shape: asGivenShape, Group: GroupEndpoint, Auth: NotForAuth, BothUpstreams: true, Default: "127.0.0.1:8080", Help: "address to listen on, as host:port, a host name of letters, digits, - . and _ only; public addresses only when configured"},
	{Name: "tls-cert-file", shape: pathShape, Group: GroupEndpoint, Auth: NotForAuth, BothUpstreams: true, Help: "serve TLS on the listener: an absolute path to the PEM certificate, followed by any intermediates; with tls-key-file; needs an https public-url; a replaced file is served from the next connection on, with no restart (docs/how-to/tls.md)"},
	{Name: "tls-key-file", shape: pathShape, Group: GroupEndpoint, Auth: NotForAuth, BothUpstreams: true, Help: "serve TLS on the listener: an absolute path to the certificate's unencrypted PEM private key, with no permission for its group or others, or on a read-only mount; with tls-cert-file (docs/how-to/tls.md)"},
	{Name: "allowed-origins", shape: asGivenShape, Group: GroupEndpoint, Auth: NotForAuth, BothUpstreams: true, Help: "comma-separated Origin values allowed on the MCP endpoint (scheme://host[:port]), with their hosts as browsers write them: a host name of letters, digits, - . and _ only, an internationalized one in its ASCII (xn--) form; an IPv4 address in dotted decimal, and no other host ending in a number; a default port (:443 for https, :80 for http) is dropped, as browsers never send it; an Origin header matches in any spelling a browser produces of the same origin (case, an IP address's spelling, the default port); two entries for one origin are a warning"},
	{Name: "allowed-hosts", shape: asGivenShape, Group: GroupEndpoint, Auth: NotForAuth, BothUpstreams: true, Help: "comma-separated extra Host values accepted besides the public URL's host, as browsers write them: a host name of letters, digits, - . and _ only, an internationalized one in its ASCII (xn--) form; an IPv4 address in dotted decimal (127.0.0.1, not 127.1, which is refused), and no other host ending in a number (mcp.10); a Host header matches in any spelling of the same address; two entries for one host are a warning"},
	{Name: "scope", shape: asGivenShape, Group: GroupEndpoint, Auth: NotForAuth, BothUpstreams: true, Default: "mcp", Help: "the scope advertised in protected resource metadata and 401 challenges"},
	{Name: "resource-name", shape: asGivenShape, Group: GroupEndpoint, Auth: NotForAuth, BothUpstreams: true, Help: "human-readable resource name in protected resource metadata"},
	{Name: "resource-documentation", shape: urlShape, Group: GroupEndpoint, Auth: NotForAuth, BothUpstreams: true, Help: "documentation URL in protected resource metadata"},
	{Name: "log-format", shape: asGivenShape, Group: GroupOperations, Auth: NotForAuth, BothUpstreams: true, Default: "json", Help: "log format: json or text"},
	{Name: "trusted-proxies", shape: asGivenShape, Group: GroupOperations, Auth: NotForAuth, BothUpstreams: true, Help: "comma-separated CIDRs or addresses of reverse proxies whose X-Forwarded-For is trusted for the client address (ADR-0018 §6); empty trusts none; an entry with an IPv6 zone, or inside link-local fe80::/10, is refused: such an address names a host only together with an interface"},
	{Name: "oauth-rate-limits", shape: asGivenShape, Group: GroupOperations, Auth: NotForAuth, BothUpstreams: true, Help: "per-minute limits per client address on OAuth endpoints, e.g. authorize=60,token=120 (ADR-0018 §8); unset endpoints keep their defaults"},
	{Name: "internal-listen", shape: asGivenShape, Group: GroupOperations, Auth: NotForAuth, BothUpstreams: true, Default: "127.0.0.1:9090", EmptyIsGiven: true, Help: "address of the internal listener for /metrics, /livez and /readyz (ADR-0018 §10), as host:port, a host name of letters, digits, - . and _ only; empty turns it off"},
	{Name: "idp", shape: asGivenShape, Group: GroupIdP, Auth: ForAuth, BothUpstreams: true, Default: "entra", Help: "the IdP users sign in with: entra, or oidc for any OpenID Connect IdP, or one of its presets " + strings.Join(OIDCPresets, ", ") + " (ADR-0011, docs/how-to/oidc.md); the callback path is /callback/<idp>"},
	{Name: "entra-tenant", shape: asGivenShape, Group: GroupEntra, Auth: ForAuth, BothUpstreams: true, Help: "Entra tenant ID (a GUID) of the IdP app"},
	{Name: "entra-client-id", shape: asGivenShape, Group: GroupEntra, Auth: ForAuth, BothUpstreams: true, Help: "application (client) ID of the IdP app registration"},
	{Name: "entra-client-secret", shape: secretShape, Group: GroupEntra, Auth: ForAuth, BothUpstreams: true, Help: "client secret of the IdP app"},
	{Name: "entra-client-certificate", shape: secretShape, Group: GroupEntra, Auth: ForAuth, BothUpstreams: true, Help: "instead of a client secret: a PEM file with the IdP app's certificate and its unencrypted RSA private key (2048 bits or more); the certificate must be uploaded to the app registration; recommended for production (ADR-0012 §5, docs/how-to/entra-certificate.md)"},
	{Name: "entra-federated-token-file", shape: pathShape, Group: GroupEntra, Auth: ForAuth, BothUpstreams: true, Help: "instead of a client secret: an absolute path to a file holding a federated token (a JWT from another identity provider, such as GitHub Actions or AKS workload identity) that byward sends Entra as its client assertion, re-reading the file for every token request; the app registration needs a matching federated identity credential (ADR-0012 §5, docs/how-to/entra-federated-credential.md)"},
	{Name: "entra-client-secret-expires-at", shape: asGivenShape, Group: GroupEntra, Auth: ForAuth, BothUpstreams: true, Help: "when the client secret expires, as a date (2027-11-06) or an RFC 3339 time; the proxy warns at startup and doctor warns from 30 days before (ADR-0012 §10)"},
	{Name: "oidc-issuer", shape: urlShape, Group: GroupOIDC, Auth: ForAuth, BothUpstreams: true, Help: "with an oidc IdP: the issuer URL, exactly as its discovery document states it (https); " + defaultIssuersHelp()},
	{Name: "oidc-client-id", shape: asGivenShape, Group: GroupOIDC, Auth: ForAuth, BothUpstreams: true, Help: "with an oidc IdP: the client ID of the proxy's app at the IdP"},
	{Name: "oidc-client-secret", shape: secretShape, Group: GroupOIDC, Auth: ForAuth, BothUpstreams: true, Help: "with an oidc IdP: the client secret; give this or BYWARD_OIDC_CLIENT_KEY_FILE"},
	{Name: "oidc-client-key", shape: secretShape, Group: GroupOIDC, Auth: ForAuth, BothUpstreams: true, Help: "with an oidc IdP: a PEM private key (RSA of 2048 bits or more, or EC P-256) for private_key_jwt instead of a secret"},
	{Name: "oidc-client-key-alg", shape: asGivenShape, Group: GroupOIDC, Auth: ForAuth, BothUpstreams: true, Help: "with an oidc IdP and BYWARD_OIDC_CLIENT_KEY_FILE: the client assertion's signing algorithm, PS256 or RS256 for an RSA key, ES256 for an EC P-256 key; default PS256 for RSA, ES256 for EC. Okta refuses PS256: use RS256 there (docs/how-to/oidc.md)"},
	{Name: "oidc-client-key-id", shape: asGivenShape, Group: GroupOIDC, Auth: ForAuth, BothUpstreams: true, Help: "with an oidc IdP: the key ID (kid) the IdP registered for BYWARD_OIDC_CLIENT_KEY_FILE"},
	{Name: "oidc-scopes", shape: asGivenShape, Group: GroupOIDC, Auth: ForAuth, BothUpstreams: true, Help: "with an oidc IdP: comma-separated scopes to request besides openid and the preset's"},
	{Name: "oidc-subject-claim", shape: asGivenShape, Group: GroupOIDC, Auth: ForAuth, BothUpstreams: true, Default: "sub", Help: "with an oidc IdP: the claim that identifies a user; one users can change (email, preferred_username, upn, name) logs a warning"},
	{Name: "oidc-roles-claim", shape: asGivenShape, Group: GroupOIDC, Auth: ForAuth, BothUpstreams: true, Default: "roles", Help: "with an oidc IdP: the ID token claim the access gate (BYWARD_GATE_ROLES) and the identity assertion read roles from, such as a namespaced https://example.com/roles; the default is roles for every preset (docs/how-to/oidc.md)"},
	{Name: "oidc-groups-claim", shape: asGivenShape, Group: GroupOIDC, Auth: ForAuth, BothUpstreams: true, Default: "groups", Help: "with an oidc IdP: the ID token claim the access gate (BYWARD_GATE_GROUPS) and the identity assertion read groups from, such as a namespaced https://example.com/groups; the default is groups for every preset (docs/how-to/oidc.md)"},
	{Name: "oidc-name", shape: asGivenShape, Group: GroupOIDC, Auth: ForAuth, BothUpstreams: true, Help: "with an oidc IdP: its name on the consent page; default: the preset's name, or the issuer's host"},
	{Name: "data-dir", shape: pathShape, Group: GroupKeysAndStore, Auth: ForAuth, BothUpstreams: true, Default: "/var/lib/byward", Help: "data directory, an absolute path; the keys, clients and store settings default to paths in it (ADR-0007 §6, docs/how-to/state.md)"},
	{Name: "keys-dir", shape: pathShape, Group: GroupKeysAndStore, Auth: ForAuth, BothUpstreams: true, Help: "directory of sealing keys, an absolute path; each file is one key, its name the key ID; default: keys in the data directory (docs/how-to/sealing-keys.md)"},
	{Name: "assertion-keys-dir", shape: pathShape, Group: GroupIdentity, Auth: ForAuth, StdioHint: httpOnlyRefusal, Help: "directory of the identity assertion's signing keys, an absolute path: PEM ECDSA P-256 files, each name the key ID; the key whose ID sorts last signs; needed with an HTTP upstream; default: assertion-keys in the data directory (docs/how-to/identity-assertion.md)"},
	{Name: "assertion-header", shape: asGivenShape, Group: GroupIdentity, Auth: ForAuth, Default: "Authorization", StdioHint: httpOnlyRefusal, Help: "request header that carries the identity assertion to the HTTP upstream, as Bearer <JWT>; inbound copies are always removed (ADR-0016 §2)"},
	{Name: "identity-headers", shape: asGivenShape, Group: GroupIdentity, Auth: ForAuth, Bool: true, Default: "false", StdioHint: "%[1]s is for an HTTP upstream; a stdio upstream gets the user in its environment (BYWARD_SUBJECT, docs/how-to/stdio-upstream.md)",
		Help: "also send the HTTP upstream the user in plain headers (X-Byward-Subject, X-Byward-Client-Id, X-Byward-Principal-Type, and X-Byward-Roles, -Groups, -Email, -Email-Verified, -Name for the assertion's claims), percent-encoded; safe only when the upstream is reachable through this proxy alone (ADR-0016 §5, docs/how-to/plain-identity-headers.md)"},
	{Name: "obo-scopes", shape: asGivenShape, Group: GroupDownstreamTokens, Auth: ForAuth, BothUpstreams: true, Help: "On-Behalf-Of: space-separated scopes of one downstream API, e.g. https://graph.microsoft.com/User.Read; the HTTP upstream then gets a token for them in BYWARD_OBO_HEADER on every request, a stdio upstream on its token socket (BYWARD_DOWNSTREAM_TOKEN_SOCKET); empty turns it off (ADR-0017, docs/how-to/downstream-apis.md)"},
	{Name: "obo-header", shape: asGivenShape, Group: GroupDownstreamTokens, Auth: ForAuth, Default: "X-Byward-Downstream-Token", StdioHint: "%[1]s: a stdio upstream gets its downstream token from its token socket (BYWARD_DOWNSTREAM_TOKEN_SOCKET), not a header; leave %[1]s unset",
		Help: "On-Behalf-Of: request header that carries the downstream API token to the HTTP upstream, as Bearer <token>; inbound copies are always removed (ADR-0017 §3); not for a stdio upstream"},
	{Name: "assertion-claims", shape: asGivenShape, Group: GroupIdentity, Auth: ForAuth, Default: "roles", StdioHint: httpOnlyRefusal, Help: "comma-separated optional claims in the identity assertion: roles, groups, email, name; or none (ADR-0016 §1, docs/reference/identity-assertion.md)"},
	{Name: "assertion-unverified-email", shape: asGivenShape, Group: GroupIdentity, Auth: ForAuth, Bool: true, Default: "false", StdioHint: httpOnlyRefusal, Help: "with email in BYWARD_ASSERTION_CLAIMS: also assert an email the IdP has not verified (Entra never verifies one), marked email_verified false; never authorize on it (docs/how-to/identity-assertion.md)"},
	{Name: "static-clients-file", shape: pathShape, Group: GroupClientRegistration, Auth: ForAuth, BothUpstreams: true, Help: "JSON file of pre-registered MCP clients, an absolute path; default: clients.json in the data directory, optional while CIMD or DCR is on; a file you name must exist (docs/reference/static-clients.md)"},
	{Name: "gate-tenants", shape: asGivenShape, Group: GroupGate, Auth: ForAuth, BothUpstreams: true, Help: "access gate: comma-separated Entra tenant IDs allowed to sign in (docs/how-to/access-gate.md)"},
	{Name: "gate-roles", shape: asGivenShape, Group: GroupGate, Auth: ForAuth, BothUpstreams: true, Help: "access gate: comma-separated app roles; users need at least one (docs/how-to/access-gate.md)"},
	{Name: "gate-groups", shape: asGivenShape, Group: GroupGate, Auth: ForAuth, BothUpstreams: true, Help: "access gate: comma-separated group IDs; users need one, and groups overage denies (docs/how-to/access-gate.md)"},
	{Name: "gate-email-domains", shape: asGivenShape, Group: GroupGate, Auth: ForAuth, BothUpstreams: true, Help: "access gate: comma-separated domains of a verified email; oidc IdPs only, never Entra (docs/how-to/access-gate.md)"},
	{Name: "gate-hosted-domains", shape: asGivenShape, Group: GroupGate, Auth: ForAuth, BothUpstreams: true, Help: "access gate: comma-separated Google Workspace domains (hd claim); BYWARD_IDP=google only; with one domain it is also sent to Google as the hd hint (docs/how-to/access-gate.md)"},
	{Name: "dcr", shape: asGivenShape, Group: GroupClientRegistration, Auth: ForAuth, BothUpstreams: true, Bool: true, Default: "true", Help: "accept Dynamic Client Registration at /register (Cursor, Gemini CLI) and advertise it; false turns it off (docs/how-to/dcr.md)"},
	{Name: "client-denylist", shape: urlListShape, Group: GroupClientRegistration, Auth: ForAuth, BothUpstreams: true, Help: "comma-separated CIMD client IDs (https URLs) and redirect host names refused for CIMD and DCR clients (docs/how-to/dcr.md)"},
	{Name: "cimd", shape: asGivenShape, Group: GroupClientRegistration, Auth: ForAuth, BothUpstreams: true, Bool: true, Default: "true", Help: "accept MCP clients identified by a Client ID Metadata Document URL (Claude, VS Code) and advertise it; false turns it off (docs/how-to/cimd.md)"},
	{Name: "cimd-trusted-hosts", shape: asGivenShape, Group: GroupClientRegistration, Auth: ForAuth, BothUpstreams: true, EnabledBy: "cimd", Help: "comma-separated hosts whose client metadata documents you vouch for: their apps show as trusted by you on the consent page (docs/how-to/cimd.md)"},
	{Name: "cimd-allowed-hosts", shape: asGivenShape, Group: GroupClientRegistration, Auth: ForAuth, BothUpstreams: true, EnabledBy: "cimd", Help: "comma-separated hosts allowed to publish client metadata documents besides the trusted ones; empty allows any host (docs/how-to/cimd.md)"},
	{Name: "app-tokens", shape: asGivenShape, Group: GroupAppOnly, Auth: ForAuth, BothUpstreams: true, Default: "off", Help: "accept app-only tokens from headless callers at the MCP endpoint: off, or entra (BYWARD_IDP=entra only; ADR-0022, docs/how-to/app-tokens.md)"},
	{Name: "app-roles", shape: asGivenShape, Group: GroupAppOnly, Auth: ForAuth, BothUpstreams: true, EnabledBy: "app-tokens", Help: "with BYWARD_APP_TOKENS=entra, required: comma-separated app roles on the proxy's app; an app-only caller needs at least one (docs/how-to/app-tokens.md)"},
	{Name: "app-client-ids", shape: asGivenShape, Group: GroupAppOnly, Auth: ForAuth, BothUpstreams: true, EnabledBy: "app-tokens", Help: "with BYWARD_APP_TOKENS=entra: comma-separated application (client) IDs allowed to call (azp); default: any caller with a role (docs/how-to/app-tokens.md)"},
	{Name: "gate-allow-empty", shape: asGivenShape, Group: GroupGate, Auth: ForAuth, BothUpstreams: true, Bool: true, Default: "false", Help: "allow an empty access gate for a Google or generic OIDC IdP (anyone with an account can sign in); no effect with Entra (docs/how-to/access-gate.md)"},
	{Name: "operator-name", shape: asGivenShape, Group: GroupConsent, Auth: ForAuth, BothUpstreams: true, Help: "who runs this proxy, shown on the consent page, e.g. Contoso IT"},
	{Name: "scope-description", shape: asGivenShape, Group: GroupConsent, Auth: ForAuth, BothUpstreams: true, Help: "what the scope lets an app do, in plain words for the consent page, e.g. Read and query your team's dashboards"},
	{Name: "store-dir", shape: pathShape, Group: GroupKeysAndStore, Auth: ForAuth, BothUpstreams: true, Help: "state directory of the SQLite store, an absolute path, created with mode 0700; the directory to back up; default: state in the data directory (ADR-0007, docs/how-to/state.md)"},
	{Name: "store-postgres-dsn", shape: secretShape, Group: GroupKeysAndStore, Auth: ForAuth, StdioHint: "%[1]s: the PostgreSQL store is for several replicas, and a stdio upstream's processes live on one (ADR-0007 §4); use the SQLite store",
		Help: "the PostgreSQL store, for more than one replica of an HTTP upstream: a file holding the connection string (a URL or key=value pairs, pool settings such as pool_max_conns included); setting it selects PostgreSQL 15 or later instead of SQLite; sslmode=verify-full is required outside --dev; never logged (ADR-0007, docs/how-to/postgres.md)"},
	{Name: "store-counter-file", shape: pathShape, Group: GroupKeysAndStore, Auth: ForAuth, BothUpstreams: true, Help: "restore-detection counter file, an absolute path outside the state directory and its backups; default: store-writes next to the keys directory (ADR-0007 §9)"},
	{Name: "refresh-grace", shape: asGivenShape, Group: GroupOperations, Auth: ForAuth, BothUpstreams: true, Default: "30s", Help: "how long a just-rotated refresh token is still accepted, for a client retrying a lost response; 0s to 60s (ADR-0006 §4)"},
	{Name: "insecure-no-auth", shape: asGivenShape, Group: GroupDevelopment, Auth: NotForAuth, BothUpstreams: true, Bool: true, Default: "false", Help: "no authentication at all, for trying the proxy out and for tests; loopback only (ADR-0027)"},
	{Name: "dev", shape: asGivenShape, Group: GroupDevelopment, Auth: NotForAuth, BothUpstreams: true, Bool: true, Default: "false", Help: "development mode: enables the relaxations it logs at startup"},
}

// httpOnlyRefusal is the refusal, beside a stdio upstream, of a setting only an HTTP upstream reads
// that needs no hint of its own: the StdioHint of the identity assertion's settings, which a stdio
// upstream never gets (ADR-0016 §2, §6), and the refusal of an HTTP upstream's setting without a hint
// (offModeSettings). It names the HTTP upstream's selector as advice (allowedHintVariables).
const httpOnlyRefusal = "%[1]s is set, but the upstream is stdio: it applies only to an HTTP upstream (BYWARD_UPSTREAM_URL); remove it"

// A registry entry without a shape stops the program at init (ADR-0031 §3): it would show as Hidden,
// and be read as a setting that is not secret.
func init() {
	checkShapes(registry)
	checkStdioHints(registry)
	checkClassified(registry)
	checkEnablers(registry)
}

// checkShapes panics on a setting of reg that has no shape.
func checkShapes(reg []Setting) {
	for _, s := range reg {
		if s.shape == nil {
			panic("config: setting " + s.Name + " has no shape")
		}
	}
}

// checkStdioHints panics on a StdioHint of reg that is not fixed text naming the setting: one with
// no %[1]s, or any other formatting verb, which could show a value; or one on a stdio upstream's
// setting, which is never refused beside a stdio upstream.
func checkStdioHints(reg []Setting) {
	for _, s := range reg {
		switch rest := strings.ReplaceAll(s.StdioHint, "%[1]s", ""); {
		case s.StdioHint == "":
		case s.Group == GroupStdioUpstream:
			panic("config: setting " + s.Name + " is a stdio upstream's, so it takes no stdio hint")
		case rest == s.StdioHint || strings.Contains(rest, "%"):
			panic("config: the stdio hint of " + s.Name + " must name it with %[1]s and have no other verb")
		}
	}
}

// checkClassified panics on a setting of reg that leaves a classification unstated, or states its
// upstream mode twice, naming the setting and the classification (#658): whether it configures
// authentication (Auth), and, outside the upstream groups, which upstream mode it is for (a StdioHint
// for an HTTP upstream only, or BothUpstreams). A setting cannot default into either answer.
func checkClassified(reg []Setting) {
	for _, s := range reg {
		upstreamGroup := s.Group == GroupHTTPUpstream || s.Group == GroupStdioUpstream
		switch {
		case s.Auth != ForAuth && s.Auth != NotForAuth:
			panic("config: setting " + s.Name + " does not say whether it configures authentication: give it Auth: ForAuth or Auth: NotForAuth")
		case s.BothUpstreams && upstreamGroup:
			panic("config: setting " + s.Name + " is in an upstream group, which decides its mode: drop BothUpstreams")
		case s.BothUpstreams && s.StdioHint != "":
			panic("config: setting " + s.Name + " has a StdioHint and BothUpstreams: give it one of them")
		case !upstreamGroup && !s.BothUpstreams && s.StdioHint == "":
			panic("config: setting " + s.Name + " does not say which upstream mode it is for: give it a StdioHint if only an HTTP upstream reads it, or BothUpstreams")
		}
	}
}

// familyEnablers are the settings EnabledBy may name, the families a walk checks by EnabledBy: cimd
// (the CIMD host lists, clientSources) and app-tokens (the app-only lists, appTokens). An IdP family
// and an upstream mode go by Group.
var familyEnablers = []string{"cimd", "app-tokens"}

// checkEnablers panics on a setting of reg whose EnabledBy names none of familyEnablers: no walk would
// check its family, so it would load while the family is off.
func checkEnablers(reg []Setting) {
	for _, s := range reg {
		if s.EnabledBy != "" && !slices.Contains(familyEnablers, s.EnabledBy) {
			panic("config: setting " + s.Name + " is EnabledBy " + s.EnabledBy + ", which no family walk checks: give it one of " + strings.Join(familyEnablers, ", "))
		}
	}
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
		flagName, env := "--"+s.Name, s.EnvToSet()
		if s.Secret() {
			flagName = "--" + s.FileFlag()
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
	b.WriteString("Precedence: flag > environment > default. Secrets are read only from files. A variable set to\nnothing is the same as unset, unless its setting says what empty means. A setting marked *(path)*\nholds a path, as does every secret's file: a file that cannot be used is named by its setting and\nthe cause, never by its path.\n\n")
	for _, g := range groups {
		fmt.Fprintf(&b, "- [%s](#%s)\n", g, anchor(string(g)))
	}
	for _, g := range groups {
		fmt.Fprintf(&b, "\n## %s\n\n| Flag | Environment | Default | Description |\n|---|---|---|---|\n", g)
		for _, s := range registry {
			if s.Group != g {
				continue
			}
			flagName, env := "--"+s.Name, s.EnvToSet()
			if s.Secret() {
				flagName = "--" + s.FileFlag()
			}
			def := s.Default
			if def == "" {
				def = "—"
			}
			help := s.Help
			if s.HoldsPath() {
				help += " *(path)*"
			}
			fmt.Fprintf(&b, "| `%s` | `%s` | %s | %s |\n", flagName, env, def, help)
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
