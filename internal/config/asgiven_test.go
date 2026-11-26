package config

import (
	"slices"
	"strings"
	"testing"
)

// A refusal of settings given together, or of one given without another, names each given setting
// as the operator gave it, flag or variable (#619): the message points at what the operator wrote.
func TestARefusalBetweenSettingsNamesEachGivenOneAsGiven(t *testing.T) {
	withoutOIDCSecret := without("BYWARD_OIDC_CLIENT_SECRET_FILE")(slices.Clone(oidcBase))
	for _, tc := range []struct {
		name  string
		args  []string
		env   []string
		files readFileFunc
		want  string
	}{
		{"an OIDC secret and key, by env", nil, append(slices.Clone(oidcBase), "BYWARD_OIDC_CLIENT_KEY_FILE=/run/secrets/key.pem"), oidcFiles,
			"BYWARD_OIDC_CLIENT_SECRET_FILE and BYWARD_OIDC_CLIENT_KEY_FILE are both set; give one of them"},
		{"an OIDC secret and key, by flag", []string{"--oidc-client-secret-file=/run/secrets/oidc", "--oidc-client-key-file=/run/secrets/key.pem"}, withoutOIDCSecret, oidcFiles,
			"--oidc-client-secret-file and --oidc-client-key-file are both set; give one of them"},
		{"an OIDC key ID without a key, by env", nil, append(slices.Clone(oidcBase), "BYWARD_OIDC_CLIENT_KEY_ID=k1"), oidcFiles,
			"BYWARD_OIDC_CLIENT_KEY_ID is set without BYWARD_OIDC_CLIENT_KEY_FILE"},
		{"an OIDC key ID without a key, by flag", []string{"--oidc-client-key-id=k1"}, slices.Clone(oidcBase), oidcFiles,
			"--oidc-client-key-id is set without BYWARD_OIDC_CLIENT_KEY_FILE"},
		{"an OIDC key algorithm without a key, by flag", []string{"--oidc-client-key-alg=ES256"}, slices.Clone(oidcBase), oidcFiles,
			"--oidc-client-key-alg is set without BYWARD_OIDC_CLIENT_KEY_FILE"},
		{"an inline Entra secret and a certificate, by env", nil, withoutSecret("BYWARD_ENTRA_CLIENT_SECRET=abc", "BYWARD_ENTRA_CLIENT_CERTIFICATE_FILE=/run/secrets/entra"), baseFiles,
			"BYWARD_ENTRA_CLIENT_CERTIFICATE_FILE and BYWARD_ENTRA_CLIENT_SECRET are set together"},
		{"an inline OIDC secret and a key, by env", nil, append(slices.Clone(withoutOIDCSecret), "BYWARD_OIDC_CLIENT_SECRET=abc", "BYWARD_OIDC_CLIENT_KEY_FILE=/run/secrets/key.pem"), oidcFiles,
			"BYWARD_OIDC_CLIENT_SECRET and BYWARD_OIDC_CLIENT_KEY_FILE are both set"},
		{"two Entra credentials, by env", nil, append(slices.Clone(base), "BYWARD_ENTRA_FEDERATED_TOKEN_FILE=/run/secrets/token"), baseFiles,
			"BYWARD_ENTRA_CLIENT_SECRET_FILE and BYWARD_ENTRA_FEDERATED_TOKEN_FILE are set together"},
		{"two Entra credentials, by flag", []string{"--entra-federated-token-file=/run/secrets/token"}, slices.Clone(base), baseFiles,
			"--entra-federated-token-file and BYWARD_ENTRA_CLIENT_SECRET_FILE are set together"},
		{"a secret expiry with a federated token, by flag", []string{"--entra-federated-token-file=/run/secrets/token", "--entra-client-secret-expires-at=2030-01-01"}, withoutSecret(), baseFiles,
			"--entra-client-secret-expires-at has no effect with --entra-federated-token-file"},
		{"a secret expiry with a certificate, by flag", []string{"--entra-client-certificate-file=/run/secrets/entra", "--entra-client-secret-expires-at=2030-01-01"}, withoutSecret(), baseFiles,
			"--entra-client-secret-expires-at has no effect with --entra-client-certificate-file"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, _, err := Load(tc.args, tc.env, tc.files)
			if !isConfigError(err) || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want it to say %q", err, tc.want)
			}
		})
	}
}

// NameAsGiven names a setting as the operator gave it: its file flag or file variable for a secret, its
// variable to set when it is left at its default or there are no values, and panics for an unknown name.
func TestNameAsGivenNamesASettingAsTheOperatorGaveIt(t *testing.T) {
	withoutOIDCSecret := without("BYWARD_OIDC_CLIENT_SECRET_FILE")(slices.Clone(oidcBase))
	load := func(args, env []string) *Values {
		t.Helper()
		c, _, err := Load(args, env, oidcFiles)
		if err != nil {
			t.Fatal(err)
		}
		return c.Values
	}
	for _, tc := range []struct {
		name string
		v    *Values
		want string
	}{
		{"by flag", load([]string{"--oidc-client-key-file=/run/secrets/key.pem"}, withoutOIDCSecret), "--oidc-client-key-file"},
		{"by env", load(nil, append(slices.Clone(withoutOIDCSecret), "BYWARD_OIDC_CLIENT_KEY_FILE=/run/secrets/key.pem")), "BYWARD_OIDC_CLIENT_KEY_FILE"},
		{"left at its default", load(nil, slices.Clone(oidcBase)), "BYWARD_OIDC_CLIENT_KEY_FILE"},
		{"no values", nil, "BYWARD_OIDC_CLIENT_KEY_FILE"},
	} {
		if got := tc.v.NameAsGiven("oidc-client-key"); got != tc.want {
			t.Errorf("%s: NameAsGiven = %q, want %q", tc.name, got, tc.want)
		}
	}
	if got := (*Values)(nil).CommandNameAsGiven(); got != "BYWARD_UPSTREAM_COMMAND" { // a Config built by hand
		t.Errorf("no values: CommandNameAsGiven = %q, want BYWARD_UPSTREAM_COMMAND", got)
	}
	defer func() {
		if r, want := recover(), "config: no setting oidc-client-keys"; r != want {
			t.Fatalf("recovered %v, want %q", r, want)
		}
	}()
	(*Values)(nil).NameAsGiven("oidc-client-keys")
}

// A refusal names each setting as the operator gave it (#623): the variable when given by env, the
// flag when given by flag, and the variable to set when it is not given. Rows mostly come in pairs,
// the env message pinned beside the flag one. Those without a twin are a command after --, which has
// no variable, and rows that pin a second naming by flag (a setting given empty, which by env would be
// unset, or another setting given by flag) whose env message another row, or offmode_test.go, pins. They sample
// refusals of a value's form or meaning and conflicts between settings; the scan, not this sample,
// covers every refusal.
func TestARefusalNamesEachSettingAsGiven(t *testing.T) {
	noURL := without("BYWARD_UPSTREAM_URL")
	noTenant := without("BYWARD_ENTRA_TENANT")
	noPublicURL := without("BYWARD_PUBLIC_URL")
	const scope = "https://graph.microsoft.com/User.Read"
	files := func(p string) ([]byte, error) { // filesPlusEmptyAndBlank's files, and a stdio environment file that is not KEY=VALUE lines
		switch p {
		case "/run/secrets/bad-env":
			return []byte("not a line\n"), nil
		}
		return filesPlusEmptyAndBlank(p)
	}
	for _, tc := range []struct {
		name string
		args []string
		env  []string
		want string
	}{
		{"a value refused for its form, by env", nil, append(slices.Clone(base), "BYWARD_LISTEN=nonsense"), "BYWARD_LISTEN: want host:port"},
		{"a value refused for its form, by flag", []string{"--listen=nonsense"}, slices.Clone(base), "--listen: want host:port"},
		{"a URL refused for its form, by env", nil, append(noPublicURL(slices.Clone(base)), "BYWARD_PUBLIC_URL=ftp://mcp.example.com/mcp"), "BYWARD_PUBLIC_URL: want an absolute http(s) URL such as https://mcp.example.com/mcp; got a value ("},
		{"a URL refused for its form, by flag", []string{"--public-url=ftp://mcp.example.com/mcp"}, noPublicURL(slices.Clone(base)), "--public-url: want an absolute http(s) URL such as https://mcp.example.com/mcp; got a value ("},
		{"a list of none, by env", nil, append(slices.Clone(base), "BYWARD_ALLOWED_HOSTS=,"), "BYWARD_ALLOWED_HOSTS: want at least one entry; got a list of none"},
		{"a list of none, by flag", []string{"--allowed-hosts=,"}, slices.Clone(base), "--allowed-hosts: want at least one entry; got a list of none"},
		{"a counter file inside the state directory, by env", nil, append(slices.Clone(base), "BYWARD_STORE_DIR=/var/lib/s", "BYWARD_STORE_COUNTER_FILE=/var/lib/s/c"),
			"BYWARD_STORE_COUNTER_FILE: want a path outside BYWARD_STORE_DIR; got one inside it"},
		{"a counter file inside the state directory, by flag", []string{"--store-dir=/var/lib/s", "--store-counter-file=/var/lib/s/c"}, slices.Clone(base),
			"--store-counter-file: want a path outside --store-dir; got one inside it"},
		{"an http public URL without --dev, by env", nil, append(noPublicURL(slices.Clone(base)), "BYWARD_PUBLIC_URL=http://127.0.0.1:8080/mcp"), "BYWARD_PUBLIC_URL: http on loopback needs --dev"},
		{"an http public URL without --dev, by flag", []string{"--public-url=http://127.0.0.1:8080/mcp"}, noPublicURL(slices.Clone(base)), "--public-url: http on loopback needs --dev"},
		{"the internal listener on the public one, by env", nil, append(slices.Clone(base), "BYWARD_LISTEN=127.0.0.1:8080", "BYWARD_INTERNAL_LISTEN=127.0.0.1:8080"),
			"BYWARD_INTERNAL_LISTEN: must differ from BYWARD_LISTEN"},
		{"the internal listener on the public one, by flag", []string{"--listen=127.0.0.1:8080", "--internal-listen=127.0.0.1:8080"}, slices.Clone(base),
			"--internal-listen: must differ from --listen"},
		{"both upstreams, by env", nil, append(slices.Clone(base), `BYWARD_UPSTREAM_COMMAND=["/usr/bin/server"]`), "BYWARD_UPSTREAM_URL and BYWARD_UPSTREAM_COMMAND are both set"},
		{"both upstreams, by flag", []string{"--upstream-url=http://u/mcp", `--upstream-command=["/usr/bin/server"]`}, noURL(slices.Clone(base)), "--upstream-url and --upstream-command are both set"},
		{"both upstreams, a command after --", []string{"--", "/usr/bin/server"}, slices.Clone(base), "BYWARD_UPSTREAM_URL and the command after -- are both set"},
		{"more processes per user than in all, by env", nil, stdioBase(stdioCommand, "BYWARD_STDIO_MAX_PROCESSES=2", "BYWARD_STDIO_MAX_PROCESSES_PER_USER=3"),
			"BYWARD_STDIO_MAX_PROCESSES_PER_USER (3) must not exceed BYWARD_STDIO_MAX_PROCESSES (2)"},
		{"more processes per user than in all, by flag", []string{"--stdio-max-processes=2", "--stdio-max-processes-per-user=3"}, stdioBase(stdioCommand),
			"--stdio-max-processes-per-user (3) must not exceed --stdio-max-processes (2)"},
		{"a credential header without a credential, by env", nil, append(slices.Clone(base), "BYWARD_UPSTREAM_CREDENTIAL_HEADER=X-Key"),
			"BYWARD_UPSTREAM_CREDENTIAL_HEADER is set, but there is no credential: set BYWARD_UPSTREAM_CREDENTIAL_FILE too"},
		{"a credential header without a credential, by flag", []string{"--upstream-credential-header=X-Key"}, slices.Clone(base),
			"--upstream-credential-header is set, but there is no credential: set BYWARD_UPSTREAM_CREDENTIAL_FILE too"},
		{"the credential and the assertion in one header, by env", nil, append(slices.Clone(base), "BYWARD_UPSTREAM_CREDENTIAL_FILE=/run/secrets/entra",
			"BYWARD_UPSTREAM_CREDENTIAL_HEADER=X-Same", "BYWARD_ASSERTION_HEADER=X-Same"), "BYWARD_UPSTREAM_CREDENTIAL_HEADER and BYWARD_ASSERTION_HEADER name the same header, but the credential and the identity assertion never share a header (ADR-0016 §7): set BYWARD_ASSERTION_HEADER to a header of your own"},
		{"the credential and the assertion in one header, by flag", []string{"--upstream-credential-file=/run/secrets/entra", "--upstream-credential-header=X-Same", "--assertion-header=X-Same"},
			slices.Clone(base), "--upstream-credential-header and --assertion-header name the same header, but the credential and the identity assertion never share a header (ADR-0016 §7): set --assertion-header to a header of your own"},
		{"On-Behalf-Of in the assertion's header, by env", nil, append(slices.Clone(base), "BYWARD_OBO_SCOPES="+scope, "BYWARD_OBO_HEADER=X-Same", "BYWARD_ASSERTION_HEADER=X-Same"),
			"BYWARD_OBO_HEADER names the header that already carries the identity assertion (BYWARD_ASSERTION_HEADER)"},
		{"On-Behalf-Of in the assertion's header, by flag", []string{"--obo-scopes=" + scope, "--obo-header=X-Same", "--assertion-header=X-Same"}, slices.Clone(base),
			"--obo-header names the header that already carries the identity assertion (--assertion-header)"},
		{"On-Behalf-Of with another IdP, by env", nil, append(slices.Clone(oidcBase), "BYWARD_OBO_SCOPES="+scope), "BYWARD_OBO_SCOPES: On-Behalf-Of is Entra's; it needs BYWARD_IDP=entra, got keycloak"},
		{"On-Behalf-Of with another IdP, by flag", []string{"--obo-scopes=" + scope, "--idp=keycloak"}, without("BYWARD_IDP")(slices.Clone(oidcBase)),
			"--obo-scopes: On-Behalf-Of is Entra's; it needs --idp=entra, got keycloak"},
		{"CIMD hosts with CIMD off, by env", nil, append(slices.Clone(base), "BYWARD_CIMD=false", "BYWARD_CIMD_TRUSTED_HOSTS=claude.ai"),
			"BYWARD_CIMD_TRUSTED_HOSTS has no effect while BYWARD_CIMD is false"},
		{"CIMD hosts with CIMD off, by flag", []string{"--cimd=false", "--cimd-trusted-hosts=claude.ai"}, slices.Clone(base),
			"--cimd-trusted-hosts has no effect while --cimd is false"},
		{"app roles with app tokens off, by env", nil, append(slices.Clone(base), "BYWARD_APP_TOKENS=off", "BYWARD_APP_ROLES=reader"),
			"BYWARD_APP_ROLES set while BYWARD_APP_TOKENS=off: they configure app-only callers; set BYWARD_APP_TOKENS=entra"},
		{"app roles with app tokens off, by flag", []string{"--app-tokens=off", "--app-roles=reader"}, slices.Clone(base),
			"--app-roles set while --app-tokens=off: they configure app-only callers; set --app-tokens=entra"},
		{"the other IdP's setting, by env", nil, append(slices.Clone(base), "BYWARD_OIDC_SCOPES=openid"), "BYWARD_OIDC_SCOPES cannot be used with BYWARD_IDP=entra: they configure the oidc IdP; remove them, or set BYWARD_IDP to match"},
		{"the other IdP's setting, by flag", []string{"--idp=entra", "--oidc-scopes=openid"}, slices.Clone(base), "--oidc-scopes cannot be used with --idp=entra: they configure the oidc IdP; remove them, or set --idp to match"},
		{"a setting the IdP requires, by env", nil, append(noTenant(slices.Clone(base)), "BYWARD_IDP=entra"),
			"BYWARD_ENTRA_TENANT is required with BYWARD_IDP=entra (or set BYWARD_INSECURE_NO_AUTH to try the proxy without sign-in)"},
		{"a setting the IdP requires, by flag", []string{"--idp=entra"}, noTenant(slices.Clone(base)),
			"BYWARD_ENTRA_TENANT is required with --idp=entra (or set BYWARD_INSECURE_NO_AUTH to try the proxy without sign-in)"},
		{"no authentication on a public address, by env", nil, append(slices.Clone(anon), "BYWARD_LISTEN=0.0.0.0:8080"), "BYWARD_INSECURE_NO_AUTH: BYWARD_LISTEN must be a loopback address"},
		{"no authentication on a public address, by flag", []string{"--insecure-no-auth", "--listen=0.0.0.0:8080"}, without("BYWARD_INSECURE_NO_AUTH")(slices.Clone(anon)),
			"--insecure-no-auth: --listen must be a loopback address"},
		{"an upstream URL refused for its form, by env", nil, append(noURL(slices.Clone(base)), "BYWARD_UPSTREAM_URL=ftp://u/mcp"), "BYWARD_UPSTREAM_URL: want an absolute http(s) URL such as "},
		{"an upstream URL refused for its form, by flag", []string{"--upstream-url=ftp://u/mcp"}, noURL(slices.Clone(base)), "--upstream-url: want an absolute http(s) URL such as "},
		{"a resource documentation URL refused for its form, by env", nil, append(slices.Clone(base), "BYWARD_RESOURCE_DOCUMENTATION=ftp://docs.example.com"),
			"BYWARD_RESOURCE_DOCUMENTATION: want an absolute http(s) URL such as "},
		{"a resource documentation URL refused for its form, by flag", []string{"--resource-documentation=ftp://docs.example.com"}, slices.Clone(base),
			"--resource-documentation: want an absolute http(s) URL such as "},
		{"TLS with an http public URL, by env", []string{"--dev"}, append(noPublicURL(slices.Clone(base)), "BYWARD_PUBLIC_URL=http://127.0.0.1:8080/mcp",
			"BYWARD_TLS_CERT_FILE=/run/tls/tls.crt", "BYWARD_TLS_KEY_FILE=/run/tls/tls.key"), "BYWARD_TLS_CERT_FILE: TLS on the listener needs an https BYWARD_PUBLIC_URL;"},
		{"TLS with an http public URL, by flag", []string{"--dev", "--public-url=http://127.0.0.1:8080/mcp", "--tls-cert-file=/run/tls/tls.crt", "--tls-key-file=/run/tls/tls.key"},
			noPublicURL(slices.Clone(base)), "--tls-cert-file: TLS on the listener needs an https --public-url;"},
		{"PostgreSQL beside a stdio upstream, by env", nil, stdioBase(stdioCommand, "BYWARD_STORE_POSTGRES_DSN_FILE="+dsnFile),
			"BYWARD_STORE_POSTGRES_DSN_FILE: the PostgreSQL store is for several replicas"},
		{"PostgreSQL beside a stdio upstream, by flag", []string{"--store-postgres-dsn-file=" + dsnFile}, stdioBase(stdioCommand),
			"--store-postgres-dsn-file: the PostgreSQL store is for several replicas"},
		{"On-Behalf-Of's header beside a stdio upstream, by env", nil, stdioBase(stdioCommand, "BYWARD_OBO_HEADER=X-Token"),
			"BYWARD_OBO_HEADER: a stdio upstream gets its downstream token from its token socket (BYWARD_DOWNSTREAM_TOKEN_SOCKET), not a header; leave BYWARD_OBO_HEADER unset"},
		{"On-Behalf-Of's header beside a stdio upstream, by flag", []string{"--obo-header=X-Token"}, stdioBase(stdioCommand),
			"--obo-header: a stdio upstream gets its downstream token from its token socket (BYWARD_DOWNSTREAM_TOKEN_SOCKET), not a header; leave --obo-header unset"},
		{"On-Behalf-Of in the credential's header, by env", nil, append(slices.Clone(base), "BYWARD_UPSTREAM_CREDENTIAL_FILE=/run/secrets/entra",
			"BYWARD_UPSTREAM_CREDENTIAL_HEADER=X-Same", "BYWARD_OBO_SCOPES="+scope, "BYWARD_OBO_HEADER=X-Same"),
			"BYWARD_OBO_HEADER names the header that already carries the operator's upstream credential (BYWARD_UPSTREAM_CREDENTIAL_HEADER)"},
		{"On-Behalf-Of in the credential's header, by flag", []string{"--upstream-credential-file=/run/secrets/entra", "--upstream-credential-header=X-Same",
			"--obo-scopes=" + scope, "--obo-header=X-Same"}, slices.Clone(base),
			"--obo-header names the header that already carries the operator's upstream credential (--upstream-credential-header)"},
		{"a plain identity header for the assertion, by env", nil, append(slices.Clone(base), "BYWARD_ASSERTION_HEADER=X-Byward-Subject"),
			"BYWARD_ASSERTION_HEADER: want "},
		{"a plain identity header for the assertion, by flag", []string{"--assertion-header=X-Byward-Subject"}, slices.Clone(base),
			"--assertion-header: want "},
		{"a stdio environment file that is not KEY=VALUE lines, by env", nil, stdioBase(stdioCommand, "BYWARD_UPSTREAM_ENV_FILE=/run/secrets/bad-env"),
			"BYWARD_UPSTREAM_ENV_FILE: want KEY=VALUE lines, each key once"},
		{"a stdio environment file that is not KEY=VALUE lines, by flag", []string{"--upstream-env-file=/run/secrets/bad-env"}, stdioBase(stdioCommand),
			"--upstream-env-file: want KEY=VALUE lines, each key once"},
		{"an upstream credential beside a stdio upstream, by env", nil, stdioBase(stdioCommand, "BYWARD_UPSTREAM_CREDENTIAL_FILE=/run/secrets/entra"),
			"BYWARD_UPSTREAM_CREDENTIAL_FILE is for an HTTP upstream; give a stdio upstream its credential with BYWARD_UPSTREAM_ENV_FILE"},
		{"an upstream credential beside a stdio upstream, by flag", []string{"--upstream-credential-file=/run/secrets/entra"}, stdioBase(stdioCommand),
			"--upstream-credential-file is for an HTTP upstream; give a stdio upstream its credential with BYWARD_UPSTREAM_ENV_FILE"},
		{"a client denylist entry refused for its form, by env", nil, append(slices.Clone(base), "BYWARD_CLIENT_DENYLIST=https://user:pw@app.example/"),
			"BYWARD_CLIENT_DENYLIST: want "},
		{"a client denylist entry refused for its form, by flag", []string{"--client-denylist=https://user:pw@app.example/"}, slices.Clone(base),
			"--client-denylist: want "},
		{"no authentication with a public URL elsewhere, by env", nil, append(noPublicURL(slices.Clone(anon)), "BYWARD_PUBLIC_URL=https://mcp.example.com/mcp"),
			"BYWARD_INSECURE_NO_AUTH: BYWARD_PUBLIC_URL must be a loopback URL"},
		{"no authentication with a public URL elsewhere, by flag", []string{"--insecure-no-auth", "--public-url=https://mcp.example.com/mcp"},
			noPublicURL(without("BYWARD_INSECURE_NO_AUTH")(slices.Clone(anon))), "--insecure-no-auth: --public-url must be a loopback URL"},
		{"no authentication with a gate, by env", nil, append(slices.Clone(anon), "BYWARD_GATE_ROLES=reader"), "BYWARD_INSECURE_NO_AUTH cannot be combined with BYWARD_GATE_ROLES"},
		{"no authentication with a gate, by flag", []string{"--insecure-no-auth", "--gate-roles=reader"}, without("BYWARD_INSECURE_NO_AUTH")(slices.Clone(anon)),
			"--insecure-no-auth cannot be combined with --gate-roles"},
		{"no authentication with an allowed origin elsewhere, by env", nil, append(slices.Clone(anon), "BYWARD_ALLOWED_ORIGINS=https://app.example.com"),
			"BYWARD_ALLOWED_ORIGINS: want only loopback origins with BYWARD_INSECURE_NO_AUTH"},
		{"no authentication with an allowed origin elsewhere, by flag", []string{"--insecure-no-auth", "--allowed-origins=https://app.example.com"}, without("BYWARD_INSECURE_NO_AUTH")(slices.Clone(anon)),
			"--allowed-origins: want only loopback origins with --insecure-no-auth"},
		{"no authentication with an allowed host elsewhere, by env", nil, append(slices.Clone(anon), "BYWARD_ALLOWED_HOSTS=mcp.example.com"),
			"BYWARD_ALLOWED_HOSTS: want only loopback hosts with BYWARD_INSECURE_NO_AUTH"},
		{"no authentication with an allowed host elsewhere, by flag", []string{"--insecure-no-auth", "--allowed-hosts=mcp.example.com"}, without("BYWARD_INSECURE_NO_AUTH")(slices.Clone(anon)),
			"--allowed-hosts: want only loopback hosts with --insecure-no-auth"},
		{"no Entra credential, by env", nil, append(without("BYWARD_ENTRA_CLIENT_SECRET_FILE")(slices.Clone(base)), "BYWARD_IDP=entra"),
			"BYWARD_ENTRA_CLIENT_SECRET_FILE, BYWARD_ENTRA_CLIENT_CERTIFICATE_FILE or BYWARD_ENTRA_FEDERATED_TOKEN_FILE is required with BYWARD_IDP=entra"},
		{"no Entra credential, by flag", []string{"--idp=entra"}, without("BYWARD_ENTRA_CLIENT_SECRET_FILE")(slices.Clone(base)),
			"BYWARD_ENTRA_CLIENT_SECRET_FILE, BYWARD_ENTRA_CLIENT_CERTIFICATE_FILE or BYWARD_ENTRA_FEDERATED_TOKEN_FILE is required with --idp=entra"},
		{"no OIDC credential, by env", nil, without("BYWARD_OIDC_CLIENT_SECRET_FILE")(slices.Clone(oidcBase)),
			"BYWARD_OIDC_CLIENT_SECRET_FILE or BYWARD_OIDC_CLIENT_KEY_FILE is required with BYWARD_IDP=keycloak"},
		{"no OIDC credential, by flag", []string{"--idp=keycloak"}, without("BYWARD_OIDC_CLIENT_SECRET_FILE", "BYWARD_IDP")(slices.Clone(oidcBase)),
			"BYWARD_OIDC_CLIENT_SECRET_FILE or BYWARD_OIDC_CLIENT_KEY_FILE is required with --idp=keycloak"},
		{"app tokens with another IdP, by env", nil, append(slices.Clone(oidcBase), "BYWARD_APP_TOKENS=entra", "BYWARD_APP_ROLES=reader"),
			"BYWARD_APP_TOKENS=entra cannot be used with BYWARD_IDP=keycloak: app-only tokens are Entra's (ADR-0022 §1); remove it, or set BYWARD_IDP=entra"},
		{"app tokens with another IdP, by flag", []string{"--app-tokens=entra", "--idp=keycloak", "--app-roles=reader"}, without("BYWARD_IDP")(slices.Clone(oidcBase)),
			"--app-tokens=entra cannot be used with --idp=keycloak: app-only tokens are Entra's (ADR-0022 §1); remove it, or set --idp=entra"},
		{"app tokens without app roles, by env", nil, append(slices.Clone(base), "BYWARD_APP_TOKENS=entra"), "BYWARD_APP_ROLES is required with BYWARD_APP_TOKENS=entra"},
		{"app tokens without app roles, by flag", []string{"--app-tokens=entra", "--app-roles="}, slices.Clone(base), "--app-roles is required with --app-tokens=entra"},
		{"a setting the IdP requires given empty, by flag", []string{"--idp=entra", "--entra-tenant="}, noTenant(slices.Clone(base)), "--entra-tenant is required with --idp=entra"},
		{"a setting the IdP requires, no authentication by flag", []string{"--idp=entra", "--insecure-no-auth=false"}, noTenant(slices.Clone(base)),
			"BYWARD_ENTRA_TENANT is required with --idp=entra (or set --insecure-no-auth to try the proxy without sign-in)"},
		{"no Entra credential, the federated token file given empty, by flag", []string{"--idp=entra", "--entra-federated-token-file="}, without("BYWARD_ENTRA_CLIENT_SECRET_FILE")(slices.Clone(base)),
			"BYWARD_ENTRA_CLIENT_SECRET_FILE, BYWARD_ENTRA_CLIENT_CERTIFICATE_FILE or --entra-federated-token-file is required with --idp=entra"},
		{"no Entra credential, no authentication by flag", []string{"--idp=entra", "--insecure-no-auth=false"}, without("BYWARD_ENTRA_CLIENT_SECRET_FILE")(slices.Clone(base)),
			"BYWARD_ENTRA_CLIENT_SECRET_FILE, BYWARD_ENTRA_CLIENT_CERTIFICATE_FILE or BYWARD_ENTRA_FEDERATED_TOKEN_FILE is required with --idp=entra (or set --insecure-no-auth to try the proxy without sign-in)"},
		{"no authentication on a listen address without a port, by env", nil, append(slices.Clone(anon), "BYWARD_LISTEN=127.0.0.1"),
			"BYWARD_INSECURE_NO_AUTH: BYWARD_LISTEN must be a loopback host:port"},
		{"no authentication on a listen address without a port, by flag", []string{"--insecure-no-auth", "--listen=127.0.0.1"}, without("BYWARD_INSECURE_NO_AUTH")(slices.Clone(anon)),
			"--insecure-no-auth: --listen must be a loopback host:port"},
		{"a counter file beside PostgreSQL, by env", nil, append(slices.Clone(base), "BYWARD_STORE_POSTGRES_DSN_FILE="+dsnFile, "BYWARD_STORE_COUNTER_FILE=/var/lib/c"),
			"BYWARD_STORE_POSTGRES_DSN_FILE and BYWARD_STORE_COUNTER_FILE: the counter file belongs to the SQLite store"},
		{"a counter file beside PostgreSQL, by flag", []string{"--store-postgres-dsn-file=" + dsnFile, "--store-counter-file=/var/lib/c"}, slices.Clone(base),
			"--store-postgres-dsn-file and --store-counter-file: the counter file belongs to the SQLite store"},
		{"a stdio setting with an HTTP upstream, the stdio selector given empty", []string{"--upstream-command=", "--stdio-max-processes=4"}, slices.Clone(base),
			"--stdio-max-processes is set, but the upstream is HTTP: it applies only to a stdio upstream (BYWARD_UPSTREAM_COMMAND)"},
		{"an HTTP setting with a stdio upstream, the HTTP selector given empty", []string{"--upstream-url=", "--assertion-header=X-A"}, stdioBase(stdioCommand),
			"--assertion-header is set, but the upstream is stdio: it applies only to an HTTP upstream (BYWARD_UPSTREAM_URL)"},
		{"no upstream, the URL given empty", []string{"--upstream-url="}, noURL(slices.Clone(base)), "--upstream-url is required (or BYWARD_UPSTREAM_COMMAND, or a command after --)"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, _, err := Load(tc.args, tc.env, files)
			if !isConfigError(err) || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want it to say %q", err, tc.want)
			}
		})
	}
}

// The relaxation of a stdio upstream without authentication names the process bound as the operator
// gave it (#623), as a refusal does.
func TestTheNoAuthStdioRelaxationNamesTheProcessBoundAsGiven(t *testing.T) {
	stdio := append(without("BYWARD_UPSTREAM_URL")(slices.Clone(anon)), stdioCommand)
	for _, tc := range []struct {
		name string
		args []string
		env  []string
		want string
	}{
		{"by env", nil, append(slices.Clone(stdio), "BYWARD_STDIO_MAX_PROCESSES=16"), "bounded only by BYWARD_STDIO_MAX_PROCESSES,"},
		{"by flag", []string{"--stdio-max-processes=16"}, stdio, "bounded only by --stdio-max-processes,"},
		{"left at its default", nil, stdio, "bounded only by BYWARD_STDIO_MAX_PROCESSES,"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, _, err := Load(tc.args, tc.env, filesPlusEmptyAndBlank)
			if err != nil {
				t.Fatal(err)
			}
			if !slices.ContainsFunc(c.Relaxations, func(r string) bool { return strings.Contains(r, tc.want) }) {
				t.Fatalf("relaxations = %q, want one saying %q", c.Relaxations, tc.want)
			}
		})
	}
}

// Values resolved over a registry of their own name its settings from it, given or left at its
// default, which the global registry (lookup) does not hold; a setting they do not hold is named from
// the global registry (#631).
func TestNameAsGivenNamesASettingFromItsValuesOwnRegistryBeforeTheGlobalOne(t *testing.T) {
	probe := Setting{Name: "probe-secret", shape: secretShape, Group: GroupKeysAndStore}
	for _, tc := range []struct {
		name, setting string
		args          []string
		want          string
	}{
		{"its own setting left at its default", "probe-secret", nil, "BYWARD_PROBE_SECRET_FILE"},
		{"its own setting given", "probe-secret", []string{"--probe-secret-file=/run/secrets/p"}, "--probe-secret-file"},
		{"a setting only the global registry holds", "public-url", nil, "BYWARD_PUBLIC_URL"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			v, err := resolve([]Setting{probe}, tc.args, nil, func(string) ([]byte, error) { return []byte("p"), nil }, nil)
			if err != nil {
				t.Fatal(err)
			}
			if got := v.NameAsGiven(tc.setting); got != tc.want {
				t.Errorf("NameAsGiven(%q) = %q, want %q", tc.setting, got, tc.want)
			}
		})
	}
}
