# Commands reference

`byward` with no command runs the proxy. The commands below read the same `BYWARD_*` environment
as the proxy ([settings](settings.md)), so run them with the proxy's configuration;
`downstream-token` is the exception: it reads only `BYWARD_DOWNSTREAM_TOKEN_SOCKET`. They take no
setting flags; give settings through the environment. A stdio upstream given on the command line goes
after `--`, as for the proxy (`byward check --offline -- /usr/local/bin/server --flag`).
`byward --help` lists them.

| Command | What it does | Network | Exit codes |
|---|---|---|---|
| `byward check --offline [-- <command>]` | validates the configuration as the proxy does at startup | none | 0, 2 |
| `byward doctor [--json] [-- <command>]` | probes the running proxy as MCP clients do, and the IdP app | the public URL and the IdP | 0, 2, 4, 8, 12 |
| `byward init entra --tenant <id>` | prints the `az` commands for the Entra app registration and a minimal env file | none | 0, 2 |
| `byward revoke-user <user key>` | ends one user's access ([below](#byward-revoke-user)) | the store | 0, 1, 2 |
| `byward revoke-all --yes` | ends every user's access ([below](#byward-revoke-all)) | the store | 0, 1, 2 |
| `byward store new-epoch --yes` | after restoring the PostgreSQL store: starts a new store epoch, so refresh tokens from before it are refused ([below](#byward-store-new-epoch)) | the store | 0, 1, 2 |
| `byward jwks` | prints the identity assertion's public keys as a JWKS, for an upstream that loads them from a file ([below](#byward-jwks)) | none | 0, 2 |
| `byward downstream-token [--json]` | run by a stdio upstream process or one of its descendants: prints its user's On-Behalf-Of token from `BYWARD_DOWNSTREAM_TOKEN_SOCKET`, for a server that takes a credential command ([below](#byward-downstream-token)) | the token socket | 0, 1, 2 |

Decisions: [ADR-0020](../adr/0020-configuration.md) §7–8, [ADR-0021](../adr/0021-observability.md) §11,
[ADR-0013](../adr/0013-discovery-and-errors.md) §8, [ADR-0012](../adr/0012-entra-specifics.md) §10, §12.

## `byward check --offline`

Checks everything the proxy checks at startup that needs no network and writes nothing:

- the settings (unknown names, values, required settings);
- the sealing keys and the static clients file (optional while CIMD or DCR is on);
- the IdP settings (Entra or `oidc`) and the access gate, and the IdP credential file if there is one:
  the Entra client certificate (an RSA key of 2048 bits or more, its certificate; an expired
  certificate is a configuration error) or the `oidc` client key;
- the secret files' permissions, as at startup (relaxed with `--dev`);
- a stdio upstream's command (`BYWARD_UPSTREAM_COMMAND` or the command after `--`): it must be found
  and executable, as at startup; it is never started;
- the store: with SQLite, its paths (an existing state directory must be a directory, a missing one
  is created at startup, and the counter file's directory must exist, it is not created); with
  PostgreSQL, the DSN as startup parses it, including the `sslmode=verify-full` rule, without
  connecting. Nothing is created;
- with `BYWARD_TLS_CERT_FILE`, the TLS certificate and key: readable, a matching pair, and valid now.

It prints the warnings the proxy would log at startup (an empty access gate, generic consent
wording, a client secret or client certificate that expires within 30 days, a TLS certificate that
expires within 30 days or names neither the public URL's host nor an allowed host, and with
PostgreSQL the reminder that every replica needs the same keys), then `configuration OK`. A problem is a
configuration error on standard error, exit code 2. `check` without `--offline` is refused, so that a
script written today keeps meaning the same thing.

## `byward doctor`

Run it where the proxy runs, with the same environment, while the proxy is running. It reaches the
proxy at `BYWARD_PUBLIC_URL`, as an MCP client would, and the IdP: Entra at
`login.microsoftonline.com`, or an `oidc` IdP's discovery document and token endpoint. It sends no
token to the proxy, and it calls no Microsoft Graph API.

A configuration error stops doctor before any check, with exit code 2. Otherwise it prints one line
per check, with the fix below each problem:

```text
pass  proxy  protected resource metadata (path-inserted): https://mcp.example.com/.well-known/oauth-protected-resource/mcp names resource https://mcp.example.com/mcp and issuer https://mcp.example.com
fail  idp    entra app and credential: Entra rejected the client secret (AADSTS7000215)
             fix: the file named by BYWARD_ENTRA_CLIENT_SECRET_FILE must hold the secret's value, not its ID; ...
```

### Checks

| Class | Check | Passes when |
|---|---|---|
| `proxy` | TLS certificate expiry | with `BYWARD_TLS_CERT_FILE`: the chain's first certificate to expire is more than 30 days from expiry (a warning at 30 days or less; a failure when the files are not valid yet or cannot be served) |
| `proxy` | TLS certificate names | with `BYWARD_TLS_CERT_FILE`: the certificate covers the public URL's host or a `BYWARD_ALLOWED_HOSTS` entry (otherwise a warning: fine when only an ingress connects and verifies another name) |
| `proxy` | upstream | passes once the configuration loads: names the HTTP upstream, and the environment's HTTP proxy its requests go through (`HTTPS_PROXY`, `HTTP_PROXY`, `NO_PROXY`; by scheme and host only), or the stdio command that was found. A warning when Go refuses `HTTP_PROXY` because `REQUEST_METHOD` is set (its CGI guard, which `NO_PROXY` does not lift), or when the proxy setting's credentials hold an unescaped character (such as `/`, `?` or `#`), which Go then reads partly as the host, or cannot read a host from at all. A proxy setting Go cannot parse is ignored without an error, so then no proxy is named. Doctor never reaches the upstream, and never starts a stdio process |
| `proxy` | upstream hop | shown only as a warning: the HTTP upstream is `http` and its host resolves to a public address, so the secrets each request carries (the identity assertion, the upstream credential, an On-Behalf-Of token) travel in clear. A host that does not resolve gets no warning. Also logged at startup, and by `check --offline` for an upstream given as an address |
| `proxy` | identity headers | with `BYWARD_IDENTITY_HEADERS` and an HTTP upstream: the upstream's host resolves only to loopback, private, link-local, shared (CGNAT) or unspecified addresses (a warning when it has a public address or does not resolve). A hint, not a guarantee: doctor sees addresses, not who can reach them |
| `proxy` | configuration | never fails; one warning per startup warning (an empty access gate, generic consent wording), and with the PostgreSQL store the reminder that every replica needs the same keys |
| `proxy` | protected resource metadata (path-inserted) | `/.well-known/oauth-protected-resource<path>` answers 200 with `resource` equal to the public URL and our issuer first in `authorization_servers` |
| `proxy` | protected resource metadata (root) | the same at `/.well-known/oauth-protected-resource` |
| `proxy` | authorization server metadata (RFC 8414), (OpenID) | both documents name our issuer, `authorization_response_iss_parameter_supported: true`, `S256`, and a `revocation_endpoint` |
| `proxy` | unauthenticated MCP request | a POST without a token gets 401 whose `resource_metadata` is one of the URLs above and resolves |
| `proxy` | Host header | no response was 421; a reverse proxy that changes `Host` shows up here |
| `proxy` | identity assertion keys (discovery) | with an HTTP upstream: the OpenID discovery document names byward's issuer and a `jwks_uri` that serves the key signing assertions, as a verifier using only discovery (MCP Toolbox) needs |
| `proxy` | authentication | only with `BYWARD_INSECURE_NO_AUTH`: always a warning, since there is no discovery and no IdP to check |
| `idp` | discovery | with an `oidc` IdP or preset: the discovery document at `BYWARD_OIDC_ISSUER` names that issuer exactly |
| `idp` | client credential | with an `oidc` IdP or preset: a token request with a made-up authorization code is answered `invalid_grant` with a 4xx status, so the IdP accepted the client ID and the secret or key and refused only the code. `invalid_client`, `unauthorized_client`, or `access_denied` with 401 (Auth0) fail, with a fix naming the credential's setting; any other answer is a warning. The IdP's `error_description` is never shown (an IdP may echo the request into it). Needs no user. Keycloak, Okta, Auth0 and Google were measured to check the client before the code; for plain `oidc` a pass says that order is assumed |
| `idp` | entra tenant | the tenant's v2 discovery document exists and names its v2 issuer |
| `idp` | entra signing keys | the tenant's key set has a signing key |
| `idp` | entra app and credential | a client-credentials request for `api://<client-id>/.default` succeeds: Entra accepted the tenant, the client ID and the secret. Needs no app permission. |
| `idp` | entra access token | that token verifies, is version 2.0 (`requestedAccessTokenVersion: 2`) and has `aud` = the client ID |
| `idp` | entra idtyp claim | the token carries `idtyp=app` (otherwise a warning, or a failure while `BYWARD_APP_TOKENS=entra`: app-only callers need it, ADR-0022) |
| `idp` | entra redirect URI | always a skip: only Microsoft Graph can read it. The fix is the `az ad app show` command that checks it; a wrong redirect URI fails the first sign-in with AADSTS50011 |
| `idp` | entra app roles | always a skip, for the same reason; the fix lists the access gate's roles the app must define, and the app roles for app-only callers (`BYWARD_APP_ROLES`) |
| `idp` | client secret expiry | `BYWARD_ENTRA_CLIENT_SECRET_EXPIRES_AT` is more than 30 days away (a warning at 30 days or less, a failure once passed, a skip when unset) |
| `idp` | client certificate expiry | with `BYWARD_ENTRA_CLIENT_CERTIFICATE_FILE` instead of a secret: the certificate's own end date is more than 30 days away (a warning at 30 days or less, a failure once passed) |

With assignment required on the app (as `init entra` sets it, and
[hardening](../how-to/harden-a-deployment.md) recommends), Entra answers the client-credentials request
with AADSTS501051 unless the app holds a role on itself. Doctor then reports the credential as
passed, since Entra checked it before refusing, and the access token as a skip, with the
`az ad app show` command that checks its version by hand.

With `BYWARD_INSECURE_NO_AUTH` there is no discovery and no IdP: doctor runs the TLS certificate,
`upstream`, `upstream hop` and `configuration` checks, then reports `authentication` as a warning.

### Statuses and exit codes

| Status | Meaning |
|---|---|
| `pass` | checked and right |
| `warn` | works, but look at it; does not change the exit code |
| `skip` | could not be checked; the message says why and the fix how to check by hand |
| `fail` | wrong; the fix names what to change |

| Exit code | Meaning |
|---|---|
| 0 | no check failed (warnings and skips allowed) |
| 2 | configuration error; no check ran |
| 4 | a `proxy` check failed |
| 8 | an `idp` check failed |
| 12 | both (4 OR 8) |

### `--json`

One JSON document on standard output, the checks in the order they ran. Fields are only ever added.

```json
{
  "checks": [
    {
      "class": "idp",
      "name": "entra app and credential",
      "status": "fail",
      "message": "Entra rejected the client secret (AADSTS7000215)",
      "fix": "the file named by BYWARD_ENTRA_CLIENT_SECRET_FILE must hold the secret's value, not its ID; ..."
    }
  ]
}
```

| Field | Type | Values |
|---|---|---|
| `class` | string | `proxy`, `idp` |
| `name` | string | a check name from the table above |
| `status` | string | `pass`, `warn`, `skip`, `fail` |
| `message` | string | what doctor found |
| `fix` | string, omitted when empty | what to change, or how to check by hand |

## `byward init entra`

```sh
byward init entra --tenant <tenant-id> [--public-url <url>] [--upstream-url <url>] [--secret-years 1|2] [--credential secret|certificate] > byward-entra.sh
```

Prints a shell script; byward runs none of it, calls no API and never sees the client secret.
`--public-url` and `--upstream-url` default to `BYWARD_PUBLIC_URL` and `BYWARD_UPSTREAM_URL`. Review
the script, then run it with the Azure CLI signed in to the tenant (`az login --tenant <tenant-id>`;
the script stops if `az` is signed in elsewhere). It follows
[the Entra quickstart](../how-to/quickstart-entra.md) step 1 and adds what app-only callers need
(ADR-0022 §6):

1. a single-tenant app registration with the redirect URI `https://<public host>/callback/entra`;
2. one Microsoft Graph request: the Application ID URI `api://<client-id>`, the `access_as_user`
   scope with `requestedAccessTokenVersion: 2`, the app roles `byward.user` (users and groups) and
   `byward.app` (applications), and the `idtyp` optional claim on access tokens;
3. the OpenID Connect permissions;
4. the service principal, with **assignment required**: only users, groups and applications you
   assign can sign in;
5. a client secret (the script's `az ad app credential reset --append` keeps existing credentials; at
   most two years), written straight to
   the `0600` file `entra-client-secret`; or, with `--credential certificate`, an RSA 2048 key and a
   self-signed certificate valid for `--secret-years` years, made locally with `openssl`, written together to the `0600` file
   `entra-client-certificate.pem`, with only the public certificate uploaded
   ([certificate how-to](../how-to/entra-certificate.md));
6. `byward.env` (`0600`): `BYWARD_PUBLIC_URL`, `BYWARD_UPSTREAM_URL`, `BYWARD_ENTRA_TENANT`,
   `BYWARD_ENTRA_CLIENT_ID`, `BYWARD_ENTRA_CLIENT_SECRET_FILE`, and
   `BYWARD_ENTRA_CLIENT_SECRET_EXPIRES_AT` (the date `--secret-years` from today, so the expiry
   warning works from the first start); with a certificate, `BYWARD_ENTRA_CLIENT_CERTIFICATE_FILE`
   instead of both (byward reads the certificate's own end date). Without an upstream URL, `BYWARD_UPSTREAM_URL` is left empty
   for you to fill in.

Each run creates a new app registration. Afterwards, assign users or groups to the enterprise
application with the `byward.user` role, create a [sealing key](../how-to/sealing-keys.md), start the
proxy and run `byward doctor`.

## `byward revoke-user`

```sh
byward revoke-user <user key>
```

Deletes every grant of one user and records a cut-off, so every proxy using the same store refuses
the user's refresh tokens at once and their access tokens at its next deny-list sync, within
seconds. The user key is the one the audit records show as `user_key`: with Entra, `tid:oid` (the
tenant and object IDs); with an `oidc` IdP, the value of its subject claim (`BYWARD_OIDC_SUBJECT_CLAIM`,
`sub` by default). It runs beside a running proxy. A key that is not a user key of the configured
IdP exits 2; a store that cannot be opened or written exits 1. The revocation is audited as
`grant_revoked` with the reason `operator revoke-user` ([observability](observability.md)).

## `byward revoke-all`

```sh
byward revoke-all --yes
```

The same for every user at once, for incident response: everyone signs in again. `--yes` is required.
Audited as `grant_revoked` with the reason `operator revoke-all`.

## `byward store new-epoch`

```sh
byward store new-epoch --yes
```

For the PostgreSQL store, after a `pg_restore` or a point-in-time recovery: starts a new store epoch,
so refresh tokens issued before it are refused and their users sign in again, and forgets every
remembered consent. Running replicas adopt the epoch at once. It prints the new epoch and is audited as
`store_restored` with the reason `operator new-epoch`. With the SQLite store it exits 2: SQLite finds a
restore by itself at startup ([state](../how-to/state.md#restore-detection)). See
[PostgreSQL](../how-to/postgres.md#backup-and-restore).

## `byward jwks`

```sh
byward jwks > byward-jwks.json
```

Prints the identity assertion's public keys as a JWKS, for an upstream that loads them from a file
instead of the JWKS URL. Run it again after every assertion key rotation
([identity assertion](../how-to/identity-assertion.md)).

## `byward downstream-token`

```sh
byward downstream-token [--json]
```

Run by a stdio upstream process or one of its descendants. It reads only
`BYWARD_DOWNSTREAM_TOKEN_SOCKET`, asks that socket for its user's On-Behalf-Of token and prints it;
`--json` prints the token with its `expires_at`. On an error answer it prints the error code alone on
standard error and exits 1 ([On-Behalf-Of §5](../how-to/downstream-apis.md#5-a-stdio-upstream)).

## Proxy actions

These are flags of the proxy itself (`byward` with no command), read with the same settings:

| Action | What it does | Exit codes |
|---|---|---|
| `byward --help` | prints the settings and the commands | 0 |
| `byward --version [--json]` | prints the version, the source revision and the Go version; with `--json`, an object with `version`, `revision`, `time`, `modified` (only when set) and `go_version` | 0 |
| `byward --print-config` | prints every setting as `NAME=value (source)`, the source being `flag`, `env`, `file` or `default`; secrets show as `<redacted>` | 0, 2 |

