# Commands reference

`byward` with no command runs the proxy. The commands below read the same `BYWARD_*` environment
as the proxy ([settings](settings.md)), so run them with the proxy's configuration. They take no
setting flags; give settings through the environment. A stdio upstream given on the command line goes
after `--`, as for the proxy (`byward check --offline -- /usr/local/bin/server --flag`).
`byward --help` lists them.

| Command | What it does | Network | Exit codes |
|---|---|---|---|
| `byward check --offline [-- <command>]` | validates the configuration as the proxy does at startup | none | 0, 2 |
| `byward doctor [--json] [-- <command>]` | probes the running proxy as MCP clients do, and the IdP app | the public URL and Entra | 0, 2, 4, 8, 12 |
| `byward init entra --tenant <id>` | prints the `az` commands for the Entra app registration and a minimal env file | none | 0, 2 |
| `byward revoke-user <user key>` | ends one user's access ([hardening](../how-to/harden-a-deployment.md)) | the store | 0, 1, 2 |
| `byward revoke-all --yes` | ends every user's access ([hardening](../how-to/harden-a-deployment.md)) | the store | 0, 1, 2 |
| `byward jwks` | prints the identity assertion's public keys as a JWKS, for an upstream that loads them from a file ([identity assertion](../how-to/identity-assertion.md)) | none | 0, 2 |

Decisions: [ADR-0020](../adr/0020-configuration.md) §7–8, [ADR-0021](../adr/0021-observability.md) §11,
[ADR-0013](../adr/0013-discovery-and-errors.md) §8, [ADR-0012](../adr/0012-entra-specifics.md) §10, §12.

## `byward check --offline`

Checks everything the proxy checks at startup that needs no network and writes nothing:

- the settings (unknown names, values, required settings);
- the sealing keys and the static clients file (optional while CIMD or DCR is on);
- the Entra settings and the access gate, and the Entra client certificate file if there is one
  (an RSA key of 2048 bits or more, its certificate; an expired certificate is a configuration
  error);
- the secret files' permissions, as at startup (relaxed with `--dev`);
- a stdio upstream's command (`BYWARD_UPSTREAM_COMMAND` or the command after `--`): it must be found
  and executable, as at startup; it is never started;
- the store paths: an existing state directory must be a directory (a missing one is created at
  startup), and the counter file's directory must exist (it is not created). Nothing is created.

It prints the warnings the proxy would log at startup (an empty access gate, generic consent
wording, a client secret or client certificate that expires within 30 days), then `configuration OK`. A problem is a
configuration error on standard error, exit code 2. `check` without `--offline` is refused, so that a
script written today keeps meaning the same thing.

## `byward doctor`

Run it where the proxy runs, with the same environment, while the proxy is running. It reaches the
proxy at `BYWARD_PUBLIC_URL`, as an MCP client would, and Entra at `login.microsoftonline.com`. It
sends no token to the proxy, and it calls no Microsoft Graph API.

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
| `proxy` | upstream | passes once the configuration loads: names the HTTP upstream, and the environment's HTTP proxy its requests go through (`HTTPS_PROXY`, `HTTP_PROXY`, `NO_PROXY`; by scheme and host only), or the stdio command that was found. A warning when Go refuses `HTTP_PROXY` because `REQUEST_METHOD` is set (its CGI guard, which `NO_PROXY` does not lift), or when the proxy setting's credentials hold an unescaped `/`, `?` or `#`, which Go then reads partly as the host. A proxy setting Go cannot parse is ignored without an error, so then no proxy is named. Doctor never reaches the upstream, and never starts a stdio process |
| `proxy` | upstream hop | shown only as a warning: the HTTP upstream is `http` and its host resolves to a public address, so the secrets each request carries (the identity assertion, the upstream credential, an On-Behalf-Of token) travel in clear. A host that does not resolve gets no warning. Also logged at startup, and by `check --offline` for an upstream given as an address |
| `proxy` | configuration | never fails; one warning per startup warning (an empty access gate, generic consent wording) |
| `proxy` | protected resource metadata (path-inserted) | `/.well-known/oauth-protected-resource<path>` answers 200 with `resource` equal to the public URL and our issuer first in `authorization_servers` |
| `proxy` | protected resource metadata (root) | the same at `/.well-known/oauth-protected-resource` |
| `proxy` | authorization server metadata (RFC 8414), (OpenID) | both documents name our issuer, `authorization_response_iss_parameter_supported: true`, `S256`, and a `revocation_endpoint` |
| `proxy` | unauthenticated MCP request | a POST without a token gets 401 whose `resource_metadata` is one of the URLs above and resolves |
| `proxy` | Host header | no response was 421; a reverse proxy that changes `Host` shows up here |
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

With `BYWARD_ENTRA_TENANT=organizations` there is no home tenant to send a client-credentials request
to (Microsoft documents that request only with a tenant ID or domain), so the credential check is a
skip with the `az` commands that check it by hand.

With `BYWARD_INSECURE_NO_AUTH` there is no discovery and no IdP; doctor reports one warning.

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
5. a client secret (`--append` keeps existing credentials; at most two years), written straight to
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
