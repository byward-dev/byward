# Static clients file

Static clients are MCP clients the operator registers in advance (ADR-0008). They are listed in one
JSON file, given by `BYWARD_STATIC_CLIENTS_FILE` (`--static-clients-file`), by default
`clients.json` in the data directory (`/var/lib/byward/clients.json`). The file is read
once at startup; a change needs a restart (ADR-0020 §9). Static clients are shown on the consent
page as trusted by the operator (ADR-0008 §8).

**The file is optional while CIMD or DCR is on** (both are by default), because apps can then
register themselves:

| CIMD or DCR | The default path is absent | The file lists no clients | A path you set is absent |
|---|---|---|---|
| on | starts, with no static clients | starts, with no static clients | startup error |
| both off | startup error | startup error | startup error |

A path you set must exist, so a typo stops startup instead of silently dropping your clients. A
file that exists but cannot be read is always an error. The startup log line `client sources`
shows the active sources, for example `static=0 cimd=true dcr=true`.

Field names follow RFC 7591. Unknown fields, trailing data after the JSON object and inline secrets
are startup errors, so a typo never silently weakens a client.

## Example

```json
{
  "clients": [
    {
      "client_id": "claude-code",
      "client_name": "Claude Code",
      "token_endpoint_auth_method": "none",
      "redirect_uris": ["http://localhost/callback", "http://127.0.0.1/callback"]
    },
    {
      "client_id": "nightly-report",
      "client_name": "Nightly report",
      "token_endpoint_auth_method": "private_key_jwt",
      "redirect_uris": ["https://reports.example.com/oauth/callback"],
      "jwks_file": "keys/nightly-report.jwks.json"
    },
    {
      "client_id": "intranet-portal",
      "token_endpoint_auth_method": "client_secret_basic",
      "redirect_uris": ["https://portal.example.com/mcp/callback"],
      "client_secret_file": "secrets/intranet-portal"
    }
  ]
}
```

## Fields

| Field | Required | Rules |
|---|---|---|
| `client_id` | yes | Printable ASCII without spaces, at most 255 characters, unique in the file. The value the client sends as `client_id`. |
| `client_name` | no | Shown on the consent page; defaults to `client_id`. At most 100 bytes of UTF-8, no control characters. |
| `token_endpoint_auth_method` | yes | `none` (public client, PKCE only), `private_key_jwt`, `client_secret_basic` or `client_secret_post`. There is no default. |
| `redirect_uris` | yes | 1 to 10 URIs, each at most 512 characters, following the redirect URI policy below. |
| `client_secret_file` | with a secret method | Path to a file holding the client secret (at least 32 bytes; a trailing newline is ignored). Only with `client_secret_basic` or `client_secret_post`. |
| `jwks` | with `private_key_jwt` | The client's public signing keys as an inline JWK Set. |
| `jwks_file` | with `private_key_jwt` | Path to a file holding that JWK Set. Give `jwks` or `jwks_file`, not both. |

Relative paths in `client_secret_file` and `jwks_file` are resolved against the directory of the
clients file.

**Secrets** are never written inline: a `client_secret` field is a startup error that points to
`client_secret_file`. Keep secret files readable only by the proxy (`0600`).

**Keys** for `private_key_jwt` must be public keys only (a private key is a startup error), at least
one must be usable for signing, and RSA keys need at least 2048 bits. The client signs its assertion
with the matching private key; the proxy checks `aud` (the token endpoint), a short `exp` and a
single-use `jti` (ADR-0008 §6).

## Redirect URI policy (ADR-0009)

- **https** URIs must match exactly what the client sends.
- **Loopback http** is allowed only on `localhost`, `127.0.0.1` and `[::1]`. Any port matches, so a
  client that picks a free port at sign-in works with one registered URI. The host is compared
  literally: `localhost` does not match `127.0.0.1`, so register both when a client may use either
  (Claude Code 2.1.229 sent `127.0.0.1`).
- No fragments, no user info, no wildcards, and the scheme in lower case.
- Other schemes, including custom app schemes, are refused.

## Limits

At most 1000 clients and 1 MiB per file. Errors name the client (or its position) and the field, and
never contain a secret.
