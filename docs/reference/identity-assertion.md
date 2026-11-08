# Identity assertion reference

What an HTTP upstream receives on every request, and how to verify it. Setup:
[identity assertion how-to](../how-to/identity-assertion.md). Decisions:
[ADR-0016](../adr/0016-identity-propagation.md). This contract is public interface: the RFC 9068
claims are fixed, and byward's own claims are only ever added to.

## On the wire

```http
Authorization: Bearer eyJhbGciOiJFUzI1NiIsImtpZCI6IjIwMjYtMTEtMDEiLCJ0eXAiOiJhdCtqd3QifQ...
```

The header is `BYWARD_ASSERTION_HEADER` (default `Authorization`), and the value is always
`Bearer <JWT>`. Every copy of that header sent by the client is removed first, and the client's own
token never reaches the upstream.

## The JWT

Header:

| Field | Value |
|---|---|
| `alg` | `ES256`, always |
| `typ` | `at+jwt` (RFC 9068 §2.1) |
| `kid` | the signing key's ID: its file name in `BYWARD_ASSERTION_KEYS_DIR` |

Claims:

| Claim | Always | Value |
|---|---|---|
| `iss` | yes | byward's issuer: the public URL's origin, e.g. `https://mcp.example.com` |
| `aud` | yes | `BYWARD_UPSTREAM_URL` exactly as configured, e.g. `http://mcp-upstream.internal:3001/mcp` |
| `sub` | yes | the user key: `tid:oid` for Entra, stable and opaque; for an app-only caller, its service principal's `tid:oid` |
| `client_id` | yes | the MCP client's ID at byward (a static ID, a CIMD URL or a DCR ID); for an app-only caller, its Entra application (client) ID |
| `principal_type` | yes | `user`, or `client` for a headless caller with an [app-only token](../how-to/app-tokens.md): check it before treating `sub` as a person |
| `iat` | yes | issued at, seconds |
| `exp` | yes | `iat` + 60 seconds |
| `jti` | yes | 128 random bits, base64url |
| `roles` | `roles` opted in (default) | the user's app roles, when they have any |
| `groups` | `groups` opted in | group IDs; left out under Entra groups overage, or when too many to fit |
| `email` | `email` opted in, and the IdP verified it or `BYWARD_ASSERTION_UNVERIFIED_EMAIL` is `true` | display only, never for authorization |
| `email_verified` | exactly when `email` is | `true` when the IdP vouched for the address; `false` when only `BYWARD_ASSERTION_UNVERIFIED_EMAIL` let it through (every Entra email) |
| `name` | `name` opted in | display only |

A claim the user has no value for is left out; it is never sent empty. An app-only caller's
assertion carries its app roles and never `groups`, `email`, `email_verified` or `name`. Roles and groups are as of
the user's last sign-in or token refresh, so they can be up to one hour old.

Example (from `internal/assertion/testdata/assertion.golden.json`; `jti` is random):

```json
{
  "aud": "http://upstream.internal:3001/mcp",
  "client_id": "https://claude.ai/oauth/claude-code-client-metadata",
  "email": "alex@contoso.example",
  "email_verified": true,
  "exp": 1794042060,
  "groups": ["22222222-2222-2222-2222-222222222222"],
  "iat": 1794042000,
  "iss": "https://mcp.example.com",
  "jti": "<random>",
  "name": "Alex",
  "principal_type": "user",
  "roles": ["byward.user"],
  "sub": "00000000-0000-0000-0000-000000000001:11111111-1111-1111-1111-111111111111"
}
```

## Keys

- JWKS at `/.well-known/jwks.json` on the public and the internal listener, `Cache-Control: public,
  max-age=300`, or exported with `byward jwks`. The internal listener is plain http, so its JWKS is
  safe only on the same host or under a NetworkPolicy and mesh mTLS
  ([how-to](../how-to/identity-assertion.md#2-point-the-upstream-at-the-public-keys)).
- The key whose ID sorts last signs. Older keys stay in the JWKS until you remove their files, so a
  rotation needs no change in the upstream.
- With an HTTP upstream, the authorization server metadata advertises the JWKS as `jwks_uri`, at
  `/.well-known/openid-configuration` and `/.well-known/oauth-authorization-server`, so a verifier
  that only uses OIDC discovery finds it (see [By discovery](#by-discovery)). The keys verify
  identity assertions only: proxy tokens are opaque `byw_` strings, so an MCP client has nothing
  to verify with them. With a stdio upstream there is no assertion and no `jwks_uri`.

## Verifying

Check the signature against the JWKS (ES256 only), `iss`, `aud`, and `exp` with a leeway of about
30 seconds. Check `typ` = `at+jwt` where the library allows it, so no other JWT signed by these keys
is mistaken for an assertion. Rely on `sub` for who the user is.

There is no replay cache: the 60-second lifetime and the per-upstream `aud` bound replay.

These examples are the verifiers byward's contract tests run (`internal/assertion/gosdk_contract_test.go`,
`scripts/assertion/`). Examples, not a library.

### Go: go-sdk

```go
import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/modelcontextprotocol/go-sdk/auth"
)

// keys is byward's /.well-known/jwks.json; audience is byward's BYWARD_UPSTREAM_URL.
func verifier(keys jose.JSONWebKeySet, audience string) auth.TokenVerifier {
	return func(_ context.Context, raw string, _ *http.Request) (*auth.TokenInfo, error) {
		tok, err := jwt.ParseSigned(raw, []jose.SignatureAlgorithm{jose.ES256})
		if err != nil || len(tok.Headers) != 1 || tok.Headers[0].ExtraHeaders["typ"] != "at+jwt" {
			return nil, auth.ErrInvalidToken
		}
		k := keys.Key(tok.Headers[0].KeyID)
		if len(k) != 1 {
			return nil, auth.ErrInvalidToken
		}
		var c jwt.Claims
		var extra struct {
			ClientID string   `json:"client_id"`
			Roles    []string `json:"roles"`
		}
		if err := tok.Claims(k[0].Key, &c, &extra); err != nil {
			return nil, auth.ErrInvalidToken
		}
		if err := c.ValidateWithLeeway(jwt.Expected{AnyAudience: jwt.Audience{audience}, Time: time.Now()}, 30*time.Second); err != nil {
			return nil, fmt.Errorf("%w: %v", auth.ErrInvalidToken, err)
		}
		return &auth.TokenInfo{UserID: c.Subject, Expiration: c.Expiry.Time(),
			Extra: map[string]any{"client_id": extra.ClientID, "roles": extra.Roles}}, nil
	}
}

// handler = auth.RequireBearerToken(verifier(keys, "http://mcp-upstream.internal:3001/mcp"), nil)(mcpHandler)
```

Also check the issuer (`c.Issuer`) when the upstream trusts more than one proxy.

### TypeScript: the MCP TypeScript SDK

```js
import { createRemoteJWKSet, jwtVerify } from 'jose';
import { requireBearerAuth } from '@modelcontextprotocol/sdk/server/auth/middleware/bearerAuth.js';
import { InvalidTokenError } from '@modelcontextprotocol/sdk/server/auth/errors.js';

const keys = createRemoteJWKSet(new URL('https://mcp.example.com/.well-known/jwks.json'));
const verifier = {
  async verifyAccessToken(token) {
    try {
      const { payload } = await jwtVerify(token, keys, {
        algorithms: ['ES256'],
        typ: 'at+jwt',
        issuer: 'https://mcp.example.com', // byward's public origin
        audience: 'http://mcp-upstream.internal:3001/mcp', // byward's BYWARD_UPSTREAM_URL, exactly
        clockTolerance: 30,
      });
      return { token, clientId: payload.client_id, scopes: [], expiresAt: payload.exp, extra: { sub: payload.sub, roles: payload.roles } };
    } catch (e) {
      throw new InvalidTokenError(e.message);
    }
  },
};
app.use('/mcp', requireBearerAuth({ verifier }));
```

### Python: FastMCP

```python
from fastmcp import FastMCP
from fastmcp.server.auth.providers.jwt import JWTVerifier

verifier = JWTVerifier(
    jwks_uri="https://mcp.example.com/.well-known/jwks.json",
    issuer="https://mcp.example.com",  # byward's public origin
    audience="http://mcp-upstream.internal:3001/mcp",  # byward's BYWARD_UPSTREAM_URL, exactly
    algorithm="ES256",
)
mcp = FastMCP("my-server", auth=verifier)
```

FastMCP's `JWTVerifier` does not check `typ`.

Tested versions: go-sdk 1.8.0, the TypeScript SDK 1.32.1 with jose 6.2.13, FastMCP 4.1.3.

### By discovery

Some verifiers take only an issuer and find the keys through OIDC discovery:
`<issuer>/.well-known/openid-configuration` → `jwks_uri`. Give them byward's issuer, its public
origin (`https://mcp.example.com`). The discovery document names that issuer, so the assertion's
`iss` matches it. byward's contract test follows this path (`TestAVerifierUsingDiscoveryFindsTheAssertionKeys`),
and `byward doctor` checks it ("identity assertion keys (discovery)"). The snippets below are not run
by byward's tests; their field names are from each project's code or docs, checked 2026-11-07.

**MCP Toolbox for Databases** (`generic` auth service, v1.16.0). It has no JWKS field: it reads
`jwks_uri` from `<authorizationServer>/.well-known/openid-configuration` and checks `iss` against the
document's `issuer` and `aud` against `audience`. It checks neither `typ` nor the algorithm, so
the audience is what binds the assertion to this upstream.

```yaml
# The fields of the generic auth service (internal/auth/generic/generic.go); see Toolbox's docs
# for where authServices go in your configuration.
type: generic
authorizationServer: https://mcp.example.com            # byward's public origin
audience: http://mcp-upstream.internal:3001/mcp         # byward's BYWARD_UPSTREAM_URL, exactly
```

**OpenSearch.** Its `jwt` authenticator takes the JWKS directly (`jwks_uri`, OpenSearch 3.3 and
later); its `openid` authenticator uses discovery (`openid_connect_url`):

```yaml
http_authenticator:
  type: jwt
  challenge: false
  config:
    jwks_uri: https://mcp.example.com/.well-known/jwks.json
    # or, with type: openid:
    # openid_connect_url: https://mcp.example.com/.well-known/openid-configuration
    required_issuer: https://mcp.example.com
    required_audience: http://mcp-upstream.internal:3001/mcp
    subject_key: sub
    roles_key: roles
```

**Go: go-oidc** (v3.21.0). Discovery checks that the document's `issuer` is the one given. byward's
metadata does not list `id_token_signing_alg_values_supported`, so name ES256, and check `typ`
yourself: go-oidc does not.

```go
provider, err := oidc.NewProvider(ctx, "https://mcp.example.com") // fetches the discovery document
if err != nil {
	return err
}
v := provider.Verifier(&oidc.Config{
	ClientID:             "http://mcp-upstream.internal:3001/mcp", // aud: byward's BYWARD_UPSTREAM_URL
	SupportedSigningAlgs: []string{oidc.ES256},
})
tok, err := v.Verify(ctx, raw) // checks the signature, iss, aud and exp; tok.Subject is the user key
```

Without discovery, `oidc.NewVerifier("https://mcp.example.com", oidc.NewRemoteKeySet(ctx, jwksURL), cfg)`
does the same with the JWKS URL given directly.
