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
| `sub` | yes | the user key: `tid:oid` for Entra, stable and opaque |
| `client_id` | yes | the MCP client's ID at byward (a static ID, a CIMD URL or a DCR ID) |
| `iat` | yes | issued at, seconds |
| `exp` | yes | `iat` + 60 seconds |
| `jti` | yes | 128 random bits, base64url |
| `roles` | `roles` opted in (default) | the user's app roles, when they have any |
| `groups` | `groups` opted in | group IDs; left out under Entra groups overage, or when too many to fit |
| `email` | `email` opted in | display only, never for authorization (Entra does not verify it) |
| `name` | `name` opted in | display only |

A claim the user has no value for is left out; it is never sent empty. Roles and groups are as of
the user's last sign-in or token refresh, so they can be up to one hour old.

Example (from `internal/assertion/testdata/assertion.golden.json`; `jti` is random):

```json
{
  "aud": "http://upstream.internal:3001/mcp",
  "client_id": "https://claude.ai/oauth/claude-code-client-metadata",
  "email": "alex@contoso.example",
  "exp": 1794042060,
  "groups": ["22222222-2222-2222-2222-222222222222"],
  "iat": 1794042000,
  "iss": "https://mcp.example.com",
  "jti": "<random>",
  "name": "Alex",
  "roles": ["byward.user"],
  "sub": "00000000-0000-0000-0000-000000000001:11111111-1111-1111-1111-111111111111"
}
```

## Keys

- JWKS at `/.well-known/jwks.json` on the public and the internal listener, `Cache-Control: public,
  max-age=300`, or exported with `byward jwks`.
- The key whose ID sorts last signs. Older keys stay in the JWKS until you remove their files, so a
  rotation needs no change in the upstream.
- The JWKS is not advertised in byward's authorization server metadata. Proxy tokens are opaque, so
  only upstreams use these keys.

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
