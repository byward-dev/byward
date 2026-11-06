// Contract test (ADR-0016 §8): an upstream on the TypeScript SDK's requireBearerAuth, with the
// verifier docs/reference/identity-assertion.md shows, accepts the proxy's assertion and refuses one
// for another audience, an expired one and one signed with another key.
//   node verify.mjs <fixture dir>   (scripts/assertion/run.sh)
import { readFileSync } from 'node:fs';
import { createLocalJWKSet, jwtVerify } from 'jose';
import { requireBearerAuth } from '@modelcontextprotocol/sdk/server/auth/middleware/bearerAuth.js';
import { InvalidTokenError } from '@modelcontextprotocol/sdk/server/auth/errors.js';

const dir = process.argv[2];
const jwks = JSON.parse(readFileSync(`${dir}/jwks.json`, 'utf8'));
const f = JSON.parse(readFileSync(`${dir}/tokens.json`, 'utf8'));

// --- the docs' example ---
// jwks: the proxy's /.well-known/jwks.json (createRemoteJWKSet fetches and caches it instead).
const keys = createLocalJWKSet(jwks);
const verifier = {
  async verifyAccessToken(token) {
    try {
      const { payload } = await jwtVerify(token, keys, {
        algorithms: ['ES256'],
        typ: 'at+jwt',
        issuer: f.issuer, // the proxy's public origin
        audience: f.audience, // this upstream's URL exactly as the proxy's BYWARD_UPSTREAM_URL says
        clockTolerance: 30,
      });
      return { token, clientId: payload.client_id, scopes: [], expiresAt: payload.exp, extra: { sub: payload.sub, roles: payload.roles } };
    } catch (e) {
      throw new InvalidTokenError(e.message);
    }
  },
};
const auth = requireBearerAuth({ verifier });
// --- end of the example ---

async function call(token) {
  let status = 200;
  let info;
  const req = { headers: { authorization: `Bearer ${token}` } };
  const res = { set() { return this; }, status(c) { status = c; return this; }, json() { return this; } };
  await auth(req, res, () => { info = req.auth; });
  return { status, info };
}

let failed = 0;
const ok = await call(f.valid);
if (ok.status !== 200 || ok.info?.extra?.sub !== f.subject || ok.info?.clientId !== f.client_id) {
  console.error('FAIL valid assertion:', ok.status, ok.info);
  failed++;
} else {
  console.log('ok   valid assertion accepted');
}
for (const name of ['wrong_audience', 'expired', 'other_key']) {
  const r = await call(f[name]);
  if (r.status !== 401) {
    console.error(`FAIL ${name}: status ${r.status}, want 401`);
    failed++;
  } else {
    console.log(`ok   ${name} refused`);
  }
}
process.exit(failed ? 1 : 0);
