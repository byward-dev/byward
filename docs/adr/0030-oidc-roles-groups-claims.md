# ADR-0030: Configurable roles and groups claims for OIDC IdPs

- Status: Accepted
- Date: 2026-11-14
- Issue: #286 (PR #302); amends ADR-0011 §2

## Context

Recorded after the fact; the ADR-0011 amendment of 2026-11-14 summarises it. It is on `main`, not in
v0.2.0-rc.1.

The access gate (ADR-0015) and the identity assertion (ADR-0016) read a user's roles and groups from
the ID token. For an OIDC IdP the adapter read only the top-level `roles` and `groups` claims
(ADR-0011 §2 made the subject claim configurable, not these).

- **Auth0** restricts the claim names `roles` and `groups`: "In case of collisions, the transaction
  won't fail, but your custom claim won't be added to your tokens", and it recommends namespaced
  claims such as `https://example.com/…`
  ([Create Custom Claims](https://auth0.com/docs/secure/tokens/json-web-tokens/create-custom-claims)).
  The Auth0 run on v0.2.0-rc.1 (#282) showed it: the post-login Action's namespaced claim reached the
  ID token, the top-level `roles` did not, and a user holding the role was refused. A role or group
  gate with `BYWARD_IDP=auth0` admitted nobody (#286). It failed closed.
- **Keycloak** puts realm roles under `realm_access.roles` by default; a "User Realm Role" mapper
  with the claim name `roles` already makes it work (`docs/how-to/keycloak.md`,
  `TestIntegrationKeycloakSignsAUserInAndRefreshes`).
- **Constraint (maintainer, #286):** no other provider's behaviour may change.

## Decision

1. **`BYWARD_OIDC_ROLES_CLAIM` and `BYWARD_OIDC_GROUPS_CLAIM`** name the ID token claims roles and
   groups are read from. Both default to `roles` and `groups` for every OIDC preset, Auth0 included;
   no preset changes the default. With Auth0 the operator names the namespaced claim.
2. **One source for the gate and the assertion.** The adapter fills `Identity.Roles` and
   `Identity.Groups` from the named claims, at sign-in and at refresh. The access gate
   (`BYWARD_GATE_ROLES`, `BYWARD_GATE_GROUPS`) and the identity assertion's `roles` and `groups`
   both read them, as do the `X-Byward-Roles` and `X-Byward-Groups` identity headers; the
   assertion's claim names stay `roles` and `groups`.
3. **A claim name is a top-level key matched exactly.** No dotted paths, so `realm_access.roles` is
   not reachable; Keycloak keeps its mapper.
4. **The claim must be an array of strings.** Non-string entries are skipped; a single string is
   ignored, so the gate stays closed (`idp.StringsClaim`, unchanged).
5. **These refuse to start:**
   - an empty or padded name (it would never match and would close the gate silently);
   - a claim about the sign-in itself: `iss`, `sub`, `aud`, `azp`, `exp`, `iat`, `nbf`, `jti`,
     `nonce`, `auth_time`, `acr`, `amr`, `sid`, `at_hash`, `c_hash`. `aud` and `azp` hold the
     proxy's client ID, so a gate on either would admit every user of the IdP; `amr` is an array of
     strings and would be read as roles without an error;
   - either setting with `BYWARD_IDP=entra`, even at its default value: Entra's claims are fixed
     (ADR-0012), and the existing rule refuses any `BYWARD_OIDC_*` setting with Entra.

## Consequences

- Auth0 role gates work with a post-login Action and one setting; verified on 2026-11-14 against the
  test tenant from #282 with the code on `main`, the role kept after a refresh
  (`docs/how-to/auth0.md`).
- Every other preset reads the same claims as on v0.2.0-rc.1 (`TestEveryIdPGatesOnTheTopLevelRolesAndGroupsByDefault`).
- Both settings are `Auth` settings, so `--insecure-no-auth` refuses them (ADR-0027 §2).
- A preset default is public interface (ADR-0011); a later per-preset default would be a breaking
  change.

## Considered options

- An Auth0 preset that defaults to a namespaced claim: the namespace is the operator's, so there is
  no default to give, and the maintainer ruled out changing any preset's behaviour.
- Dotted paths (`realm_access.roles`): Keycloak already works with a mapper, and an exact key keeps a
  namespaced URL claim, which contains dots, unambiguous.
- Accept a single string as one role: `idp.StringsClaim` is shared with Entra and stays unchanged,
  and a gate that fails closed on an unexpected shape is the safer error.
