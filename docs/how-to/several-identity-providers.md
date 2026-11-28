# Serve users from several identity providers

One byward signs users in with one IdP. When your users come from several identity sources, staff
on Entra and partners on Google or their own Okta, say, there are two ways to serve them:

- **Federate at the IdP.** byward's IdP brokers the other sources, and byward still sees one IdP.
  [Keycloak as the broker](#keycloak-as-the-broker),
  [Entra B2B guests](#entra-b2b-guests), and [Auth0 or Okta connections](#auth0-or-okta-connections)
  below.
- **Run one byward per IdP**, for user groups that never mix
  ([below](#one-byward-per-idp)).

[What doesn't work behind a broker](#what-doesnt-work-behind-a-broker): On-Behalf-Of.

## Why one IdP per proxy

Every user has one user key, the IdP's subject. The store, the access gate, the identity assertion,
`revoke-user` and the audit stream all name the user by that key, and a key is not scoped by
issuer. Two IdPs in one proxy could hand out the same subject for two different people
([ADR-0011](../adr/0011-idp-adapters.md) §8: several IdPs per proxy are out of scope).

## Keycloak as the broker

Keycloak signs byward's users in, and its realm offers the other sources as identity providers:
OpenID Connect and SAML IdPs, Entra among them, and social providers such as Google and GitHub
([Keycloak: integrating identity providers](https://www.keycloak.org/docs/latest/server_admin/index.html#_identity_broker)).
byward sees only Keycloak.

**Verified on 2026-11-28** with byward v0.4.0 (the published image) and Keycloak 26.8.2. Two local
realms: `partner`, the identity source, and `hub`, which brokers it and is byward's IdP. Every
result below is from that run.

### 1. Add the identity providers to the realm

In the realm byward signs in with, open **Identity providers** and add each source. For another
OpenID Connect IdP: its discovery URL, or its authorization, token and JWKS URLs, and a client the
source registered for Keycloak, whose redirect URI is
`https://<keycloak>/realms/<realm>/broker/<alias>/endpoint`. Keep **Validate signatures** on.

Keycloak's sign-in page then shows a button per identity provider next to its own login form. With
a single source, Keycloak can skip the choice: set a default provider on the **Identity Provider
Redirector** in the browser flow
([Keycloak: default identity provider](https://www.keycloak.org/docs/latest/server_admin/index.html#default_identity_provider)).

### 2. Configure byward

byward is configured exactly as for any Keycloak realm ([Keycloak](keycloak.md#3-configure-byward)):

```sh
BYWARD_IDP=keycloak
BYWARD_OIDC_ISSUER=https://keycloak.example.com/realms/<realm>
```

The issuer is the broker's realm, never a source's. The user key is the broker's `sub`, its own ID
for the user it imported at the first sign-in, not the source's subject.

### 3. The first sign-in

At a brokered user's first sign-in, Keycloak's **first broker login** flow creates a user in the
realm and links it to the source
([Keycloak: first login flow](https://www.keycloak.org/docs/latest/server_admin/index.html#_identity_broker_first_login)).
In the run, Keycloak 26.8.2 with the default flow:

- A source that sent the email and the name: no extra page. The user went straight from the source's
  login to byward.
- A source user whose email belongs to an existing realm user: Keycloak showed **Account already
  exists** ("User with email … already exists"), with **Review profile** and **Add to existing
  account**. **Add to existing account** asked for the existing user's password ("Authenticate to link
  your account with …"); without it, nothing was linked. (With SMTP set up, Keycloak verifies by
  email instead.)

Don't replace that step with automatic linking. Keycloak warns that linking an existing account to
an external identity provider automatically is "a potential security hole", and that its AutoLink
authenticator "is dangerous in a generic environment where users can register themselves using
arbitrary usernames or email addresses"
([Keycloak: automatically link existing first login flow](https://www.keycloak.org/docs/latest/server_admin/index.html#automatically-link-existing-first-login-flow)).
Brokering adds users even with self-registration off: every user a source accepts gets an account in
the realm at their first sign-in
([Keycloak: self-registration](https://www.keycloak.org/docs/latest/server_admin/index.html#proc-enabling-user-registration_server_administration_guide)).
So the source's users are your users: gate on a role or group you assign in the broker
([access gate](access-gate.md)), not on having an account.

### 4. Get `email_verified` through for an email-domain gate

`BYWARD_GATE_EMAIL_DOMAINS` admits only verified emails, and the identity assertion carries `email`
only when it is verified ([identity assertion](../reference/identity-assertion.md#email)).
byward reads `email_verified` in the broker's ID token, and the broker decides it from the
identity provider's **Trust Email** option, at the first sign-in. What byward received in the run,
with `BYWARD_GATE_EMAIL_DOMAINS=partner.example`:

| Trust Email | The source's `email_verified` | `email_verified` in the broker's ID token | byward |
|---|---|---|---|
| off | `true` | `false` | refused (`access_denied`, `reason` `email_domain`) |
| on, switched on after the user's first sign-in | `true` | `false`, unchanged | refused |
| on, at the user's first sign-in | `true` | `true` | admitted; the assertion has `email` and `email_verified: true` |
| on | `false` | `false` | refused |
| on | absent (the source doesn't send it) | `true` | **admitted**, though the source never verified the address |

So:

- **Turn Trust Email on only for a source that verifies emails and says so** in `email_verified`.
  When the source leaves the claim out, Keycloak treats the address as verified
  ([Keycloak: Trust Email](https://www.keycloak.org/docs/latest/server_admin/index.html#_general-idp-config)),
  and an email-domain gate then admits anyone who can put that domain in their profile at the
  source.
- **Trust Email applies when Keycloak imports the user.** With the sync mode the run used, Import, a
  user imported while it was off stayed unverified. Keycloak applies it at later sign-ins only with
  the sync mode Force ([Keycloak: Trust Email](https://www.keycloak.org/docs/latest/server_admin/index.html#_general-idp-config);
  not run). Otherwise set the email as verified in the broker yourself, or delete that user in the
  broker so the next sign-in imports them again. Deleting gives the user a new `sub`, which is a new
  user key in byward: [revoke](revoke-access.md#one-user) the old one.

### 5. Revoke a brokered user

`revoke-user` takes the broker's `sub`, the `user_key` in byward's audit stream. In the run, the user's
access token was refused 8 s after `byward revoke-user <sub>`: `401` `invalid_token`, after the audit
events `grant_revoked` (`reason` `operator revoke-user`) and `access_token_rejected`. To keep the user
out, also disable them in the broker or at the source ([revoke access](revoke-access.md#one-user)).

## Entra B2B guests

**Not verified with byward; based on the vendor docs, checked on 2026-11-28.**

When byward signs in with Entra, people outside your tenant can sign in as **B2B guests** of your
tenant. Guests sign in with their own work, school or social identities
([Microsoft: B2B collaboration](https://learn.microsoft.com/en-us/entra/external-id/what-is-b2b)):

- another Entra organisation: the guest signs in at their own organisation, then returns to yours;
- an organisation with a SAML or WS-Fed IdP, by federation
  ([Microsoft: SAML/WS-Fed federation](https://learn.microsoft.com/en-us/entra/external-id/direct-federation));
- Gmail accounts, by Google federation, which "is designed specifically for Gmail users". For Google
  Workspace domains, use SAML/WS-Fed federation
  ([Microsoft: Google federation](https://learn.microsoft.com/en-us/entra/external-id/google-federation));
- anyone else, with an email one-time passcode
  ([Microsoft: email one-time passcode](https://learn.microsoft.com/en-us/entra/external-id/one-time-passcode)).

A guest signs in to your tenant: the token's `tid` is "the tenant that the user is signing in to"
([Microsoft: access token claims](https://learn.microsoft.com/en-us/entra/identity-platform/access-token-claims-reference)),
and Microsoft says to treat a guest as a new user of the service
([Microsoft: ID token claims](https://learn.microsoft.com/en-us/entra/identity-platform/id-token-claims-reference)).
So byward's user key for a guest, `tid:oid`, is your tenant and the guest's object in it, and
`BYWARD_GATE_TENANTS` with your tenant does not keep guests out.

**Set the access gate.** An empty gate with Entra admits every user of your tenant, guests included
([empty gate](access-gate.md#empty-gate)). Use the [recommended setup](access-gate.md#entra-recommended-setup):
**Assignment required**, and an app role you assign to the staff and the guests who should have
access.

**On-Behalf-Of for guests:** not verified. Microsoft's On-Behalf-Of page says the flow "only works for
user principals" and doesn't mention guests
([Microsoft: On-Behalf-Of flow](https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth2-on-behalf-of-flow)).
Headless callers with [app-only tokens](app-tokens.md) are apps, not users, so guests don't change
them.

## Auth0 or Okta connections

**Not verified with byward; based on the vendor docs, checked on 2026-11-28.**

byward signs in with one Auth0 application or Okta app; the IdP behind it offers several sources.

**Auth0.** Enable several connections on the application
([Auth0: application connections](https://auth0.com/docs/get-started/applications/update-application-connections)).
With identifier-first login, Auth0 sends a user to the enterprise connection that registered their
email domain
([Auth0: identifier-first, Home Realm Discovery](https://auth0.com/docs/authenticate/login/auth0-universal-login/identifier-first)).
Each connection gives its own user: "Auth0 treats all identities as separate by default"
([Auth0: user account linking](https://auth0.com/docs/manage-users/user-accounts/user-account-linking)).
byward's user key is the `sub` (`auth0|…`, `google-oauth2|…`), so a person who signs in through two
connections is two users in byward: two keys to gate and to revoke. Link their accounts at Auth0 to
make them one, and follow Auth0's precaution: request authentication for both accounts before
linking.

**Okta.** Add the identity providers to your org
([Okta: identity providers](https://developer.okta.com/docs/concepts/identity-providers/)), and route
users to them with routing rules, for example by email domain
([Okta: routing rules](https://help.okta.com/oie/en-us/content/topics/security/configure-routing-rules.htm)).
Account linking is off by default. Set to automatic, it links when the username the IdP sends, by
default its email, matches an Okta username
([Okta: account linking](https://developer.okta.com/docs/concepts/identity-providers/)), so turn it on
only for IdPs you trust to verify emails. What Okta does with a second user for the same person was
not found in its docs.

## One byward per IdP

For user groups that never mix, run one byward per IdP: each with its own public URL, settings,
keys and store, and its own registration at its IdP. Users add the server for their group. The MCP
server can sit behind both proxies. If it uses the [identity assertion](identity-assertion.md), it
must trust both proxies' issuers, and a user key is unique only within one proxy.

## What doesn't work behind a broker

**On-Behalf-Of.** byward calls a downstream API as the user only with Entra: `BYWARD_OBO_SCOPES` needs
`BYWARD_IDP=entra` ([downstream APIs](downstream-apis.md)). Behind any broker, the proxy refuses to
start (verified in the run above):

```text
byward: configuration error: BYWARD_OBO_SCOPES: On-Behalf-Of is Entra's; it needs BYWARD_IDP=entra, got keycloak
```

So a Microsoft Graph token for the user, through byward, needs byward signing in with Entra itself.
Keycloak can store the source IdP's tokens and hand them to an application
([Keycloak: retrieving external IdP tokens](https://www.keycloak.org/docs/latest/server_admin/index.html#retrieving-external-idp-tokens)),
and its token exchange to an external token exists only in the deprecated legacy version
([Keycloak: token exchange](https://www.keycloak.org/securing-apps/token-exchange)). byward uses
neither; not verified with byward.
