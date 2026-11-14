# Sign users in with Google

Step by step: a Google Cloud OAuth client for byward, who may sign in, and the proxy settings. The
general OIDC guide, with every setting, is [oidc.md](oidc.md).
The data directory, the keys and starting the proxy are in [run byward](run-byward.md).

> Verified on 2026-11-13 with the byward v0.2.0-rc.1 code: sign-in, refresh, revoke, and the email-domain
> gate (allowed and refused). The Workspace domain gate (`BYWARD_GATE_HOSTED_DOMAINS`) was not tested.
> Use the image `ghcr.io/byward-dev/byward:v0.2.0-rc.1` or a later release: `latest` is still v0.1.1,
> which has no OIDC IdPs.

## 1. The OAuth client

In the [Google Cloud console](https://console.cloud.google.com), in a project of its own (no billing
needed):

1. **Google Auth Platform › Branding** (older consoles: **APIs & Services › OAuth consent screen**): app
   name, support and developer email.
2. **Audience**: **External** for any Google account, or **Internal** to allow only your Google
   Workspace organisation. While the app is in **Testing**, only the accounts listed under **Test
   users** can sign in, and Google shows them a "Google hasn't verified this app" screen; choose
   **Continue**. Publish the app (and go through Google's verification if it asks for it) before real
   users sign in.
3. **Clients › Create client**: type **Web application**, authorised redirect URI
   `https://<public host>/callback/google`. byward logs the exact URI at startup.
4. Copy the client secret into a file only the proxy's user can read.

## 2. Configure byward

```sh
BYWARD_IDP=google
BYWARD_OIDC_CLIENT_ID=<client id>.apps.googleusercontent.com
BYWARD_OIDC_CLIENT_SECRET_FILE=/run/secrets/google-client-secret
BYWARD_GATE_EMAIL_DOMAINS=example.com       # or BYWARD_GATE_HOSTED_DOMAINS for Workspace
```

The `google` preset fills in the issuer (`https://accounts.google.com`).

## 3. Who may sign in

Anyone with a Google account can sign in to Google, so an empty access gate refuses to start (unless
`BYWARD_GATE_ALLOW_EMPTY=true`). Choose one:

- `BYWARD_GATE_EMAIL_DOMAINS`: verified email domains, for example `gmail.com` or your company domain.
  A user outside them gets "You don't have access to this server." and the audit records
  `access_denied` with `reason` `email_domain`.
- `BYWARD_GATE_HOSTED_DOMAINS`: Google Workspace domains (the `hd` claim), which a user cannot change.
  Prefer it for a Workspace organisation. With one domain, Google also shows only that Workspace's
  accounts.

Google has no roles or groups claims for this; use the domain gates.

## 4. What users see

- Google's consent screen at **every** sign-in: the preset sends `prompt=consent`, because Google
  returns a refresh token only on the first consent otherwise ([oidc.md](oidc.md)). byward's own consent
  page is remembered; Google's is not.
- A client gets a refresh token from byward only if it asks for `offline_access`.

## 5. Check it

`byward check --offline`, then `byward doctor`: "discovery at https://accounts.google.com matches the
configured issuer", and "client credential": Google accepted the client ID and the secret. A wrong
secret fails, with the setting to fix. (The client credential check is on `main`; the doctor in
v0.2.0-rc.1 does not have it, and a wrong secret shows at the first sign-in as an IdP alert.) Then sign in from an MCP client
([oidc.md](oidc.md#5-check-it)).
