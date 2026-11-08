# The scheduled real-Entra lane

Every night, `.github/workflows/real-entra.yml` checks byward against a real Entra tenant
([ADR-0024](../adr/0024-testing-strategy.md) §1, §12). It stores no secret. GitHub's OIDC token for
the run is the CI app's federated credential, which byward sends Entra in place of a client secret
(`BYWARD_ENTRA_FEDERATED_TOKEN_FILE`, [ADR-0012](../adr/0012-entra-specifics.md) §5). The lane never
blocks a pull request.

## What it checks

1. `byward check --offline` with the lane's settings.
2. A byward proxy on loopback, with sealing and assertion keys made for this run only.
3. `byward doctor` against the tenant. These checks must pass, not just not fail:
   - `entra tenant`: the discovery document and its issuer;
   - `entra signing keys`: the tenant's JWKS;
   - `entra app and credential`: a client-credentials token request for `api://<app>/.default`,
     authenticated by the federated token;
   - `entra access token`: that token is signed by the tenant, version 2, with `aud` = the app;
   - `entra idtyp claim`: app-only tokens carry `idtyp=app`.

The app-only path end to end (a headless caller's token through the proxy to an upstream) is added
with #64.

The token is masked in the log as soon as it is fetched and kept only in a `0600` file. The lane
prints only its `iss`, `sub` and `aud`. Without a token the lane fails; there is no other credential
to fall back on.

## Set it up once

This needs an Entra role that can create app registrations and their credentials: the app's
owner, Application Administrator or Cloud Application Administrator.

### 1. Create the CI app in the tenant

A single-tenant app with no secret, no certificate and no Microsoft Graph permissions. It is
configured like byward's own app for what doctor checks (the same requests as `byward init entra`):
the Application ID URI, version 2 access tokens and the `idtyp` claim.

```sh
TENANT_ID=<your tenant ID>
if [ "$(az account show --query tenantId -o tsv)" != "$TENANT_ID" ]; then
  echo "az is signed in to another tenant; run: az login --tenant $TENANT_ID" >&2
fi
APP_ID=$(az ad app create --display-name byward-ci --sign-in-audience AzureADMyOrg --query appId -o tsv)
cat > byward-ci.json <<EOF
{
  "identifierUris": ["api://$APP_ID"],
  "api": {"requestedAccessTokenVersion": 2},
  "optionalClaims": {"accessToken": [{"name": "idtyp"}]}
}
EOF
az rest --method patch --url "https://graph.microsoft.com/v1.0/applications(appId='$APP_ID')" --body @byward-ci.json
rm byward-ci.json
az ad sp create --id "$APP_ID" --query id -o tsv
echo "$APP_ID"
```

Leave **Assignment required** off on this app's service principal (unlike byward's own app). With it
on, Entra issues the app no token for itself, so doctor has none to check and the lane fails.

### 2. Create the environment and variables in the repository

1. **Settings → Environments → New environment** `real-entra`.
   - **Deployment branches and tags:** selected branches, `main` only.
   - No required reviewers: a reviewer would hold every scheduled run.
2. In that environment, add two **variables** (not secrets):

   | Variable | Value |
   |---|---|
   | `BYWARD_CI_ENTRA_TENANT` | the tenant ID: `az account show --query tenantId -o tsv` |
   | `BYWARD_CI_ENTRA_CLIENT_ID` | `$APP_ID` from step 1 |

### 3. Run it once, then create the federated credential

1. **Actions → real-entra → Run workflow** on `main`. The run fails at `byward doctor`, because Entra
   does not trust GitHub yet. Its log has one line like:

   ```text
   GitHub OIDC claims for the federated credential: {"iss":"https://token.actions.githubusercontent.com","sub":"repo:byward-dev@…/byward@…:environment:real-entra","aud":"api://AzureADTokenExchange"}
   ```

2. Create the federated identity credential with that exact `sub`. Entra matches it exactly and
   case-sensitively, with no patterns. This repository's `sub` uses GitHub's immutable form, with
   the owner's and the repository's IDs, so copy it rather than typing it:

   ```sh
   az ad app federated-credential create --id "$APP_ID" --parameters '{
     "name": "github-real-entra",
     "issuer": "https://token.actions.githubusercontent.com",
     "subject": "<the sub from the log>",
     "audiences": ["api://AzureADTokenExchange"]
   }'
   ```

3. Run the workflow again. It passes.

The credential is bound to the `real-entra` environment, and the environment to `main`. A run from
any other branch cannot use it.

## When it fails

- GitHub mails whoever last changed the schedule (`cron`) in the workflow.
- The `notify` job also opens one issue labelled `real-entra-lane`, and comments on it on every
  later failure. Close it when the lane passes again.
- In a public repository, GitHub disables scheduled workflows after 60 days with no repository
  activity. Re-enable it under **Actions → real-entra**.

| The log says | Do |
|---|---|
| `no GitHub OIDC token can be requested` | the job lost `permissions: id-token: write` |
| `set the real-entra environment variable …` | step 2 |
| `entra app and credential` fails: "must match one of the app's federated identity credentials" | step 3: the `sub` in the log differs from the credential's, e.g. after the repository was renamed or moved |
| `entra access token` or `entra idtyp claim` fails | step 1: `requestedAccessTokenVersion` 2 and the `idtyp` optional claim |
