# Use a federated credential instead of a client secret for Entra

When byward runs where a platform already issues it a token, such as an AKS pod with Microsoft Entra
Workload ID, a GitHub Actions job, or any other OIDC issuer Entra can trust, byward can use that
token as its Entra credential. There is then no secret to store or rotate. byward sends the token to
Entra as its client assertion ([ADR-0012](../adr/0012-entra-specifics.md) §5) and re-reads the file
for every token request, so the platform can renew the file whenever it likes.

byward takes exactly one Entra credential: `BYWARD_ENTRA_CLIENT_SECRET_FILE`,
`BYWARD_ENTRA_FEDERATED_TOKEN_FILE` or `BYWARD_ENTRA_CLIENT_CERTIFICATE_FILE`. With neither a
platform token nor a secret store, use a [certificate](entra-certificate.md) instead.

## 1. Find the token's issuer, subject and audience

Entra trusts a token only when its `iss`, `sub` and `aud` claims match a federated identity
credential on byward's app registration. Entra supports no wildcards
([Microsoft](https://learn.microsoft.com/entra/workload-id/workload-identity-federation-create-trust)).

| Platform | Issuer | Subject | Audience |
|---|---|---|---|
| AKS Workload ID | the cluster's OIDC issuer: `az aks show --name <cluster> --resource-group <group> --query oidcIssuerProfile.issuerUrl -o tsv` | `system:serviceaccount:<namespace>:<service account>` | `api://AzureADTokenExchange` |
| GitHub Actions, a job in an environment | `https://token.actions.githubusercontent.com` | `repo:<owner>/<repo>:environment:<name>`. Repositories created after 2026-07-15 use a form with the owner's and repository's IDs, so copy the `sub` from a real token | `api://AzureADTokenExchange` |

Sources:
- AKS:
  [Microsoft](https://learn.microsoft.com/azure/aks/workload-identity-deploy-cluster).
- GitHub:
  - [the subject format](https://docs.github.com/actions/security-for-github-actions/security-hardening-your-deployments/about-security-hardening-with-openid-connect);
  - [the job needs `permissions: id-token: write`](https://docs.github.com/actions/reference/security/oidc).

When in doubt, decode the token's payload, the second dot-separated part, and read the three claims
from it. They are not secret, but the token is: don't paste it anywhere.

Entra creates a credential with a wrong subject without complaint. Only the token request fails
later, so check the claims before you create it.

## 2. Create the federated identity credential

Signed in to the tenant with an Entra role that can change the app (owner, Application Administrator
or Cloud Application Administrator), add the credential to byward's app registration (`$APP_ID`, as in
the [quickstart](quickstart-entra.md#11-create-the-registration)):

```sh
az ad app federated-credential create --id "$APP_ID" --parameters '{
  "name": "byward-prod",
  "issuer": "<issuer>",
  "subject": "<subject>",
  "audiences": ["api://AzureADTokenExchange"]
}'
```

An app can hold up to 20 federated credentials, one per issuer and subject pair, such as one per
cluster or environment.

On AKS, the pod also needs the label `azure.workload.identity/use: "true"`. Its service account
needs the annotation `azure.workload.identity/client-id: <APP_ID>`. The Workload ID webhook then
mounts a token and names its path in `AZURE_FEDERATED_TOKEN_FILE`
([Microsoft](https://learn.microsoft.com/azure/aks/workload-identity-overview)).

## 3. Point byward at the token file

Set `BYWARD_ENTRA_FEDERATED_TOKEN_FILE` to the token file's absolute path, and drop the other
credential setting ([settings](../reference/settings.md)).

- **On AKS:** byward does not read `AZURE_FEDERATED_TOKEN_FILE` itself. Set byward's setting to the
  path that variable names in the pod. Microsoft notes that this path belongs to the webhook and can
  change; recheck it after an AKS upgrade.
- **The file must exist at startup**, and other users must not be able to read it, unless it is on
  a read-only mount. This is the same check as for every secret file, and `--dev` relaxes it.
  `byward check --offline` reports both problems.
- **No expiry setting:** `BYWARD_ENTRA_CLIENT_SECRET_EXPIRES_AT` is refused with a federated token,
  which has no secret to expire.

## 4. Check it

`byward doctor` asks Entra for a token with the federated credential. When the claims don't match,
its `entra app and credential` check fails, names the setting and gives the
`az ad app federated-credential list` command to compare against
([commands](../reference/commands.md#byward-doctor)).

A worked example is the maintainers' scheduled test against a real tenant, which uses a GitHub
Actions token: [the real-Entra lane](../maintainers/real-entra-lane.md).
