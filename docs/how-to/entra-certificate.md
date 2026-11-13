# Use a certificate instead of a client secret for Entra

byward signs in to Entra as a confidential client. A client secret is the quickest way to start;
for production, Microsoft and [ADR-0012 §5](../adr/0012-entra-specifics.md) recommend a
**certificate**: "It's therefore recommended that your application uses a certificate rather than
a secret" ([Microsoft](https://learn.microsoft.com/entra/identity-platform/howto-create-self-signed-certificate)).
With a certificate, the private key never leaves the proxy's machine, and nothing that could sign
in as the app is ever sent over the wire: byward sends Entra a short-lived assertion signed with
the key (`private_key_jwt`, `PS256`, `x5t#S256`, per
[Microsoft's certificate credentials](https://learn.microsoft.com/entra/identity-platform/certificate-credentials)).

byward takes exactly one Entra credential: `BYWARD_ENTRA_CLIENT_SECRET_FILE`,
`BYWARD_ENTRA_FEDERATED_TOKEN_FILE` or `BYWARD_ENTRA_CLIENT_CERTIFICATE_FILE`.

## 1. Make the certificate

**Shortcut:** `byward init entra --credential certificate …` prints the whole app registration
script with a certificate instead of a secret ([commands](../reference/commands.md#byward-init-entra)).
It runs the steps below for you.

By hand, on the machine (or into the secret store) the proxy reads from:

```sh
umask 077
openssl req -x509 -newkey rsa:2048 -sha256 -days 365 -nodes -subj "/CN=byward" \
  -keyout byward-cert.key -out byward-cert.crt
cat byward-cert.key byward-cert.crt > entra-client-certificate.pem
rm byward-cert.key
```

- Entra accepts only **RSA** keys; byward refuses an EC key, and an RSA key under 2048 bits.
- The private key must be **unencrypted** (`-nodes`): protect the file instead (mode `0600`, owned
  by the proxy's user, or a read-only secret mount). byward checks the file's permissions as it does
  for a client secret; `--dev` relaxes the check.
- A certificate from your own CA works the same way; put the key and the certificate in the one
  file. Extra certificates (a chain) may follow; byward uses the one that matches the key.

## 2. Upload the public certificate

Only the certificate, never the key:

```sh
az ad app credential reset --id <client-id> --append --display-name byward --cert @byward-cert.crt
rm byward-cert.crt
```

`--append` keeps the app's other credentials; without it, the command replaces them all. The portal
works too: in the Microsoft Entra admin center, **App registrations** › byward › **Certificates &
secrets** › **Certificates** › **Upload certificate** (`.cer`, `.pem` or `.crt`).

Allow a few minutes before you test a sign-in. In the real-tenant test (2026-11-13), `byward doctor`
accepted a newly uploaded certificate within a minute, but sign-ins were refused with AADSTS700027
for about five minutes after the upload.

## 3. Point byward at the file

```sh
BYWARD_ENTRA_CLIENT_CERTIFICATE_FILE=/run/secrets/entra-client-certificate.pem
```

Remove `BYWARD_ENTRA_CLIENT_SECRET_FILE` (and `BYWARD_ENTRA_CLIENT_SECRET_EXPIRES_AT`): byward
refuses to start with two credentials. Then run `byward check --offline` and `byward doctor`; the
"entra app and credential" check signs in with the certificate.

byward reads the certificate's end date from the file. It warns at startup, in `check` and in
`doctor` ("client certificate expiry") from 30 days before. Once the certificate has expired, the
proxy and `check` refuse to start, and `doctor` reports a failure; `revoke-user` still works.

## 4. Rotate it

An app registration can hold several certificates at once ("The `keyCredentials` property is
multi-valued", [Microsoft](https://learn.microsoft.com/entra/identity-platform/certificate-credentials)),
so rotation has no downtime:

1. Make a new key and certificate (step 1) and upload the new certificate with `--append` (step 2).
2. Replace the file the proxy reads and restart the proxy. byward reads the file at startup only.
3. Once every replica runs with the new file, remove the old certificate:
   `az ad app credential list --id <client-id> --cert` lists the certificates, each with its key ID
   (Microsoft Graph's `keyCredential.keyId`) and end date;
   `az ad app credential delete --id <client-id> --key-id <key ID> --cert` removes one.

## Troubleshooting

`byward doctor` names the fix for each:

| Entra says | Meaning | Fix |
|---|---|---|
| AADSTS700027 "Client assertion failed signature validation" | the app has no certificate for this key: not uploaded, or the old one after a rotation | upload this file's certificate (step 2) |
| AADSTS50012, "Thumbprint of the signing certificate isn't authorized" | the same, as Entra sometimes reports it | upload this file's certificate (step 2) |
| AADSTS700030 "subject name in certificate isn't authorized" | the app trusts certificates by subject name, not by upload | upload this file's certificate (step 2) |
| AADSTS5002723 | the assertion had no thumbprint | a byward bug: it always sends `x5t#S256`; please report it |

Error descriptions are from Microsoft's
[error code reference](https://learn.microsoft.com/entra/identity-platform/reference-error-codes);
AADSTS5002723 was observed in the real-tenant test of ADR-0012.

Verified against a real tenant on 2026-11-13: sign-in, On-Behalf-Of and `byward doctor` with a
certificate; a certificate that is not uploaded gives AADSTS700027, as in the table.
