# Serve TLS at the proxy

byward can terminate TLS on its public listener with a certificate you supply
([ADR-0019](../adr/0019-packaging.md) §9, amended 2026-11-13). It never obtains certificates itself:
there is no ACME. Use it to encrypt the hop from your ingress to byward, or to serve clients directly
from a host with a certificate of its own.

You do not need it when the hop from the ingress to byward is private (same host, same pod, or a
mesh that encrypts it), or on a platform that encrypts it for you ([Azure Container Apps](#azure-container-apps)).

## Settings

| Setting | Value |
|---|---|
| `BYWARD_TLS_CERT_FILE` | Absolute path to the PEM certificate, followed by any intermediates. |
| `BYWARD_TLS_KEY_FILE` | Absolute path to its unencrypted PEM private key. |

- Set both or neither.
- `BYWARD_PUBLIC_URL` must be `https`. It stays the URL clients use; byward never derives the issuer,
  cookies or `Strict-Transport-Security` from the connection.
- The key file is checked like every secret file: mode `0600` owned by the proxy's user, or on a
  read-only mount. `--dev` relaxes the check.
- TLS 1.2 is the minimum, and TLS 1.3 is preferred. Go's default cipher suites are used, and there
  is no setting for either.
- HTTP/2 and HTTP/1.1 are both served. Plain HTTP on the TLS port gets a `400`, and byward opens no
  `:80` listener and sends no redirect.
- The internal listener (`/metrics`, `/livez`, `/readyz`) stays plain HTTP.

## What byward checks

| When | Refused | Warned |
|---|---|---|
| Startup, `byward check --offline` | One file without the other; an unreadable file; an encrypted key; a key that does not match the certificate; any certificate in the chain expired, or not valid for more than 5 minutes yet | Expiry within 30 days, counted from the chain's earliest `NotAfter`; a certificate that covers neither the public URL's host nor any `BYWARD_ALLOWED_HOSTS` entry |
| `byward doctor` | An unreadable or mismatched pair (a configuration error) | It reads the files on disk, the ones the next connection gets. "TLS certificate expiry" names the certificate in the chain that expires first, fails a pair that is expired, and says when a running proxy will serve a pair that is not valid yet. "TLS certificate names" is the name check above |

A name mismatch is only a warning: an ingress may verify byward under an internal name such as
`byward.mcp.svc`.

## Renewal

Replace the files; there is no restart. On every new connection byward checks both files, following
symlinks, and reads them again when either has changed.

- A renewed pair is checked as at startup: a key other users can read is refused (outside `--dev`),
  and the startup warnings (expiry within 30 days, a name mismatch) are logged for it.
- A pair that cannot be served is never served: half written, a key that does not match or that other
  users can read, expired, or not yet valid. byward keeps the previous certificate and logs one warning for that state of the
  files, naming the files and the error but never their contents. Once the files are fixed, the next
  connection gets them.
- A certificate whose `NotBefore` is up to 5 minutes ahead of byward's clock is served, so a renewal
  works despite clock skew with the issuer. One further ahead is served from 5 minutes before its
  `NotBefore`, with no further change to the files.
- The listening line in the log says `"tls":true`, and each certificate served after a change is
  logged with its file, subject and end date. A TCP health probe of the port (one that connects,
  then closes or resets the connection) is not logged; a handshake that fails is, as a warning.
- Write the new pair to new files and rename them over the old ones, or let the platform swap them as
  Kubernetes does. A copy over the old files works too, but a connection made in the middle of the
  copy sees a half-written pair and keeps the old certificate until the copy completes.

## Kubernetes with cert-manager

cert-manager writes the certificate, followed by its intermediates, to `tls.crt` and the key to
`tls.key` ([cert-manager](https://cert-manager.io/docs/usage/certificate/)):

```yaml
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: byward-backend
  namespace: mcp
spec:
  secretName: byward-backend-tls
  dnsNames: [byward.mcp.svc]
  issuerRef:
    name: internal-ca
    kind: ClusterIssuer
```

Mount the whole secret as a volume. Do not use `subPath`: "A container using a Secret as a subPath
volume mount does not receive automated Secret updates"
([Kubernetes](https://kubernetes.io/docs/concepts/configuration/secret/)). The kubelet updates a
whole-volume mount by swapping its `..data` link, and byward picks that up at the next connection.
Secret volumes are read-only mounts, so the key passes the permission check.

```yaml
      containers:
        - name: byward
          env:
            - {name: BYWARD_PUBLIC_URL, value: https://mcp.example.com/mcp}
            - {name: BYWARD_LISTEN, value: 0.0.0.0:8443}
            - {name: BYWARD_TLS_CERT_FILE, value: /run/tls/tls.crt}
            - {name: BYWARD_TLS_KEY_FILE, value: /run/tls/tls.key}
          volumeMounts:
            - {name: tls, mountPath: /run/tls, readOnly: true}
      volumes:
        - name: tls
          secret: {secretName: byward-backend-tls}
```

Have the gateway verify byward's certificate. With the Gateway API, use a `BackendTLSPolicy`
(`gateway.networking.k8s.io/v1`; Gateway API v1.7.0):

```yaml
apiVersion: gateway.networking.k8s.io/v1
kind: BackendTLSPolicy
metadata:
  name: byward
  namespace: mcp
spec:
  targetRefs:
    - {group: "", kind: Service, name: byward}
  validation:
    caCertificateRefs:
      - {group: "", kind: ConfigMap, name: internal-ca}
    hostname: byward.mcp.svc
```

An ingress that does not verify byward's certificate gets encryption without authentication: the
hop is private from eavesdroppers, but anything that can take byward's address can impersonate it.

## Azure Container Apps

You do not need it. The Container Apps edge proxy terminates TLS, and "peer-to-peer encryption"
encrypts the traffic within the environment with certificates the platform manages
([Microsoft](https://learn.microsoft.com/azure/container-apps/ingress-environment-configuration)):

```sh
az containerapp env update --name <env> --resource-group <rg> --enable-peer-to-peer-encryption
```

It is off by default.

## Not supported

| What | Why |
|---|---|
| ACME (Let's Encrypt) | It binds ports 80 and 443 and adds state and rate limits ([ADR-0019](../adr/0019-packaging.md)). Use cert-manager, certbot or your platform, and point byward at the files. |
| OCSP stapling | Let's Encrypt ended OCSP on 2025-08-06; revocation is published through CRLs. |
| Several certificates, chosen by SNI | One public URL needs one certificate. |
| Client certificates (mTLS from the ingress) | Not yet. Restrict who reaches the port with a NetworkPolicy. |
| PROXY protocol | Not yet. Use `BYWARD_TRUSTED_PROXIES` with `X-Forwarded-For`. |
| TLS on the internal listener | It binds to loopback or a private address, and it carries no tokens. |
