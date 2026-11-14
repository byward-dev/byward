# Trust a private CA

Use this when the IdP (a self-hosted Keycloak, for example) or the HTTP upstream has a certificate
from your own CA. byward has no CA setting of its own: it trusts the roots Go loads, and you add
your CA through Go's `SSL_CERT_FILE` (or `SSL_CERT_DIR`).

Those roots apply to every connection byward opens with TLS:
- the IdP (discovery, keys, sign-in, refresh, On-Behalf-Of);
- the HTTP upstream;
- the OpenTelemetry exporter;
- the fetches of client-supplied URLs (CIMD documents and `jwks_uri`). These go through the SSRF
  guard, which uses the same roots.

Go reads the roots once, at start, so restart byward after changing them.

## In the byward image

Mount a PEM file that holds your CA (only yours) and point `SSL_CERT_FILE` at it:

```sh
docker run … -v /etc/pki/my-ca.pem:/etc/byward/ca.pem:ro -e SSL_CERT_FILE=/etc/byward/ca.pem …
```

The file does not need the public CAs as well. On Linux, `SSL_CERT_FILE` replaces only the bundle
*file* Go reads; Go still reads every file in `/etc/ssl/certs`. In the image, that directory holds
the public bundle (`ca-certificates.crt`), so Entra, Google and other public IdPs keep working.

`byward doctor` checks the result. Its "trust store" line says where the roots come from and how
many there are, and its IdP discovery line passes only if byward trusts the IdP's certificate.

What each way of adding a CA leaves byward trusting, measured in the image (Go 1.27.4,
`distroless/static-debian13`):

| Setting | Public roots | Your CA |
|---|---|---|
| Nothing (the image sets `SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt`) | yes | no |
| `SSL_CERT_FILE=/etc/byward/ca.pem` | yes | yes |
| One file mounted into the directory: `-v my-ca.pem:/etc/ssl/certs/my-ca.pem:ro` | yes | yes |
| `SSL_CERT_DIR=/etc/byward/ca:/etc/ssl/certs` (a list that keeps `/etc/ssl/certs`) | yes | yes |
| `SSL_CERT_DIR=/etc/byward/ca` alone: it replaces the directories, but Go still reads the bundle file `/etc/ssl/certs/ca-certificates.crt` | yes | yes |
| `SSL_CERT_FILE=/etc/byward/ca.pem` and `SSL_CERT_DIR=/etc/byward/ca`: Go reads only those | **no** | yes |
| A volume mounted over the whole `/etc/ssl/certs` | **no** | yes |
| `SSL_CERT_FILE` naming a file that does not exist | yes | **no**, without an error |

Go silently ignores an `SSL_CERT_FILE` it cannot read or that holds no certificate (the last row),
and likewise an `SSL_CERT_DIR` entry that does not exist, is not a directory it can read, or holds no
certificate. `byward doctor`'s "trust store" line warns about each of those (a missing entry only when
every entry is missing; beside an entry that exists, it is reported as skipped), and about an
`SSL_CERT_FILE` other than the image's bundle with an `SSL_CERT_DIR` that leaves out `/etc/ssl/certs`.

## Kubernetes, with trust-manager

cert-manager's [trust-manager](https://cert-manager.io/docs/trust/trust-manager/) copies a CA into
a ConfigMap in every namespace you select. This was written against v0.26.0, API
`trust.cert-manager.io/v1alpha1`.

Keep your CA in its own ConfigMap or Secret in trust-manager's trust namespace (`cert-manager` by
default). Don't point trust-manager at the `ca.crt` of a cert-manager Secret. trust-manager's docs
warn against it: when the issuer rotates, the new root replaces the old one at once, and the old
one is no longer trusted.

```yaml
apiVersion: trust.cert-manager.io/v1alpha1
kind: Bundle
metadata:
  name: my-org-ca            # the ConfigMap trust-manager writes has this name
spec:
  sources:
    - configMap:
        name: my-org-root-ca # in the trust namespace
        key: ca.pem
  target:
    configMap:
      key: ca.pem
    namespaceSelector:
      matchLabels:
        byward.dev/trust: my-org-ca
```

Label byward's namespace `byward.dev/trust=my-org-ca`, then mount the ConfigMap and set
`SSL_CERT_FILE`:

```yaml
    spec:
      containers:
        - name: byward
          env:
            - name: SSL_CERT_FILE
              value: /etc/byward/ca/ca.pem
          volumeMounts:
            - name: org-ca
              mountPath: /etc/byward/ca
              readOnly: true
      volumes:
        - name: org-ca
          configMap:
            name: my-org-ca
```

Mount it at its own path, never over `/etc/ssl/certs`; see the table above. When the bundle
changes, restart the Deployment (`kubectl rollout restart`): byward reads the roots only at start.

## Outside the image

- **Linux:** Go reads the first of the distribution's bundle files it finds, plus every file in
  `/etc/ssl/certs` and `/etc/pki/tls/certs`. `SSL_CERT_FILE` replaces the bundle file and
  `SSL_CERT_DIR` replaces the directories. Whether the public roots survive `SSL_CERT_FILE` depends
  on whether your distribution keeps its bundle in one of those directories. Adding your CA to the
  system trust store (`update-ca-certificates`, `update-ca-trust`) avoids the question.
- **macOS:** with either variable set, Go (since 1.27) stops using the system verifier and trusts
  only the files you name. An `SSL_CERT_FILE` that exists but cannot be read, or an `SSL_CERT_DIR`
  entry that is a file or a directory Go may not read, falls back to the system verifier, unless
  another entry or the other setting yields a certificate.
  `GODEBUG=x509sslcertoverrideplatform=0` keeps the system verifier and ignores both variables. Add
  your CA to the keychain instead.
