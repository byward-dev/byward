# Deploy byward

Choose the shape of a production deployment and set it up: how many replicas, where TLS ends,
which ports are public, and how secrets reach the proxy. Start from a working first run
([run byward](run-byward.md)). Every setting is in the [settings reference](../reference/settings.md);
the checklist behind each choice is [harden a deployment](harden-a-deployment.md).

Items about a feature in no release yet say "(on `main`)". The examples use the image
`ghcr.io/byward-dev/byward:v0.2.0-rc.1`.

## 1. Choose one replica or several

| | One replica on SQLite | Several replicas on PostgreSQL (on `main`) |
|---|---|---|
| Store | Embedded SQLite in the data directory, the default ([state](state.md)) | A shared PostgreSQL 15 or later database ([postgres](postgres.md)) |
| Upstream | HTTP or stdio | HTTP only: the proxy refuses to start with a stdio upstream and PostgreSQL |
| Disk | A persistent volume for the data directory | No volume for the store |
| Keys | In the data directory, or mounted | The same sealing and assertion keys mounted into every replica |
| Backup | The state directory ([state](state.md#backups)) | `pg_dump` or the database service's backups ([postgres](postgres.md#backup-and-restore)) |

The SQLite store lives inside the proxy process, on that replica's disk, so it serves one replica
([ADR-0007](../adr/0007-state-and-storage.md)). Use PostgreSQL when you need more than one.

## 2. One replica on SQLite

1. Give the data directory (`BYWARD_DATA_DIR`, default `/var/lib/byward`) a persistent volume that
   uid 65532 can write. By default it holds the sealing keys (`keys/`), the assertion keys
   (`assertion-keys/`), the restore counter (`store-writes`) and the database (`state/`). The proxy
   must be able to write the data directory and the state directory, or it does not start.
2. Run exactly one replica. In Kubernetes, use the `Recreate` strategy, so an upgrade stops the old
   pod before the new one opens the same volume.
3. Back up `state/` only. Keep the restore counter out of that backup, or a restored copy goes
   unnoticed ([restore detection](state.md#restore-detection)). If the keys come from a read-only
   mount, set `BYWARD_STORE_COUNTER_FILE` to a writable path outside `state/`: its default sits next
   to the keys directory ([layouts](state.md#layouts)).
4. Back up the keys, the static clients file and your settings separately and securely.

## 3. Several replicas on PostgreSQL (on `main`)

Follow [run several replicas on PostgreSQL](postgres.md). In short:

1. Create the database and a role ([step 1](postgres.md#1-create-the-database-and-a-role)).
2. Write the connection string to a file and point `BYWARD_STORE_POSTGRES_DSN_FILE` at it, with
   `sslmode=verify-full` ([step 2](postgres.md#2-give-the-proxy-the-connection-string)). Do not set
   `BYWARD_STORE_DIR` or `BYWARD_STORE_COUNTER_FILE` beside it: the proxy refuses them.
3. Mount the same sealing keys (`BYWARD_KEYS_DIR`) and assertion keys (`BYWARD_ASSERTION_KEYS_DIR`)
   into every replica, from one Secret on Kubernetes. Keys never live in the store; a replica with
   other keys refuses the tokens the others sealed.
4. Start the replicas with the same settings ([step 3](postgres.md#3-start-the-replicas)).
   Rate limits count per replica: divide the budgets in `BYWARD_OAUTH_RATE_LIMITS` by the number of
   replicas to keep the total. Scrape every replica's `/metrics` and collect every replica's log.
5. After restoring the database, run `byward store new-epoch --yes`.

## 4. Decide where TLS ends

`BYWARD_PUBLIC_URL` is always the `https` URL users enter, including the MCP path, e.g.
`https://mcp.example.com/mcp`. A non-loopback `http` URL refuses to start.

- **At a reverse proxy, load balancer or ingress** (the usual shape). Set `BYWARD_LISTEN` to the
  address it reaches, e.g. `0.0.0.0:8080` in a container: the default `127.0.0.1:8080` is reachable
  only from the same host or pod. The hop from the ingress to byward carries bearer tokens: keep it
  on a private network, or encrypt it as below.
- **At byward itself** (on `main`). Set `BYWARD_TLS_CERT_FILE` and `BYWARD_TLS_KEY_FILE` to a
  certificate you supply; byward obtains none itself. Use it to encrypt the hop from the ingress, or
  to serve clients directly. Steps, renewal and cert-manager: [serve TLS at the proxy](tls.md).

## 5. Trust the reverse proxy's addresses

Set `BYWARD_TRUSTED_PROXIES` to the addresses or CIDRs your reverse proxy connects from, e.g.
`10.0.0.0/8`. byward then reads the client address from `X-Forwarded-For`
([client address](../reference/rate-limits.md#client-address)). Without it, every request seems to
come from the reverse proxy: all users share one rate-limit budget, and audit records show the
proxy's address as `remote_ip`. List only proxies you control.

## 6. Keep the internal listener private

`/livez`, `/readyz` and `/metrics` are served only on the internal listener,
`BYWARD_INTERNAL_LISTEN` (default `127.0.0.1:9090`), without authentication
([health](../reference/observability.md#health), [metrics](../reference/observability.md#metrics)).

- Leave it on loopback, or in Kubernetes set `:9090` so the kubelet and Prometheus reach the pod IP.
- Never route it through the public ingress, and leave its port out of the Service that fronts the
  proxy. It must differ from `BYWARD_LISTEN`; the proxy refuses to start otherwise.
- Use `/livez` for liveness and `/readyz` for readiness. `/readyz` answers `503` when no sealing key
  signs, the store does not answer, or the proxy is shutting down. The IdP is never part of it.
- Set it empty to turn it off if you probe and scrape nothing.

More: [the internal listener](harden-a-deployment.md#the-internal-listener).

## 7. Run as non-root

The release image runs as uid/gid `65532`, with the state directory `/var/lib/byward` owned by
65532 ([image contract](../reference/packaging.md#image-contract-public-interface)). Keep that user:

- A volume or host directory for the data directory must be writable by uid 65532.
- In Kubernetes, set `runAsNonRoot: true`, `allowPrivilegeEscalation: false`, drop all capabilities
  and use the `RuntimeDefault` seccomp profile.
- When you build your own image with `COPY --from`, keep `USER 65532:65532`.

## 8. Give secrets as files

Secrets are read only from files: the IdP client secret, certificate or key, the upstream
credential, the stdio upstream's environment file and the PostgreSQL connection string (on `main`)
each have a `*_FILE` setting. An inline secret refuses to start.

A secret file, the TLS key and each assertion key must be readable by the proxy's user alone:
mode `0600` or `0400`, owned by uid 65532. A file on a read-only mount passes whatever its mode, as
on a Kubernetes secret volume (`0644` by default) or a Docker mount with `:ro`. Sealing key files may
be group- or other-readable, but never world-writable ([sealing keys](sealing-keys.md#the-key-directory)).

`--dev` (`BYWARD_DEV`) turns these checks off and accepts inline secrets. Never run production with
it, nor with `BYWARD_INSECURE_NO_AUTH`: each logs a `development mode relaxation` warning at every
start.

### What `--dev` relaxes

This is the whole list. Each relaxation applies only with `--dev`, for trying byward out
([try it on your machine](keycloak.md#try-it-on-your-machine)).

| With `--dev` | Without it | Startup log (`development mode relaxation`) |
|---|---|---|
| Secret files' permissions are not checked | A secret file its group or others can read is refused, unless on a read-only mount | `secret file permissions are not checked` |
| Secrets may be given inline, as `BYWARD_<NAME>` instead of `BYWARD_<NAME>_FILE` | An inline secret is refused | `inline secrets accepted: <the settings>` |
| An http public URL on a loopback host (`http://localhost:8080/mcp`) | The public URL must be https | `http public URL on loopback`; `BYWARD_INSECURE_NO_AUTH` allows it too |
| An http OIDC issuer on a loopback host, and http endpoints in its discovery document on loopback | The issuer and every endpoint must be https | not logged in v0.2.0-rc.1 (logged from [#355](https://github.com/byward-dev/byward/issues/355)) |
| A PostgreSQL connection without `sslmode=verify-full` (on `main`) | `verify-full` is required | `the PostgreSQL store accepts a connection without verify-full TLS` |

## 9. Check the deployment

1. `byward check --offline` with the production settings validates them, the keys and the secret
   files as startup does, without network access
   ([check](../reference/commands.md#byward-check---offline)).
2. Once the proxy runs, `byward doctor` probes it through the public URL as MCP clients do, and
   checks the IdP app ([doctor](../reference/commands.md#byward-doctor)). A reverse proxy that
   changes `Host` shows up in its "Host header" check.
3. Verify the image signature and provenance before you deploy
   ([verifying a release](../reference/packaging.md#verifying-a-release)).

## Example: Docker Compose

One replica on SQLite, behind a reverse proxy on the same host. Create the keys in `byward-data`
as for the first run ([create the keys](quickstart-entra.md#2-create-the-keys)), then hand the data
directory and the client secret to uid 65532:

```sh
sudo chown -R 65532:65532 byward-data
sudo chown 65532:65532 entra-client-secret && sudo chmod 0600 entra-client-secret
```

```yaml
services:
  byward:
    image: ghcr.io/byward-dev/byward:v0.2.0-rc.1
    restart: unless-stopped
    ports:
      - "127.0.0.1:8080:8080"   # only the reverse proxy on this host reaches it
    environment:
      BYWARD_PUBLIC_URL: https://mcp.example.com/mcp
      BYWARD_UPSTREAM_URL: http://upstream:3001/mcp   # your MCP server
      BYWARD_ENTRA_TENANT: "<tenant GUID>"
      BYWARD_ENTRA_CLIENT_ID: "<application (client) ID>"
      BYWARD_ENTRA_CLIENT_SECRET_FILE: /run/secrets/entra-client-secret
      BYWARD_LISTEN: 0.0.0.0:8080
      BYWARD_TRUSTED_PROXIES: "<the address the reverse proxy connects from>"
    volumes:
      - ./byward-data:/var/lib/byward
    secrets:
      - entra-client-secret

secrets:
  entra-client-secret:
    file: ./entra-client-secret
```

- The internal listener keeps its default, `127.0.0.1:9090` inside the container. To scrape it
  from another container, set `BYWARD_INTERNAL_LISTEN: 0.0.0.0:9090` and publish no port for it.
- To find the address for `BYWARD_TRUSTED_PROXIES`, start without it, sign in once and read
  `remote_ip` in the `login` audit record.
- Back up `byward-data/state/`, not the whole directory: `store-writes` must stay out of the backup.

## Example: Kubernetes

A sketch of one replica on SQLite, with TLS ending at the ingress. Create the Secrets from the files
of the first run:

```sh
kubectl -n mcp create secret generic byward-sealing-keys --from-file=keys/
kubectl -n mcp create secret generic byward-assertion-keys --from-file=assertion-keys/
kubectl -n mcp create secret generic byward-idp --from-file=client-secret=entra-client-secret
```

```yaml
apiVersion: v1
kind: PersistentVolumeClaim
metadata: {name: byward-data, namespace: mcp}
spec:
  accessModes: [ReadWriteOnce]
  resources: {requests: {storage: 1Gi}}
---
apiVersion: apps/v1
kind: Deployment
metadata: {name: byward, namespace: mcp}
spec:
  replicas: 1                # SQLite: one replica
  strategy: {type: Recreate}
  selector: {matchLabels: {app: byward}}
  template:
    metadata: {labels: {app: byward}}
    spec:
      securityContext:
        runAsNonRoot: true
        runAsUser: 65532
        runAsGroup: 65532
        fsGroup: 65532         # makes the volume writable by the proxy's user
        seccompProfile: {type: RuntimeDefault}
      containers:
        - name: byward
          image: ghcr.io/byward-dev/byward:v0.2.0-rc.1
          env:
            - {name: BYWARD_PUBLIC_URL, value: "https://mcp.example.com/mcp"}
            - {name: BYWARD_UPSTREAM_URL, value: "http://upstream.mcp.svc:3001/mcp"}
            - {name: BYWARD_ENTRA_TENANT, value: "<tenant GUID>"}
            - {name: BYWARD_ENTRA_CLIENT_ID, value: "<application (client) ID>"}
            - {name: BYWARD_ENTRA_CLIENT_SECRET_FILE, value: /etc/byward/idp/client-secret}
            - {name: BYWARD_KEYS_DIR, value: /etc/byward/keys}
            - {name: BYWARD_ASSERTION_KEYS_DIR, value: /etc/byward/assertion-keys}
            - {name: BYWARD_STORE_COUNTER_FILE, value: /var/lib/byward/store-writes}
            - {name: BYWARD_LISTEN, value: "0.0.0.0:8080"}
            - {name: BYWARD_INTERNAL_LISTEN, value: ":9090"}
            - {name: BYWARD_TRUSTED_PROXIES, value: "10.0.0.0/8"}   # your ingress's pod CIDR
          ports:
            - {name: http, containerPort: 8080}
            - {name: internal, containerPort: 9090}
          livenessProbe:
            httpGet: {path: /livez, port: internal}
          readinessProbe:
            httpGet: {path: /readyz, port: internal}
            timeoutSeconds: 3      # each readiness check may take up to 2 s
          securityContext:
            allowPrivilegeEscalation: false
            capabilities: {drop: [ALL]}
          volumeMounts:
            - {name: data, mountPath: /var/lib/byward}
            - {name: sealing-keys, mountPath: /etc/byward/keys, readOnly: true}
            - {name: assertion-keys, mountPath: /etc/byward/assertion-keys, readOnly: true}
            - {name: idp, mountPath: /etc/byward/idp, readOnly: true}
      volumes:
        - {name: data, persistentVolumeClaim: {claimName: byward-data}}
        - {name: sealing-keys, secret: {secretName: byward-sealing-keys}}
        - {name: assertion-keys, secret: {secretName: byward-assertion-keys}}
        - {name: idp, secret: {secretName: byward-idp}}
---
apiVersion: v1
kind: Service
metadata: {name: byward, namespace: mcp}
spec:
  selector: {app: byward}
  ports:
    - {name: http, port: 8080, targetPort: http}   # never the internal port
```

- The keys come from read-only Secret volumes, so `BYWARD_STORE_COUNTER_FILE` moves the restore
  counter onto the data volume, outside `state/`. Back up `state/` by copying it, not by
  snapshotting the whole volume, or give the counter its own small volume.
- Point your ingress at the `byward` Service, and restrict port 9090 with a NetworkPolicy to the
  kubelet and Prometheus.
- For several replicas on PostgreSQL (on `main`): drop the PersistentVolumeClaim, the `data` volume
  and `BYWARD_STORE_COUNTER_FILE`; mount the connection string from a Secret and set
  `BYWARD_STORE_POSTGRES_DSN_FILE`; raise `replicas` and drop `strategy`. Every replica mounts the
  same key Secrets.
- For TLS from the ingress to byward (on `main`), mount a cert-manager Secret and set the TLS
  settings ([Kubernetes with cert-manager](tls.md#kubernetes-with-cert-manager)).
