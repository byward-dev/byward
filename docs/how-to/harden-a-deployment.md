# How to harden a deployment

A checklist for operators putting byward in front of an MCP server for real users. It
describes `main`; items about a feature in no release yet say "(on `main`)". The reasoning behind
each item is in the [security posture](../security-posture.md). Every setting is listed in the
[settings reference](../reference/settings.md).

## TLS and the reverse proxy

TLS usually ends at an ingress or a reverse proxy. byward can also terminate it with a certificate you
supply ([Serve TLS at the proxy](tls.md), [ADR-0019](../adr/0019-packaging.md) §9 as amended).

- [ ] Set `BYWARD_PUBLIC_URL` to the https URL users enter, including the MCP path, e.g.
      `https://mcp.example.com/mcp`. Leave off the trailing slash, and give an internationalized host
      in its `xn--` form. A non-loopback `http` URL refuses to start.
- [ ] With an `https` public URL, every answer carries `Strict-Transport-Security: max-age=31536000`
      (one year, no `includeSubDomains` or `preload`), so a browser on the sign-in and consent pages
      is never downgraded to http. It needs no setting. If the ingress adds its own, keep one: a
      browser uses only the first (RFC 6797 §8.1). For a year after, browsers turn every http request
      to that host into https, so serve it over https only.
- [ ] Protect the hop from the ingress to the proxy: it carries bearer tokens. Either keep it on a
      private network, or encrypt it with `BYWARD_TLS_CERT_FILE` and `BYWARD_TLS_KEY_FILE`
      ([Serve TLS at the proxy](tls.md)). Have the ingress verify the proxy's certificate (with a
      Gateway API `BackendTLSPolicy`, for example). An ingress that does not verify it gets encryption
      without authentication: anything that takes the proxy's address can impersonate it.
- [ ] Set `BYWARD_LISTEN` to the address the ingress reaches, e.g. `0.0.0.0:8080` in a
      container. The default `127.0.0.1:8080` is reachable only from the same host or pod.
- [ ] Set `BYWARD_TRUSTED_PROXIES` to the ingress's addresses or CIDRs, e.g. `10.0.0.0/8`.
      Without it, every request seems to come from the ingress. All users then share one rate-limit
      budget, and logs and audit records show the ingress address. List only proxies you control: a
      trusted CIDR that includes client networks lets those clients choose their own address. How
      the address is read from `X-Forwarded-For`: [rate limits](../reference/rate-limits.md#client-address).
- [ ] For an IdP or upstream with a private CA, add only that CA with `SSL_CERT_FILE`. Don't
      mount over the image's `/etc/ssl/certs`, or set `SSL_CERT_DIR` without it beside
      `SSL_CERT_FILE`: either drops the public roots. Every outbound TLS connection trusts the CA
      you add ([trust a private CA](private-ca.md)).

## Host and Origin allowlists

Both checks run before authentication ([ADR-0018](../adr/0018-hardening.md) §1–2).

- [ ] **Host:** the public URL's host is always accepted, and `:80` and `:443` are ignored when
      comparing. If the ingress sends a different `Host`, such as an internal service name, add it to
      `BYWARD_ALLOWED_HOSTS`. A mismatch gets `421` and a `host_rejected` audit event. Prefer an
      ingress that passes the original `Host` through, and keep the list short.
- [ ] **Origin:** browser-based MCP clients send an `Origin`. Only the proxy's own origin and exact
      entries in `BYWARD_ALLOWED_ORIGINS` (`scheme://host[:port]`) pass; anything else gets
      `403` and an `origin_rejected` event. Requests without `Origin` (desktop and CLI clients) pass.
      Add only the origins of web clients you use. Never add a wildcard; none is supported.

## Sealing keys and secret files

- [ ] Create the key directory as in [sealing keys](sealing-keys.md): mode `0700`, one file per key,
      `openssl rand -base64 32`, owned by the proxy's user (uid 65532 in the image).
      - The proxy refuses a world-writable key file or directory, unless the directory is on a
        read-only mount such as a Kubernetes secret volume.
      - It does **not** refuse group- or other-readable files. Use `0600` (or `0400`) yourself
        wherever the platform allows.
- [ ] Create the identity assertion's signing key as in [identity assertion](identity-assertion.md):
      a separate directory, `BYWARD_ASSERTION_KEYS_DIR`, mode `0700`, one PEM P-256 file per key,
      `0600` and owned by the proxy's user. Unlike sealing keys, a key file other users can read is
      refused, unless it is on a read-only mount.
- [ ] Leave `BYWARD_IDENTITY_HEADERS` off unless the upstream cannot verify a JWT. If you turn it
      on, make sure the upstream is reachable through the proxy alone, and run `byward doctor`
      ([plain identity headers](plain-identity-headers.md)).
- [ ] If the upstream needs the proxy's own credential, give it in `BYWARD_UPSTREAM_CREDENTIAL_FILE`,
      `0600` and owned by the proxy's user, never inline; it and the assertion use separate headers
      ([upstream credential](upstream-credential.md)).
- [ ] Configure the upstream's verifier with the audience `BYWARD_UPSTREAM_URL` exactly, and with
      the public https JWKS or a pinned `byward jwks` file. The internal listener's JWKS is plain
      http: only on the same host, or under a NetworkPolicy **and** mesh mTLS
      ([identity assertion](identity-assertion.md#2-point-the-upstream-at-the-public-keys)).
- [ ] Keep keys out of backups of the state directory, and out of images and repositories. The
      store never holds them ([ADR-0007](../adr/0007-state-and-storage.md) §5).
- [ ] Rotate by adding a file whose name sorts last (date names), restarting, and removing the old
      file 15 days after that restart, so no user has to sign in again
      ([sealing keys](sealing-keys.md#rotating) explains the 15 days and the several-replica case).
- [ ] Know the operator revocation commands. They read the same `BYWARD_*` environment as the
      proxy (run them in its container or with its settings), write to the same store while it
      runs, and every proxy refuses the tokens within seconds (the deny list resyncs every 5 s):
      - `byward revoke-user <user key>` ends one user's access: their grants are deleted, so their
        refresh tokens stop at once, and their access tokens are refused. The key is the
        `user_key` of the audit stream: with Entra `tid:oid`, the portal's tenant and object IDs
        in either case; with an oidc IdP the value of its subject claim, exactly. An
        [app-only caller](app-tokens.md)'s key is its service principal's `tid:oid`: its tokens
        issued before the revocation are refused.
      - `byward revoke-all --yes` does the same for every user (incident response).
      - Each writes a `grant_revoked` audit record with the reason `operator revoke-user` or
        `operator revoke-all`. A user who still passes the access gate can sign in again; to keep
        them out, also block them at the IdP or in the gate.
      - If the sealing keys may be compromised, also replace every key file and restart: that
        invalidates every token at once, whatever the store holds.
- [ ] Give secrets only as files:
      - the Entra credential: preferably a certificate, `BYWARD_ENTRA_CLIENT_CERTIFICATE_FILE` (see
        below); or the client secret through `BYWARD_ENTRA_CLIENT_SECRET_FILE` (or
        `--entra-client-secret-file`); or no secret at all: where the platform hands the proxy a
        federated token (AKS workload identity, GitHub Actions), point
        `BYWARD_ENTRA_FEDERATED_TOKEN_FILE` at it and give the app a matching federated identity
        credential ([an example](../maintainers/real-entra-lane.md#3-run-it-once-then-create-the-federated-credential));
      - static client secrets through `client_secret_file` in the
        [static clients file](../reference/static-clients.md);
      - static client secrets must be at least 32 bytes.

      An inline secret refuses to start unless `--dev` is set. So does a secret file that its group
      or others can read or write (mode `0600` or `0400`, owned by the proxy's user), unless it is
      on a read-only mount such as a Kubernetes secret volume (default mode `0644`).
      - Docker Compose: use `secrets:` (Compose mounts those read-only) or a volume with `:ro`, e.g.
        `./entra-secret:/run/secrets/entra:ro`. A host file at `0600` owned by your user cannot be
        read by the image's uid 65532, and `chmod 644` without `:ro` is refused.
- [ ] Never run production with `BYWARD_DEV` or `BYWARD_INSECURE_NO_AUTH`. Each logs a
      `development mode relaxation` warning at every start; alert on that message.

## The Entra app registration

Background: [ADR-0012](../adr/0012-entra-specifics.md), [ADR-0015](../adr/0015-access-gate.md) and
[access gate](access-gate.md).

- [ ] **Single tenant.** `BYWARD_ENTRA_TENANT` must be a tenant GUID. Multi-tenant
      (`organizations`) cannot be configured through the settings.
- [ ] **Redirect URI** `https://<public host>/callback/entra`, built from the public URL's scheme and
      host.
- [ ] **Expose an API** with the scope `access_as_user` and `requestedAccessTokenVersion: 2`. The proxy
      asks for `openid profile email offline_access api://<client-id>/access_as_user`, and sign-in
      fails if the access token lacks that scope.
- [ ] **Assignment required = Yes** on the enterprise application: `appRoleAssignmentRequired` on the
      service principal, which Microsoft Graph documents as "whether users or other service principals
      need to be granted an app role assignment … before users can sign in". Unassigned users are then
      stopped by Entra (AADSTS50105).
- [ ] **App roles and the gate.** Define a role such as `MCP.User`, assign it, and set
      `BYWARD_GATE_ROLES=MCP.User`.
      - Global Administrators can sign in regardless of assignment; the role gate still applies to
        them.
      - "Default Access" assignments carry no `roles` claim.
      - Use `BYWARD_GATE_GROUPS` only with `groupMembershipClaims: ApplicationGroup`. A user in
        too many groups (groups overage) is denied.
      - An empty gate lets every user of the tenant in, guests included unless you restrict them, and
        logs a warning at every start.
- [ ] **Admin consent** for the app's permissions, so users do not see a second consent screen from
      Entra after ours (ADR-0012 §12).
- [ ] **Client secret expiry.**
      - Entra limits client secrets to two years.
      - Set `BYWARD_ENTRA_CLIENT_SECRET_EXPIRES_AT` to the secret's end date: the proxy then warns at
        every start, and `byward doctor` from 30 days before
        ([commands](../reference/commands.md#byward-doctor)). Put the date in your monitoring too.
      - An expired or wrong secret makes sign-ins fail, and refreshes answer `503` instead of signing
        users out. Alert on any increase of
        `byward_idp_alerts_total{reason="credential_rejected"}`
        ([observability](../reference/observability.md#metrics)).
- [ ] **Use a certificate credential** instead of a client secret (ADR-0012 §5; Microsoft: "It's
      therefore recommended that your application uses a certificate rather than a secret"). The
      private key stays on the proxy's machine, and Entra gets only a short-lived signed assertion.
      `byward init entra --credential certificate` makes one; the
      [certificate how-to](entra-certificate.md) covers making, uploading and rotating it. byward
      reads the certificate's end date itself, warns from 30 days before, and refuses to start
      once it has expired.
- [ ] Gate changes take effect after a restart, at each user's next sign-in or refresh: at most one
      access-token lifetime (1 h) later. To cut someone off sooner, use `byward revoke-user` (above);
      to keep them out, remove their assignment in Entra, after which their next refresh fails too.

## An OIDC IdP

For Google, Okta, Keycloak, Auth0 or another OpenID Connect IdP ([OIDC how-to](oidc.md)).

- [ ] **A confidential client**, with the redirect URI `https://<public host>/callback/<idp>`
      (`<idp>` is the `BYWARD_IDP` value; the proxy logs the exact URI at startup).
- [ ] **The credential as a file:** `BYWARD_OIDC_CLIENT_SECRET_FILE`, or a key for `private_key_jwt`
      in `BYWARD_OIDC_CLIENT_KEY_FILE` with `BYWARD_OIDC_CLIENT_KEY_ID`. The secret-file rules above
      apply to both.
- [ ] **A gate.** With an empty gate anyone with an account at the IdP could sign in, so the proxy
      refuses to start unless `BYWARD_GATE_ALLOW_EMPTY=true`. Gate on roles, groups, a verified email
      domain or a Google Workspace domain ([access gate](access-gate.md)).
- [ ] **A stable subject.** Keep `BYWARD_OIDC_SUBJECT_CLAIM` at `sub`. A claim users can change
      (`email`, `preferred_username`, `upn`, `name`) logs a warning at every start: someone could take
      over another user's grants by changing it.
- [ ] **An ID token on refresh.** The gate is checked again at every refresh, so the IdP must return
      an ID token then; a refresh without one ends the grant ([OIDC how-to](oidc.md)).
- [ ] Run `byward doctor`: it checks discovery and the issuer, and (on `main`) that the IdP accepts
      the client ID and the secret or key.

## The internal listener

`/metrics`, `/livez` and `/readyz` are served only on the internal listener
(`BYWARD_INTERNAL_LISTEN`, default `127.0.0.1:9090`). They have no authentication. The `Host`
check there accepts any IP address and `localhost`, which is what the kubelet and Prometheus send,
plus the names in `BYWARD_ALLOWED_HOSTS`; any other name gets `421`, which stops DNS rebinding.

- [ ] Keep it on loopback, or in Kubernetes on `:9090` with that port left out of the Service that
      fronts the proxy. Restrict it with a NetworkPolicy to the kubelet and Prometheus.
- [ ] Never route it through the public ingress. It must differ from `BYWARD_LISTEN`; the
      proxy refuses to start otherwise.
- [ ] Set it empty to turn it off if you scrape nothing.
- [ ] If Prometheus scrapes by a DNS name instead of the pod IP, add that name to
      `BYWARD_ALLOWED_HOSTS`.

## State, backups and restore

- [ ] **State lives in SQLite** by default, under the data directory: `state/byward.db` (with its
      `-wal` and `-shm` files), mode 0600 in a 0700 directory ([state](state.md)). Grants, refresh
      tokens and revocations survive a restart; the revocation list is reloaded from the store before
      the proxy serves.
- [ ] **One replica on SQLite.** For several, use the PostgreSQL store (on `main`,
      [postgres](postgres.md)); a stdio upstream stays on one replica, and the proxy refuses to start
      with a stdio upstream and PostgreSQL. With PostgreSQL:
      - give the connection string as a file (`BYWARD_STORE_POSTGRES_DSN_FILE`, mode `0600`), with
        `sslmode=verify-full`;
      - give every replica the same sealing and assertion keys: they never live in the store;
      - after restoring the database, run `byward store new-epoch --yes`
        ([postgres](postgres.md#backup-and-restore)).
- [ ] **Back up the state directory** (see [state](state.md)), and separately and securely the key
      directory, the static clients file with its secret and JWKS files, and your settings.
- [ ] **Keep the restore counter outside the backup.** `store-writes` sits next to the key
      directory, not inside `state/`, so the proxy can notice a restored older store and refuse the
      refresh tokens issued before it ([restore detection](state.md#restore-detection)).

## Logs and the audit stream

- [ ] Ship logs and audit records off the host (OWASP ASVS 16.4.3). The proxy writes JSON lines to
      **standard error** (`cmd/byward/main.go`). Audit records carry `log.type=audit` and
      `schema_version=1` ([observability](../reference/observability.md#audit-stream)). There is no
      file sink.
- [ ] Treat `user_key` (`tid:oid` for Entra) and `remote_ip` as personal data (GDPR Recital 26) and
      set retention accordingly. Email and name are never logged.
- [ ] No token, secret, authorization code or PKCE verifier is logged.
      - Attribute keys are allowlisted.
      - Bearer- and JWT-shaped values are redacted.
      - Request lines carry the path without the query string.
      - The startup log prints every effective setting with secrets as `<redacted>`.
- [ ] Alert on at least these:
      - `development mode relaxation` at startup;
      - `grant_revoked` with a reuse reason, which can mean token theft;
      - spikes of `access_token_rejected`, `origin_rejected`, `host_rejected` or `rate_limited`;
      - IdP `unavailable` outcomes;
      - any increase of `byward_idp_alerts_total`: the IdP refuses the proxy's own credential, the
        proxy cannot build it, or the IdP breaks the protocol; no user can fix these (`reason` says
        which).

      Example rules are in the [observability reference](../reference/observability.md#metrics).
- [ ] Tracing is off unless you set `OTEL_TRACES_EXPORTER`. When on, send it only to a collector you
      run.

## Rate limits

The OAuth endpoints, `/register` included, are rate-limited per client address, with IPv6 grouped
by /64. The budgets per endpoint: [rate limits](../reference/rate-limits.md#budgets).

- [ ] Set `BYWARD_TRUSTED_PROXIES` ([TLS and the reverse proxy](#tls-and-the-reverse-proxy)), or every user shares one budget.
- [ ] Raise budgets for offices or VPNs behind one address with `BYWARD_OAUTH_RATE_LIMITS`,
      e.g. `authorize=120,callback=120`. Each value is 1–10,000; there is no off switch.
- [ ] MCP traffic itself is not rate-limited (ADR-0001), only capped in flight: 64 requests and
      256 streams, then `503`. Put request-rate limits for MCP traffic in your ingress if you need
      them.
- [ ] An upstream that sends no response headers within `BYWARD_UPSTREAM_HEADER_TIMEOUT` (default
      `5m`, 1 s to 1 h) frees its slot, and the client gets a JSON-RPC timeout error. Raise it if a
      tool answers with plain JSON after more than 5 minutes; a streamed (SSE) answer is not limited
      once its headers arrive. Keep your ingress's upstream timeout above it.

## Run as non-root

- [ ] Use the release image. It runs as uid/gid `65532` on `distroless/static-debian13:nonroot`,
      pinned by digest, with the binary at `/usr/local/bin/byward` and the state directory
      `/var/lib/byward` owned by 65532 ([packaging](../reference/packaging.md#image-contract-public-interface)).
      When you build your own image with `COPY --from`, keep `USER 65532:65532`.
- [ ] In Kubernetes, set `runAsNonRoot: true`, `allowPrivilegeEscalation: false`, drop all
      capabilities and use a `RuntimeDefault` seccomp profile.
      - Mount a writable volume at `/var/lib/byward` (the data directory).
      - `readOnlyRootFilesystem: true` is not tested yet: SQLite may need a writable temporary
        directory, so if you set it, also mount an `emptyDir` at `/tmp` and check startup.
- [ ] Verify the image signature and provenance before deploying
      ([packaging](../reference/packaging.md#verifying-a-release)).
- [ ] Track releases: security fixes go into the latest minor only ([SECURITY.md](../../SECURITY.md)).

## Isolate stdio upstream processes

Every stdio upstream process runs as byward's own uid, whichever user it serves. Separate processes
and `{session_dir}` keep sessions apart by default ([stdio how-to](stdio-upstream.md#3-isolate-state-between-sessions)),
but not against a server that is compromised or hostile: such a process can read another's
`{session_dir}` files and its environment, which needs only the same uid (`/proc/<pid>/environ`).
Its memory is protected only by the host's ptrace restriction. With On-Behalf-Of on, that memory
holds the user's downstream token, so byward warns at startup and in `doctor` when
`kernel.yama.ptrace_scope` is `0` or missing.

- [ ] Set `kernel.yama.ptrace_scope` to `1` or higher on the host:
      `cat /proc/sys/kernel/yama/ptrace_scope` must not print `0`, and a missing file means the
      kernel has no Yama at all. With `1`, a process can attach only to its own descendants, so
      one upstream process cannot read another's memory
      ([kernel Yama docs](https://docs.kernel.org/admin-guide/LSM/Yama.html)).
      - The setting is host-wide: a container cannot change it. In Kubernetes, set it on the node.
      - Ubuntu sets `1` (`/etc/sysctl.d/10-ptrace.conf`, from `procps`). Debian's kernels turn Yama
        off by default (`0`), so a Debian host needs
        `echo kernel.yama.ptrace_scope=1 > /etc/sysctl.d/10-ptrace.conf && sysctl --system`.
      - It does not cover the environment: put nothing in an upstream's environment that another
        user's process must not see.
- [ ] Keep the runtime's default seccomp profile and drop all capabilities ([Run as non-root](#run-as-non-root)). Docker's
      default profile allows `pidfd_getfd`, which copies another process's file descriptors, only
      with `CAP_SYS_PTRACE`, and Docker does not grant that capability.
- [ ] Run an upstream server you do not trust in its own deployment: one byward per such server,
      in its own container or VM, and per tenant or user group where their data must stay apart
      even if the server is compromised. byward does not sandbox stdio processes from each other.

## Protect the upstream hop

Every request byward relays to an HTTP upstream carries the identity assertion, and, when they are
configured, the upstream credential and an On-Behalf-Of token for a downstream API. Over plain
`http` they travel in clear to anyone on the path.

- [ ] Reach the upstream over `https`, through a service mesh that encrypts the hop (mTLS), or over a
      private network that only byward and the upstream are on, with a NetworkPolicy (or firewall
      rule) that admits byward alone. byward warns at startup and in `byward doctor` when the
      upstream is `http` and its host resolves to a public address; a private address gets no
      warning, so the network rule is yours to check.
- [ ] Switching `BYWARD_UPSTREAM_URL` to `https` changes the assertion's `aud`, which is that URL
      exactly: change the upstream verifier's audience at the same time
      ([identity assertion](identity-assertion.md)).
- [ ] Set `BYWARD_UPSTREAM_URL` to the upstream's MCP endpoint itself. An upstream that answers
      with a redirect (`http` to `https`, a trailing slash) gets the MCP client a 502, and the log
      line "upstream redirected the request" names where it pointed.
- [ ] Mind the environment's HTTP proxy. The relay honours `HTTPS_PROXY` and `HTTP_PROXY` (for an
      `https` and an `http` upstream), so with one set the hop goes through that proxy, which sees
      the assertion and the credential of a plain-http upstream. List the upstream's host in
      `NO_PROXY` to reach it directly. `byward doctor` names the proxy the upstream's requests go
      through. An upstream at `localhost` or at a loopback IP address never uses one; any other
      name does unless `NO_PROXY` lists it, even one that resolves to a loopback address. A proxy
      setting Go cannot parse is ignored, and the hop then goes direct. A setting whose credentials
      hold an unescaped `/`, `?` or `#` makes Go dial part of the credentials as the proxy host.
      The relay's "upstream error" log, IdP sign-in, refresh, discovery and readiness failures,
      doctor's checks and failed trace exports then name the cause instead of quoting the address,
      and `byward doctor` warns about the setting.

## Strip the upstream's header-driven settings

byward removes a fixed set of request headers before relaying (`Authorization`, `DPoP`,
`Forwarded`, `Origin`, `X-Forwarded-*`, `Sec-Fetch-*`, and the headers it sets itself) and forwards
every other header the MCP client sends. Some MCP servers read a target URL or a credential from a
request header. Behind byward, a signed-in client could then point the upstream elsewhere or swap
its credentials.

- [ ] Read your upstream's documentation for settings it takes from request headers, and list
      those headers in `BYWARD_UPSTREAM_STRIP_HEADERS`, comma-separated. Names match in any case,
      with `_` read as `-`. Some upstreams that read such headers:

      | Upstream | Headers |
      |---|---|
      | OpenSearch MCP (with `OPENSEARCH_HEADER_AUTH=true`) | `opensearch-url`, `opensearch-cluster-name`, `aws-region`, `aws-access-key-id`, `aws-secret-access-key`, `aws-session-token`, `aws-service-name` |
      | Argo CD MCP | `x-argocd-base-url`, `x-argocd-api-token` |
      | Terraform MCP | `TFE_TOKEN`, `TFE_SKIP_TLS_VERIFY` |
      | Grafana MCP | `X-Grafana-URL`, `X-Grafana-Service-Account-Token`, `X-Grafana-API-Key`, `X-Grafana-Org-Id` |
      | mcp-atlassian | `X-Atlassian-Jira-Url`, `X-Atlassian-Confluence-Url`, `X-Atlassian-Jira-Personal-Token`, `X-Atlassian-Confluence-Personal-Token`, `X-Atlassian-Cloud-Id` |

      Check the version you run: these lists change between releases.
- [ ] List exact names. A pattern such as `X-Atlassian-*` is refused, so name each header of a
      family.
- [ ] Keep the headers MCP needs. `Accept`, `Content-Type`, `Content-Length`, `Transfer-Encoding`,
      `Host`, `Last-Event-ID`, `Mcp-Session-Id`, `MCP-Protocol-Version`, `Mcp-Method`, `Mcp-Name` and
      every `Mcp-Param-*` header are refused: MCP 2026-07-28 requires a proxy to forward an
      `Mcp-Param-*` header it does not know. `traceparent` and `tracestate` are refused too: with
      tracing on, byward sets them from the inbound trace context, so listing them would remove
      nothing.
- [ ] A name byward strips anyway (its own headers, the hop-by-hop ones such as
      `Proxy-Authorization`) is accepted and changes nothing; the startup log, `check` and `doctor`
      say so.
- [ ] Prefer settings the upstream reads from its own configuration. A header the upstream takes
      from any caller is safe only while byward is the only way to reach the upstream.

