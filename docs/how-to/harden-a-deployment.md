# How to harden a deployment

A checklist for operators putting mcp-authproxy in front of an MCP server for real users. It
describes `main` as of 2026-11-06. Items marked **planned** do not exist yet. The reasoning behind
each item is in the [security posture](../security-posture.md). Every setting is listed in the
[settings reference](../reference/settings.md).

## 1. TLS and the reverse proxy

The proxy does not terminate TLS ([ADR-0019](../adr/0019-packaging.md) §9). Put it behind an ingress
or a reverse proxy that does.

- [ ] Set `MCP_AUTHPROXY_PUBLIC_URL` to the https URL users enter, including the MCP path, e.g.
      `https://mcp.example.com/mcp`. Leave off the trailing slash, and give an internationalized host
      in its `xn--` form. A non-loopback `http` URL refuses to start.
- [ ] Keep the hop from the ingress to the proxy on a private network. That hop is plain HTTP and
      carries bearer tokens.
- [ ] Set `MCP_AUTHPROXY_LISTEN` to the address the ingress reaches, e.g. `0.0.0.0:8080` in a
      container. The default `127.0.0.1:8080` is reachable only from the same host or pod.
- [ ] Set `MCP_AUTHPROXY_TRUSTED_PROXIES` to the ingress's addresses or CIDRs, e.g. `10.0.0.0/8`.
      Without it, every request seems to come from the ingress. All users then share one rate-limit
      budget, and logs and audit records show the ingress address.
      - With the setting, the client address is the rightmost `X-Forwarded-For` entry that is not a
        trusted proxy, so a client cannot spoof it by adding entries on the left.
      - `Forwarded` (RFC 7239) is not read.
      - List only proxies you control. A trusted CIDR that includes client networks lets those
        clients choose their own address.

## 2. Host and Origin allowlists

Both checks run before authentication ([ADR-0018](../adr/0018-hardening.md) §1–2).

- [ ] **Host:** the public URL's host is always accepted, and `:80` and `:443` are ignored when
      comparing. If the ingress sends a different `Host`, such as an internal service name, add it to
      `MCP_AUTHPROXY_ALLOWED_HOSTS`. A mismatch gets `421` and a `host_rejected` audit event. Prefer an
      ingress that passes the original `Host` through, and keep the list short.
- [ ] **Origin:** browser-based MCP clients send an `Origin`. Only the proxy's own origin and exact
      entries in `MCP_AUTHPROXY_ALLOWED_ORIGINS` (`scheme://host[:port]`) pass; anything else gets
      `403` and an `origin_rejected` event. Requests without `Origin` (desktop and CLI clients) pass.
      Add only the origins of web clients you use. Never add a wildcard; none is supported.

## 3. Sealing keys and secret files

- [ ] Create the key directory as in [sealing keys](sealing-keys.md): mode `0700`, one file per key,
      `openssl rand -base64 32`, owned by the proxy's user (uid 65532 in the image).
      - The proxy refuses a world-writable key file or directory, unless the directory is on a
        read-only mount such as a Kubernetes secret volume.
      - It does **not** refuse group- or other-readable files. Use `0600` (or `0400`) yourself
        wherever the platform allows.
- [ ] Keep keys out of backups of the state directory, and out of images and repositories. The
      store never holds them ([ADR-0007](../adr/0007-state-and-storage.md) §5).
- [ ] Rotate by adding a file whose name sorts last (date names), restarting, and removing the old
      file later ([sealing keys](sealing-keys.md#rotating)).
      - A removed key no longer opens anything it sealed. Besides access tokens, that includes the
        IdP tokens kept in each grant.
      - A grant whose IdP tokens were last sealed with a removed key is revoked at its next refresh,
        and the user signs in again (`internal/broker/refresh.go`).
      - Today the restart already ends every grant, because state is in memory (section 6). Once the
        SQLite store is wired (#50), keep an old key for the refresh-token lifetime (30 days) to avoid
        those sign-ins, or accept them.
- [ ] Emergency "sign everyone out": replace every key file and restart. Every access token then
      fails at once. A dedicated `revoke-all` command is not built yet.
- [ ] Give secrets only as files:
      - the Entra client secret through `MCP_AUTHPROXY_ENTRA_CLIENT_SECRET_FILE` (or
        `--entra-client-secret-file`);
      - static client secrets through `client_secret_file` in the
        [static clients file](../reference/static-clients.md);
      - static client secrets must be at least 32 bytes.

      An inline secret refuses to start unless `--dev` is set. The proxy does not check secret
      file permissions: make each file `0600` (or a read-only secret mount) owned by the proxy's
      user.
- [ ] Never run production with `MCP_AUTHPROXY_DEV` or `MCP_AUTHPROXY_INSECURE_NO_AUTH`. Each logs a
      `development mode relaxation` warning at every start; alert on that message.

## 4. The Entra app registration

Background: [ADR-0012](../adr/0012-entra-specifics.md), [ADR-0015](../adr/0015-access-gate.md) and
[access gate](access-gate.md).

- [ ] **Single tenant.** `MCP_AUTHPROXY_ENTRA_TENANT` must be a tenant GUID. Multi-tenant
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
      `MCP_AUTHPROXY_GATE_ROLES=MCP.User`.
      - Global Administrators can sign in regardless of assignment; the role gate still applies to
        them.
      - "Default Access" assignments carry no `roles` claim.
      - Use `MCP_AUTHPROXY_GATE_GROUPS` only with `groupMembershipClaims: ApplicationGroup`. A user in
        too many groups (groups overage) is denied.
      - An empty gate lets every user of the tenant in, guests included unless you restrict them, and
        logs a warning at every start.
- [ ] **Admin consent** for the app's permissions, so users do not see a second consent screen from
      Entra after ours (ADR-0012 §12).
- [ ] **Client secret expiry.**
      - Entra limits client secrets to two years.
      - The proxy has no expiry warning yet (`IDP_SECRET_EXPIRES_AT` with `doctor`, **planned**,
        #66). Put the date in your own calendar or monitoring.
      - An expired or wrong secret makes sign-ins fail, and refreshes answer `503` instead of signing
        users out. Alert on
        `mcp_authproxy_idp_request_duration_seconds_count{outcome="unavailable"}`
        ([observability](../reference/observability.md#metrics)).
- [ ] **Certificate credential:** recommended by ADR-0012 §5 but **not yet configurable**; only a
      client secret can be set today.
- [ ] Gate changes take effect after a restart, at each user's next sign-in or refresh: at most one
      access-token lifetime (1 h) later. To cut someone off sooner, remove their assignment in Entra.
      Their next refresh then fails too.

## 5. The internal listener

`/metrics`, `/livez` and `/readyz` are served only on the internal listener
(`MCP_AUTHPROXY_INTERNAL_LISTEN`, default `127.0.0.1:9090`). They have no authentication and no
`Host` check.

- [ ] Keep it on loopback, or in Kubernetes on `:9090` with that port left out of the Service that
      fronts the proxy. Restrict it with a NetworkPolicy to the kubelet and Prometheus.
- [ ] Never route it through the public ingress. It must differ from `MCP_AUTHPROXY_LISTEN`; the
      proxy refuses to start otherwise.
- [ ] Set it empty to turn it off if you scrape nothing.

## 6. State, backups and restore

- [ ] **Know that state is in memory today.** Grants, refresh tokens, codes and revocations live in
      process memory; the SQLite store is not wired yet (**planned**, #50). A restart therefore:
      - signs every user out: refresh tokens stop working, and clients start a new sign-in;
      - **forgets revocations.** An access token revoked before the restart is accepted again
        until it expires (at most 1 h). After revoking because of a suspected leak, do not restart
        within the hour unless you also replace the sealing keys.
- [ ] Run **one replica**. Each replica would keep its own grants and revocation list.
- [ ] **Back up configuration, not state:** the key directory (separately and securely), the static
      clients file and its secret and JWKS files, and your settings. There is no state to back up
      yet.
- [ ] **Restore detection** and the documented Litestream backup are **planned** (#50, #53;
      ADR-0007 §8–9). The SQLite store already detects a restored database, but nothing acts on it
      while it is unwired.

## 7. Logs and the audit stream

- [ ] Ship logs and audit records off the host (OWASP ASVS 16.4.3). The proxy writes JSON lines to
      **standard error** (`cmd/mcp-authproxy/main.go`). Audit records carry `log.type=audit` and
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
      - IdP `unavailable` outcomes.

      Example rules are in the [observability reference](../reference/observability.md#metrics).
- [ ] Tracing is off unless you set `OTEL_TRACES_EXPORTER`. When on, send it only to a collector you
      run.

## 8. Rate limits

The OAuth endpoints are rate-limited per client address, with IPv6 grouped by /64
([rate limits](../reference/rate-limits.md)):

| Endpoint | Default per minute |
|---|---|
| `/authorize` | 30 |
| `/consent` | 60 |
| `/callback/entra` | 30 |
| `/token` | 60 |
| `/revoke` | 30 |

- [ ] Set `MCP_AUTHPROXY_TRUSTED_PROXIES` (section 1), or every user shares one budget.
- [ ] Raise budgets for offices or VPNs behind one address with `MCP_AUTHPROXY_OAUTH_RATE_LIMITS`,
      e.g. `authorize=120,callback=120`. Each value is 1–10,000; there is no off switch.
- [ ] MCP traffic itself is not rate-limited (ADR-0001), only capped in flight: 64 requests and
      256 streams, then `503`. Put request-rate limits for MCP traffic in your ingress if you need
      them.

## 9. Run as non-root

- [ ] Use the release image. It runs as uid/gid `65532` on `distroless/static-debian13:nonroot`,
      pinned by digest, with the binary at `/usr/local/bin/mcp-authproxy` and the state directory
      `/var/lib/mcp-authproxy` owned by 65532 ([packaging](../reference/packaging.md#image-contract-public-interface)).
      When you build your own image with `COPY --from`, keep `USER 65532:65532`.
- [ ] In Kubernetes, set `runAsNonRoot: true`, `allowPrivilegeEscalation: false`, drop all
      capabilities and use a `RuntimeDefault` seccomp profile.
      - The proxy writes no files today, so `readOnlyRootFilesystem: true` works.
      - Once the SQLite store is wired, mount a writable volume at `/var/lib/mcp-authproxy`.
- [ ] Verify the image signature and provenance before deploying
      ([packaging](../reference/packaging.md#verifying-a-release)).
- [ ] Track releases: security fixes go into the latest minor only ([SECURITY.md](../../SECURITY.md)).
