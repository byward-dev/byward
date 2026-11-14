# Respond to alerts

What to do when byward asks for the operator. Each entry says what the signal means, its likely
causes, the fix, and the log lines and audit events to read. The metric, event and log definitions
are in the [observability reference](../reference/observability.md); its
[example alert rules](../reference/observability.md#metrics) are the ones this page follows.

Start every investigation from the `request_id`: it is on each log line of a request, on the error
page and in `/token` error descriptions, and with Entra it equals Entra's `correlation_id`
([logs](../reference/observability.md#logs)).

## IdP alerts: `byward_idp_alerts_total`

The rule `BywardIdPNeedsTheOperator` fires on any increase of
[`byward_idp_alerts_total`](../reference/observability.md#metrics). It counts IdP errors that do not
clear on their own: no user can fix them, and retrying will not either. The `reason` label says
which of the three below; `operation` says where it happened (`authorize`, `callback` for a
sign-in, `refresh`, or `on_behalf_of` for a downstream token).

Each one is also logged once, at error level, as `IdP alert: the operator must act`, with `idp`,
`operation`, `alert` (the reason) and `request_id`. That line's `reason` field holds the fix, not a
reason code. Use its `request_id` to find the request's other lines, which name the IdP's error code:

| `operation` | Other log line | Audit event |
|---|---|---|
| `callback` | `IdP sign-in failed`, with `idp_error_code`, `trace_id` and `correlation_id` | [`login`](../reference/observability.md#events-and-ocsf-mapping), outcome `failure` |
| `refresh` | `IdP refresh unavailable` (warn) or `IdP refresh failed` (error); its `error` names the IdP's error and code | [`token_rejected`](../reference/observability.md#events-and-ocsf-mapping), `reason` `temporarily_unavailable` or `server_error` |
| `on_behalf_of` | the refused request's error line, with `idp_error_code` and `alert` | [`downstream_token_refused`](../reference/observability.md#events-and-ocsf-mapping) |

An error in the IdP's callback query never counts: a browser can forge it. Only the token
endpoint's answer, or the proxy's own credential, raises these alerts.

### `credential_rejected`

**What it means.** The IdP's token endpoint refused the proxy's own client credential or client ID.
For an `oidc` IdP or preset, the answer was `invalid_client` or `unauthorized_client`. For Entra,
the same, or one of the codes AADSTS7000215 (invalid secret), 7000222 (expired secret), 700016 (no
such app in the tenant), 700027 (the certificate is not uploaded) or 5002723.

Nobody is signed out. A refresh answers `503 temporarily_unavailable` and keeps the grant, so users
recover once the credential is fixed. New sign-ins fail with an error page until then.

**Likely causes.**

- The client secret expired, or was deleted at the IdP.
- The secret file holds the wrong value, such as the secret's ID instead of its value.
- The client ID or the Entra tenant is wrong, or the app was deleted.
- A rotation went wrong: the certificate or key the proxy uses is not registered on the app. After
  uploading a new Entra certificate, sign-ins can be refused with AADSTS700027 for a few minutes
  ([certificate how-to](entra-certificate.md#2-upload-the-public-certificate)).
- The app is not allowed the grant byward uses (`unauthorized_client`): enable Authorization Code
  and Refresh Token on the app ([OIDC how-to](oidc.md#1-register-the-proxy-at-the-idp)).

**What to do.**

1. Run `byward doctor` where the proxy runs. Its `entra app and credential` check (Entra) or
   `client credential` check (`oidc`, on `main`) tests the credential and names the setting to fix
   ([checks](../reference/commands.md#checks)).
2. Fix the credential:
   - an Entra client secret: create a new one and restart the proxy
     ([quickstart, step 1.4](quickstart-entra.md#14-create-the-service-principal-and-the-client-secret));
   - an Entra certificate: upload the certificate in the file the proxy reads
     ([rotate it](entra-certificate.md#4-rotate-it), [troubleshooting](entra-certificate.md#troubleshooting));
   - an `oidc` IdP: check `BYWARD_OIDC_CLIENT_ID` and the file named by
     `BYWARD_OIDC_CLIENT_SECRET_FILE`, or the key in `BYWARD_OIDC_CLIENT_KEY_FILE` and its
     `BYWARD_OIDC_CLIENT_KEY_ID` ([settings](oidc.md#2-configure-the-proxy)).
3. byward reads secret and certificate files at startup: restart every replica after replacing one.
4. To be warned next time, set `BYWARD_ENTRA_CLIENT_SECRET_EXPIRES_AT`: the proxy warns at startup and
   `byward doctor` from 30 days before. byward reads a certificate's end date itself.

The Entra codes and their fixes are also in the
[quickstart's troubleshooting](quickstart-entra.md#errors-on-refresh-and-the-proxys-credentials).

### `credential_unusable`

**What it means.** The proxy could not build its client credential, so nothing was sent to the IdP.
Like `credential_rejected`, nobody is signed out: refreshes answer `503` and keep the grant.

**Likely causes.**

- With `BYWARD_ENTRA_FEDERATED_TOKEN_FILE`: the token file is missing, unreadable or empty. byward
  reads it again for every token request, so a sidecar or workload-identity agent that stopped
  writing it shows up here.
- Rarely: signing the client assertion with the configured certificate or private key failed.

**What to do.**

1. Read the request's other log line (table above): its `error` says what failed, such as a file
   that could not be read or is empty.
2. Make the token file exist, be readable by the proxy's user and hold a current token
   ([federated credential](entra-federated-credential.md#3-point-byward-at-the-token-file)). No restart is needed: the next token request
   reads it again.

### `protocol`

**What it means.** The IdP's token endpoint answered with a success status but no tokens: no access
token, no ID token and no error. Retrying the same request will not help. The request fails and the
grant is kept: a refresh answers `500 server_error`, a sign-in shows an error page, and an
On-Behalf-Of exchange is refused as `failed`.

**Likely causes.** Something other than the IdP answered on the token endpoint, or the IdP
misbehaves. Look at what sits between the proxy and the IdP: an environment HTTP proxy
(`HTTPS_PROXY`), or a gateway in front of a self-hosted IdP.

**What to do.**

1. Run `byward doctor`, which reaches the IdP the way the proxy does. For an `oidc` IdP its
   `discovery` check confirms the issuer ([checks](../reference/commands.md#checks)).
2. Check the IdP's service status, and for a self-hosted IdP its logs at the time of the alert.
3. With Entra, give Microsoft support the `trace_id` and `correlation_id` from the request's other
   log line.

## IdP unavailable

The rule `BywardIdPUnavailable` fires when IdP calls keep ending with outcome `unavailable` in
[`byward_idp_request_duration_seconds`](../reference/observability.md#metrics) (operations
`authorize`, `callback` and `refresh`).

**What it means.** The IdP did not answer, answered with a 5xx or 429 status, said
`temporarily_unavailable` or `server_error`, or its signing keys could not be fetched. A
`credential_rejected` or `credential_unusable` error counts here too, so check
`byward_idp_alerts_total` first: if it rose, follow that entry instead.

Users who are already signed in keep working: MCP requests are checked locally, and the IdP is not
part of `/readyz`. Refreshes answer `503 temporarily_unavailable` and keep the grant; new sign-ins fail.

**What to do.**

1. Check the IdP's service status.
2. Check the network path from the proxy to the IdP: DNS, egress rules, and `HTTPS_PROXY` or
   `NO_PROXY` if set. `byward doctor` reaches the IdP the same way the proxy does.
3. Read `IdP refresh unavailable` and `IdP sign-in failed` lines for the status and error code.

## Rejected access tokens

The rule `BywardRejectedTokenSpike` fires when MCP requests keep carrying access tokens the proxy
refuses: the [`access_token_rejected`](../reference/observability.md#events-and-ocsf-mapping) event,
with `reason` `invalid` or `expired`. A request with no token is the normal start of sign-in and is
not counted.

**Likely causes.**

- A sealing key was removed while tokens it sealed were still in use, or replicas have different key
  files, so one replica issues tokens another cannot open (`invalid`)
  ([sealing keys](sealing-keys.md#rotating)).
- A client that does not refresh before its token expires (`expired`).
- Someone sending made-up tokens (`invalid` from a few `remote_ip` values).

**What to do.**

1. Group the records by `remote_ip` and `reason`. These records are rate-limited per source address;
   `suppressed` counts the dropped ones, and the metric counts them all.
2. With several replicas, compare the key IDs each one loaded: each logs a
   [`key_loaded`](../reference/observability.md#events-and-ocsf-mapping) record per key at startup.
   Give every replica the same key files ([sealing keys](sealing-keys.md#rotating)).
3. Traffic from a few addresses you do not know: block them in front of the proxy.

## Upstream busy

The rule `BywardUpstreamBusy` fires when requests are refused with `503` and `Retry-After: 1`
because an admission cap is full: [`byward_upstream_busy_total`](../reference/observability.md#metrics),
with `kind` `request` or `stream`.

**What it means.** Each proxy process lets at most 64 requests and 256 long-lived streams (`GET`
streams and `subscriptions/listen`) reach the upstream at once ([ADR-0018](../adr/0018-hardening.md)
§7). The caps are fixed, not settings.

**What to do.**

1. Watch [`byward_upstream_in_flight`](../reference/observability.md#metrics) by `kind`: if it sits
   at the cap, the upstream answers too slowly or the load has grown.
2. Look at the upstream: slow tool calls hold their slot until they answer.
3. For more capacity with an HTTP upstream, run more replicas on the PostgreSQL store, on `main`
   ([PostgreSQL](postgres.md)).

## Upstream refusals

When an HTTP upstream answers a relayed request with **401 or 403**, it refused **the proxy**, not
the user: byward checked the user's token before relaying, and never passes it on. Signing in again
cannot fix it, so byward does not answer with 401 or 403
([ADR-0025](../adr/0025-upstream-refusal.md)). The client gets:

| Request | Answer |
|---|---|
| anything but `POST` | `405` |
| a notification | `202` |
| a request the upstream already answered with a JSON-RPC response of the same `id` | that response, with `200` |
| a `tools/call` | `200`: a tool result with `isError: true` and the text below |
| any other request | `200`: JSON-RPC error `-32603` with the text below and `data.upstreamStatus` |
| a request whose `id` cannot be read (a batch, a body over 64 KiB, not JSON-RPC) | `502` |

There is no metric or audit event for these. Each is logged at error level as
`upstream refused the request`, with `request_id`, `status` (the upstream's 401 or 403) and a
`reason` that holds the hint and what the client got. Alert on that log line.

### 401: the upstream rejected the proxy's credential

The client sees "The upstream MCP server rejected the proxy's credentials; ask your operator." The
log's `reason` begins `upstream rejected the proxy's credential`.

**Likely causes.**

- The upstream credential in `BYWARD_UPSTREAM_CREDENTIAL_FILE` is wrong, expired or was rotated at
  the upstream, or is sent in a header the upstream does not read
  (`BYWARD_UPSTREAM_CREDENTIAL_HEADER`).
- The upstream verifies the [identity assertion](identity-assertion.md) and cannot: it does not
  know byward's signing keys, or it holds a static copy of the JWKS from before a key rotation.

**What to do.**

1. Replace the credential file and restart: byward reads it at startup
   ([upstream credential](upstream-credential.md#1-put-the-credential-in-a-file)).
2. Check the header with [choose the header](upstream-credential.md#2-choose-the-header): the
   credential and the assertion never share one.
3. For the assertion, point the upstream at byward's keys
   ([step 2](identity-assertion.md#2-point-the-upstream-at-the-public-keys)); an upstream with a static
   JWKS needs `byward jwks` again after each [key rotation](identity-assertion.md#5-rotate-the-signing-key).
   `byward doctor` checks that the keys are discoverable ("identity assertion keys (discovery)").

### 403: the upstream denied the request

The client sees "The upstream MCP server denied this request; ask your operator." The log's `reason`
begins `upstream denied the proxy's identity`.

**Likely causes.** The upstream wants a role, group or other claim the identity assertion does not
carry for this user, or its own policy refuses the user.

**What to do.**

1. Compare what the upstream requires with the claims byward asserts
   ([choose the claims](identity-assertion.md#3-choose-the-header-and-the-claims)), and assign the
   missing role or group at the IdP.
2. A role assigned at the IdP is asserted from the client's next refresh, at most one access-token
   lifetime (1 hour) later ([how fresh the claims are](identity-assertion.md#4-how-fresh-the-claims-are)).
3. If the upstream denies tools on purpose, it should answer with a tool result with `isError`
   instead of an HTTP 403; the user then sees the upstream's own message.
