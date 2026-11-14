# Revoke access

How to cut off one user, every user, one app, an app-only caller, or everyone after a leaked
sealing key. Each section says how fast it takes effect and what the audit stream records. The
commands are in the [commands reference](../reference/commands.md); the token model behind them is
[ADR-0006](../adr/0006-token-model.md).

## What the proxy hands out

- **Access tokens** live at most 1 hour. They are sealed, and the proxy checks them against its
  revocation list on every MCP request, not against the IdP.
- **Refresh tokens** rotate on every use and end with the grant: 30 days at most, or 14 days
  unused. Each refresh asks the IdP again and checks the [access gate](access-gate.md) again.
- **The revocation list** is held in memory and rebuilt from the store every 5 seconds. A proxy
  whose list is more than 30 seconds old refuses every token until it syncs again.

## One user

**Block them at the IdP or in the gate.** Disable the user, remove their app assignment, or take
them out of the group or role your gate requires. byward notices at their next refresh, so within an
hour: if the IdP refuses the refresh, or the user no longer passes the gate, the grant is revoked
and the user has to sign in again, which then fails. Until that refresh, their access token keeps
working.

**To cut them off at once,** also run, with the proxy's settings:

```sh
byward revoke-user <user key>
```

It deletes the user's grants and remembered consents and records a cut-off. Their refresh tokens
stop at once; their access tokens are refused by every proxy using the same store at its next
revocation-list sync, within seconds. The user key is the `user_key` of the audit stream: with
Entra, `tid:oid`; with an OIDC IdP, the value of its subject claim
([`byward revoke-user`](../reference/commands.md#byward-revoke-user)).

`revoke-user` alone does not keep anyone out: a user who still passes the IdP and the gate can sign
in again. Do both.

It runs while the proxy runs: it writes to the same store, SQLite or PostgreSQL (on `main`).

| Audit record | When |
|---|---|
| `grant_revoked`, `reason` `operator revoke-user`, `user_key` set | `revoke-user` ran. Written once, by the command, to its own standard error, not to the proxy's log |
| `access_denied` and `grant_revoked` (`the access gate refused the user on refresh; grant revoked`) | a refresh found the user outside the gate |
| `grant_revoked` (`the IdP ended the session; grant revoked`) | the IdP refused the refresh |

## Everyone

```sh
byward revoke-all --yes
```

The same as `revoke-user` for every user at once, for incident response: every grant and remembered
consent goes, and every token issued before it is refused within seconds. Everyone signs in again.
`--yes` is required; without it the command exits 2. It also runs while the proxy runs
([`byward revoke-all`](../reference/commands.md#byward-revoke-all)).

Audit: one `grant_revoked` record with `reason` `operator revoke-all`, on the command's standard
error.

## One app

Put it on the client denylist and restart the proxy (every replica):

```sh
BYWARD_CLIENT_DENYLIST=https://app.example.com/oauth/client.json,callback.example.net
```

An entry is a CIMD client ID (an `https` URL) or a host name that the app's redirect URIs return to.
A DCR client ID cannot be denied, since the app would just register again; deny its host. Static
clients are never checked: remove one from the [static clients file](../reference/static-clients.md)
and restart instead. The setting's full rules are in [DCR settings](dcr.md#settings).

The denylist stops new registrations and sign-ins. It does not end what the app already holds:

- a denied CIMD client ID gets 401 `invalid_client` at `/token`, so it can no longer refresh, but
  its access tokens keep working until they expire, at most an hour;
- a denied host does not stop refreshes of an app that is already signed in.

There is no command that ends one app's grants. To end them, revoke the users who use the app with
`revoke-user`, or everyone with `revoke-all`. The audit stream's `login` and `token_issued` records
carry both `client_id` and `user_key`.

Audit: a refused DCR registration is `client_registered` with `outcome` `failure` and `reason`
`invalid_redirect_uri`; a refused `/token` request is `token_rejected` with `reason`
`invalid_client`.

## An app-only caller

An Entra app-only caller has no grant; its key is its service principal's `tid:oid`. Remove its
role assignment in Entra, and run `revoke-user` with that key to refuse the tokens it already holds:
[cut a caller off](app-tokens.md#cut-a-caller-off) explains why it can stay out for up to an hour
even so. `revoke-all` refuses the tokens of app-only callers issued before it too.

Audit: `app_token_rejected` with `reason` `revoked` on each refused request.

## A leaked sealing key

Anyone with a sealing key can seal access tokens the proxy accepts. `revoke-user` and `revoke-all`
only refuse tokens issued before they ran, so they cannot stop tokens sealed afterwards. Replace the
keys:

1. Optionally run `byward revoke-all --yes` first. It records the incident in the audit stream and
   deletes every grant and remembered consent at once.
2. Replace every file in the key directory with a new key ([sealing keys](sealing-keys.md)). Do not
   keep the old ones for a rotation overlap.
3. Restart every replica.

Every access token sealed with a removed key is refused, and each grant's IdP tokens no longer open,
so its next refresh revokes the grant. Everyone signs in again.

Audit: `key_loaded` for each new key at startup; a key rotation as such is not recorded. Without
`revoke-all`, each grant ends with `grant_revoked` and `reason`
`the grant holds no usable IdP refresh token; grant revoked` at its next refresh.

## After restoring the store

A restore from a backup loses the revocations recorded after the backup: an access token revoked
since then is accepted again until it expires, at most an hour. Run `revoke-user` or `revoke-all`
again for those users.

The SQLite store finds a restore by itself at startup ([restore detection](state.md#restore-detection)).
With the PostgreSQL store (on `main`), also run `byward store new-epoch --yes`
([backup and restore](postgres.md#backup-and-restore)): refresh tokens from before the new epoch are
refused and every remembered consent is forgotten. It runs while the proxy runs, prints the new
epoch, and is audited as `store_restored` with `reason` `operator new-epoch`. With SQLite it exits 2.
