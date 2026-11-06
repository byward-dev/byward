# How to create and rotate sealing keys

The broker seals its access tokens and authorization codes with keys you provide
([ADR-0006](../adr/0006-token-model.md), [ADR-0007](../adr/0007-state-and-storage.md) §5). Keys never
live in the store, and the proxy never generates them outside the single-node development mode.

## The key directory

The proxy reads keys from `BYWARD_KEYS_DIR`, by default `keys` in the data directory:
`/var/lib/byward/keys` with the default `BYWARD_DATA_DIR`. Create it and the first key
before the first start; a missing or empty directory stops startup with an error naming the path.

- One file per key. **The file name is the key ID**: letters, digits, `.`, `_` and `-`, at most 64
  characters.
- The content is the standard base64 encoding of 32 random bytes:

  ```sh
  install -d -m 0700 /var/lib/byward/keys
  (umask 077; openssl rand -base64 32 > "/var/lib/byward/keys/$(date -u +%Y-%m-%d)")
  ```

- Files and directories starting with `.` are ignored (Kubernetes secret volumes keep `..data`
  entries there); subdirectories are ignored; symlinks are followed.
- The proxy refuses to start when the directory is missing, has no key files, or any file is
  unreadable, not 32 bytes of base64, all one byte value, or **world-writable**. The error names the
  file. Group- and other-readable files are fine (Kubernetes mounts secrets `0644` by default).
- A world-writable directory is rejected too, **unless it is on a read-only mount**: a Kubernetes
  secret volume is a read-only tmpfs whose root is mode `1777` (checked on k3s v1.31), and nobody can
  add a key to it.

## Which key seals

**The key whose file name sorts last seals new tokens; every key in the directory opens tokens.**
Names sort as plain strings, so use names that sort by age, such as dates (`2026-11-06`): `k10`
sorts before `k9`, and a new `k10` would never seal.

## Rotating

1. Add a new key file with a name that sorts after the current one.
2. **On several replicas, make sure the new file has reached every replica** (for example, the
   updated secret volume) before restarting any of them. A replica that seals with a key the others
   do not have yet issues tokens they reject.
3. Restart. New tokens use the new key; tokens sealed with the old key keep working.
4. Remove the old file and restart **15 days after the restart in step 3**. Count from the
   restart that made the new key the one sorting last, so the one that seals, not from when you
   added the file; with several replicas, from the restart of the last one, since a replica not yet
   restarted still seals with the old key. By then nothing sealed with the old key is still needed:
   - access tokens live at most 1 h;
   - the IdP tokens kept in each grant are sealed too. Every refresh re-seals them with the current
     key, and a refresh token unused for 14 days expires (ADR-0006 §5). A sign-in can redeem its
     code up to a minute after its IdP tokens were sealed, so 14 days and a minute after the new
     key started sealing, every grant that can still refresh is sealed with it; 15 days leaves a
     margin;
   - refresh tokens rotate on every refresh, but no key seals them: they are random and stored as
     SHA-256 hashes, so removing a key never affects them;
   - legacy MCP session IDs are sealed for 30 days; one sealed with a removed key gets 404, and
     the client starts a new session (MCP Session Management), without signing in again.

   Removing the old key earlier ends the grants not refreshed since step 3: their IdP tokens no
   longer open, so the next refresh revokes the grant and the user signs in again.

**Removing a key invalidates every access token it sealed.** Clients then get `401 invalid_token`
and refresh; refresh tokens themselves are stored as hashes, not sealed.

## Limits

A key must not seal more than 2^32 tokens: AES-256-GCM with random 96-bit nonces is safe only below
that count. Rotating to a new key resets it. At one token per second this is more than 100 years per
key.
