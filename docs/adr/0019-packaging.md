# ADR-0019: Packaging — a signed container image and Linux binaries for servers

- Status: Accepted
- Date: 2026-11-06
- Issue: #20 (F19)

## Context

Operators run the proxy on a server or build their own Docker image that wraps their MCP server;
nobody is expected to install it on a laptop. stdio upstreams need a runtime (node, python) that a
static image does not have.

Standards and tools (verified 2026-11-06): goreleaser v2 (cross-builds, archives, checksums, `sboms:`
with syft, `signs:` with cosign); cosign v3 keyless signing with `--bundle`;
`actions/attest-build-provenance` for SLSA provenance (`slsa-github-generator` has had no release since
2025-02); `gcr.io/distroless/static` "contains: ca-certificates … tzdata" for static Go binaries; OCI
image annotations `org.opencontainers.image.{source,revision,version,licenses,created}`; OpenSSF
Scorecard v5.6.0. Microsoft Entra: "The HTTP scheme (`http://`) is supported *only* for *localhost*
URIs". Claude.ai connectors "must be reachable over the public internet"; ChatGPT needs a public HTTPS
endpoint or OpenAI's tunnel.

Competitors (source): babs and xnyzer ship `distroless/static-debian13:nonroot` pinned by digest; babs
signs with cosign and publishes buildx provenance and SBOM plus non-root k8s manifests; ToolHive uses
goreleaser with syft and cosign bundles; Pomerium adds deb/rpm; sigbit ships a root
debian-plus-node-plus-python image (issues: EOL Node CVE, "should run as non-root") and ACME, which its
users asked to turn off. Tags: oauth2-proxy and dex publish `vX.Y.Z` plus `latest`.

Homebrew 5.0 deprecates casks without code signing and `--no-quarantine`; signing needs the Apple
Developer Program. It is not how operators install this proxy.

## Decision

1. **Container image is the main artifact:** multi-arch (linux/amd64, linux/arm64) on
   `distroless/static-debian13:nonroot` pinned by digest; OCI annotations; cosign keyless signature by
   digest; buildx provenance (`mode=max`) and SBOM; tags `vX.Y.Z` and `latest`.
2. **Image contract (public interface):** the binary at `/usr/local/bin/byward`, state in
   `/var/lib/byward`, uid 65532. Operators build their own image with `FROM node` or
   `FROM python` plus `COPY --from=ghcr.io/byward-dev/byward:<version>`.
3. **One image, no runtime variants:** no node or python image in v0.1. A stdio command missing from
   the image fails with an error naming the `COPY --from` pattern.
4. **Binaries:** goreleaser archives for linux amd64/arm64 (supported) and darwin amd64/arm64
   (development only), with checksums, syft SBOM, cosign bundles and build provenance. `go install`
   works. **No Windows in v0.1.**
5. **Supply chain:** GitHub Actions pinned by SHA; tools pinned in `mise.toml` and at least two weeks
   old; reproducible builds (`-trimpath`, `-buildvcs=true`, `SOURCE_DATE_EPOCH`) checked by a rebuild in
   CI; a dependency licence check, with LICENSE, NOTICE and third-party licence texts in archives and the
   image; Renovate or Dependabot bumps the base-image digest; `scorecard-action` runs in CI.
6. **`mise run release:snapshot`** builds the full release locally without publishing.
7. **`--version`** (and `--version --json`) prints build info from `runtime/debug.ReadBuildInfo`.
8. **`-- <cmd>`** after the flags sets a stdio upstream (same mechanism as config, ADR-0003).
9. **No TLS or ACME in the proxy;** TLS ends at the ingress or a reverse proxy. Loopback HTTP only
   for local clients (VS Code, Cursor, Claude Code); Claude.ai and ChatGPT need a public HTTPS URL.
   _Amended 2026-11-13 (#183): byward may terminate TLS with operator-supplied certificates; still no
   ACME. See the amendment below._
10. **No update check or phone-home.**
11. **Docs:** Dockerfile examples for a stdio upstream via `npx` and via `uvx`, compose with an HTTP
    upstream, plain Kubernetes manifests meeting PodSecurity `restricted` (Litestream sidecar, probes,
    PDB, NetworkPolicy), a systemd unit (dedicated user, `StateDirectory=`), and copy-paste `cosign
    verify` and `gh attestation verify` commands.

## Consequences

- The image paths and uid are public interface; changing them is a breaking change.
- Migrations are forward-only (ADR-0007): release notes flag every schema migration and the upgrade
  guide says to back up first, because rolling back the image alone does not work.
- Persona P1 becomes a solo operator on a VM or Docker host (`docs/quality-lenses.md`).
- Later: Homebrew cask (with a signing identity), Windows (Job Objects for stdio process trees),
  deb/rpm, Helm, a node image with an owner, TLS file flags.

## Considered options

- Homebrew cask — rejected for v0.1: not how operators install it, and unsigned casks are deprecated.
- ko for the image — rejected: it cannot build the `FROM node` variants operators need.
- An image with node and python preinstalled (sigbit) — rejected: large, and EOL runtimes become our
  CVEs.
- ACME in the proxy — rejected: binds 80/443, adds state and rate limits; users turn it off.

## Amendment 2026-11-13 (optional TLS with operator-supplied certificates, #183)

**§9 now reads:** byward may terminate TLS on its public listener with certificate files the operator
supplies; there is still no ACME. Without the files, TLS ends at the ingress as before. The hop from an
ingress to byward is plain HTTP that carries bearer tokens, and before this the hardening guide could
only say to keep it private.

- **Settings:** `BYWARD_TLS_CERT_FILE` (the certificate, then any intermediates) and
  `BYWARD_TLS_KEY_FILE`, both or neither, as absolute paths. The key goes through the secret-file
  permission check (ADR-0018 §11), which `--dev` relaxes. `MinVersion` is TLS 1.2 and Go's default
  cipher suites stand, with no setting for either.
- **Serving:** `ServeTLS(ln, "", "")` with `Certificates` empty and `GetCertificate` set. Go calls
  `GetCertificate` "only if the client supplies SNI information or if Certificates is empty"
  (`crypto/tls`), so it runs at every handshake. HTTP/2 and HTTP/1.1 are both served, and plain HTTP
  on the port gets Go's 400. There is no `:80` listener and no redirect.
- **Rotation without a restart:** at each handshake byward stats both files, following symlinks.
  When the device, inode, size or modification time changes, it reads both again. A Kubernetes
  secret volume's `..data` swap counts as a change. A pair that does not load, does not match, or
  has a certificate in its chain outside its validity is never served: the previous pair stays, and
  one warning is logged per state of the files, naming the files and never their contents.
  `NotBefore` may be up to 5 minutes ahead of byward's clock, for an issuer whose clock runs ahead. A
  pair refused only because it is not valid yet is tried again from 5 minutes before its `NotBefore`,
  without waiting for the files to change again.
- **Refused at startup and by `check --offline`:**
  - one file without the other, or a relative path;
  - an unreadable file, or a key that does not match;
  - any certificate in the chain expired, or not valid for more than 5 minutes yet;
  - an `http` `BYWARD_PUBLIC_URL`, including `--dev` on loopback. Clients use the public URL, so an
    http one would reach a listener that speaks only TLS.
- **Warned:**
  - expiry within 30 days, counted from the earliest `NotAfter` in the chain;
  - a certificate that covers neither the public URL's host nor any `BYWARD_ALLOWED_HOSTS` entry. This
    is only a warning, because an ingress may verify byward under its service name.
- **`doctor`:** "TLS certificate expiry" and "TLS certificate names" read the files on disk, which the
  next handshake serves. The expiry check names the chain's certificate that expires first, and says
  when a running proxy will serve a pair that is not valid yet.
- **Invariant kept:** the issuer, the cookies' `Secure` and `__Host-` prefix, and
  `Strict-Transport-Security` (#225) derive from `BYWARD_PUBLIC_URL` alone, never from `r.TLS` or
  `X-Forwarded-Proto`. The internal listener stays plain HTTP.
- **Rejected or later:**
  - ACME (this ADR);
  - OCSP stapling: Let's Encrypt ended OCSP on 2025-08-06;
  - the PROXY protocol;
  - mTLS from the ingress;
  - several certificates chosen by SNI;
  - TLS on the internal listener.
