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
