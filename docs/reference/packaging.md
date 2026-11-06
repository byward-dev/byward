# Packaging and release artifacts

Decisions: [ADR-0019](../adr/0019-packaging.md). Config: [`.goreleaser.yaml`](../../.goreleaser.yaml).

## What a release contains

| Artifact | Platforms | Notes |
|---|---|---|
| Container image `ghcr.io/corker/mcp-authproxy:vX.Y.Z` and `:latest` | linux/amd64, linux/arm64 | Multi-arch index on `gcr.io/distroless/static-debian13:nonroot` (pinned by digest); cosign keyless signature; buildx SBOM and provenance (`mode=max`); GitHub build-provenance attestation |
| `mcp-authproxy_<version>_<os>_<arch>.tar.gz` | linux amd64/arm64 (supported), darwin amd64/arm64 (development only) | Binary, `LICENSE`, `NOTICE`, `README.md`, `third_party/` licence texts; a syft SBOM (`.sbom.json`) per archive |
| `checksums.txt` | — | sha256 of every archive and SBOM; cosign bundle `checksums.txt.sigstore.json`; GitHub build-provenance attestation |

No Windows build in v0.1.

## Image contract (public interface)

| Item | Value |
|---|---|
| Binary | `/usr/local/bin/mcp-authproxy` (entrypoint) |
| State directory | `/var/lib/mcp-authproxy` (working directory, owned by 65532) |
| User | `65532:65532` |
| Licences | `/usr/share/doc/mcp-authproxy/{LICENSE,NOTICE,third_party/}` |

Changing any of these is a breaking change (ADR-0023).

The binary is static, so it can be copied into an image that has the runtime a stdio upstream needs;
see [`docs/examples/stdio-node/Dockerfile`](../examples/stdio-node/Dockerfile).

## Building locally

Needs Docker with buildx, and `mise install`.

| Task | What it does |
|---|---|
| `mise run licenses` | Fails on a dependency licence outside Apache-2.0, BSD-2/3-Clause, MIT and ISC; copies third-party licence texts into `build/licenses` |
| `mise run release:snapshot` | Builds everything into `dist/` exactly as a release would. It does not sign or publish. Images are loaded locally as `ghcr.io/corker/mcp-authproxy:snapshot-amd64` and `snapshot-arm64` |
| `mise run image:smoke` | Checks the snapshot image: uid, paths, licences, and that the `FROM node` example builds and runs the binary |
| `mise run release:reproducible` | Builds twice (the second time in another directory with an empty Go cache) and compares the sha256 of the binaries and archives |

Builds use `-trimpath -buildvcs=true` and the commit time for file timestamps, so a rebuild with the same
Go version from the same commit gives the same bytes. `go version -m mcp-authproxy` prints the Go version and
commit that built a binary.

## Verifying a release

Replace `vX.Y.Z` with the release tag. These commands are checked against the first real release (#67).

```sh
# Image signature (cosign v3)
cosign verify ghcr.io/corker/mcp-authproxy:vX.Y.Z \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-identity-regexp '^https://github.com/corker/mcp-authproxy/\.github/workflows/release\.yml@refs/tags/v'

# Image provenance
gh attestation verify oci://ghcr.io/corker/mcp-authproxy:vX.Y.Z --repo corker/mcp-authproxy

# Archives: checksum signature, then the checksums, then provenance
cosign verify-blob checksums.txt --bundle checksums.txt.sigstore.json \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-identity-regexp '^https://github.com/corker/mcp-authproxy/\.github/workflows/release\.yml@refs/tags/v'
sha256sum --ignore-missing -c checksums.txt
gh attestation verify mcp-authproxy_X.Y.Z_linux_amd64.tar.gz --repo corker/mcp-authproxy
```
