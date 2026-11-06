# Packaging and release artifacts

Decisions: [ADR-0019](../adr/0019-packaging.md). Config: [`.goreleaser.yaml`](../../.goreleaser.yaml).

## What a release contains

| Artifact | Platforms | Notes |
|---|---|---|
| Container image `ghcr.io/byward-dev/byward:vX.Y.Z`, and `:latest` for final releases only (not for pre-releases such as `-rc.1`) | linux/amd64, linux/arm64 | Multi-arch index on `gcr.io/distroless/static-debian13:nonroot` (pinned by digest); cosign keyless signature; buildx SBOM and provenance (`mode=max`); GitHub build-provenance attestation |
| `byward_<version>_<os>_<arch>.tar.gz` | linux amd64/arm64 (supported), darwin amd64/arm64 (development only) | Binary, `LICENSE`, `README.md`, `third_party/` licence texts; a syft SBOM (`.sbom.json`) per archive |
| `checksums.txt` | — | sha256 of every archive and SBOM; cosign bundle `checksums.txt.sigstore.json`; GitHub build-provenance attestation |

No Windows build in v0.1.

## Image contract (public interface)

| Item | Value |
|---|---|
| Binary | `/usr/local/bin/byward` (entrypoint) |
| State directory | `/var/lib/byward` (working directory, owned by 65532) |
| User | `65532:65532` |
| Licences | `/usr/share/doc/byward/{LICENSE,third_party/}` |

Changing any of these is a breaking change (ADR-0023).

The binary is static, so it can be copied into an image that has the runtime a stdio upstream needs;
see [`docs/examples/stdio-node/Dockerfile`](../examples/stdio-node/Dockerfile) and the
[stdio upstream how-to](../how-to/stdio-upstream.md#6-container-image).

## Building locally

Needs Docker with buildx, and `mise install`.

| Task | What it does |
|---|---|
| `mise run licenses:check` | Fails on a dependency licence outside Apache-2.0, BSD-2/3-Clause, MIT and ISC, for both linux and darwin build constraints (part of `mise run check`) |
| `mise run licenses` | Copies third-party licence texts into `build/licenses` for the archives and the image |
| `mise run release:snapshot` | Builds everything into `dist/` exactly as a release would. It does not sign or publish. Images are loaded locally as `ghcr.io/byward-dev/byward:snapshot-amd64` and `snapshot-arm64` |
| `mise run release:smoke` | Builds a snapshot, then checks `dist/` (every archive and its contents, one SBOM per archive, `checksums.txt`) and the image (uid, paths, labels, licences; the `FROM node` example builds, runs the binary and can write the state directory). Part of `mise run test:integration` |
| `mise run release:reproducible` | Builds twice (the second time in another directory with an empty Go cache) and compares the sha256 of the binaries and archives |

Builds use `-trimpath -buildvcs=true` and the commit time for file timestamps, so a rebuild with the same
Go version from the same commit gives the same bytes. The Go patch is pinned in `mise.toml`, and a weekly
workflow (`go-version.yml`, `scripts/go-version-check.sh`) fails when go.dev lists a newer patch or minor. `go version -m byward` prints the Go version and
commit that built a binary.

## Verifying a release

Replace `vX.Y.Z` with the release tag. These commands are checked against the first real release (#67).

```sh
# Image signature (cosign v3)
cosign verify ghcr.io/byward-dev/byward:vX.Y.Z \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-identity-regexp '^https://github.com/byward-dev/byward/\.github/workflows/release\.yml@refs/tags/v'

# Image provenance
gh attestation verify oci://ghcr.io/byward-dev/byward:vX.Y.Z --repo byward-dev/byward

# Archives: checksum signature, then the checksums, then provenance
cosign verify-blob checksums.txt --bundle checksums.txt.sigstore.json \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-identity-regexp '^https://github.com/byward-dev/byward/\.github/workflows/release\.yml@refs/tags/v'
sha256sum --ignore-missing -c checksums.txt
gh attestation verify byward_X.Y.Z_linux_amd64.tar.gz --repo byward-dev/byward
```
