# How to cut a release

Written so that any maintainer can cut a release without the original author. Decisions:
[ADR-0019](../adr/0019-packaging.md) (packaging) and [ADR-0023](../adr/0023-project-governance.md)
(versioning, support).

> **Status:** the release pipeline is being built. `mise run release:snapshot` arrives with
> Slice R (#55) and the tag-triggered publish workflow with the first release (#67). Until then this
> page is the agreed procedure; update it in the same pull request that changes the pipeline.

## What a release contains

- Container image `ghcr.io/corker/mcp-authproxy`, multi-arch (linux/amd64, linux/arm64), tags `vX.Y.Z`
  and `latest`, cosign keyless signature by digest, buildx provenance and SBOM.
- goreleaser archives: linux amd64/arm64 (supported), darwin amd64/arm64 (development only), with
  checksums, syft SBOM, cosign bundles and build provenance.
- GitHub release notes, which are the changelog.

## Choose the version

The project is in 0.y.z ([SemVer](https://semver.org/spec/v2.0.0.html)):

| Change since the last release | Bump |
|---|---|
| Anything breaking in the public interface (config keys, static-clients file, identity-assertion claims, audit schema, metric names, log fields, image paths or uid) | minor: `0.Y+1.0` |
| A removal of an item deprecated for at least one minor release | minor |
| New features, fixes, deprecations (old item still works, with a warning) | minor or patch |
| Security fix only | patch: `0.Y.Z+1` |

Security fixes go into the latest minor only (SECURITY.md).

## Steps

1. **`main` is green.** The latest `check` and `test:integration` runs on `main` pass, and the
   scheduled lanes (real Entra, fuzz, reproducible-build rebuild) have no open failures.
2. **Build locally without publishing:** `mise run release:snapshot`. Check that the archives and
   the image build, and run the image once (`--version`).
3. **Manual client checklist** (ADR-0024, lane "manual"): the full sign-in and a tool call through the
   proxy with Claude Code, Claude.ai, VS Code, Cursor and ChatGPT, plus OBO if it is enabled. Record
   the client versions in the release notes.
4. **Draft the release notes**, with these sections in this order, empty ones left out:
   - **Breaking Changes**, each with the upgrade step;
   - **Schema migrations**: migrations are forward-only (ADR-0007), so say to back up the state
     directory first, because rolling back the image alone does not work;
   - **Deprecations**, with the release in which each item will be removed;
   - **Security**, linking the published advisories;
   - Features, Fixes.
5. **Tag `main`** with an annotated tag and push it; the tag push starts the publish workflow:

   ```sh
   git fetch origin
   git tag -a vX.Y.Z -m "vX.Y.Z" origin/main
   git push origin vX.Y.Z
   ```

6. **Verify what was published**, using the same commands the user docs give:

   ```sh
   cosign verify ghcr.io/corker/mcp-authproxy@sha256:<digest> \
     --certificate-identity-regexp '^https://github.com/corker/mcp-authproxy/' \
     --certificate-oidc-issuer https://token.actions.githubusercontent.com
   gh attestation verify <archive> --repo corker/mcp-authproxy
   ```

7. **Publish the release notes** on the GitHub release. For a security release, publish the advisory
   at the same time (SECURITY.md).

## If something goes wrong

- Never move or reuse a published tag. Fix forward with the next patch version.
- If a broken release is out, mark the GitHub release as a pre-release or edit its notes to warn, and
  release the fix as the next patch.
