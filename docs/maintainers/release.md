# How to cut a release

Written so that any maintainer can cut a release without the original author. Decisions:
[ADR-0019](../adr/0019-packaging.md) (packaging) and [ADR-0023](../adr/0023-project-governance.md)
(versioning, support).

Update this page in the same pull request that changes the pipeline (`.goreleaser.yaml`,
`.github/workflows/release.yml`).

## What a release contains

- Container image `ghcr.io/byward-dev/byward`, multi-arch (linux/amd64, linux/arm64), tag `vX.Y.Z`,
  and `latest` for a final release only: a pre-release (`-rc.N`) never moves `latest`
  (`.goreleaser.yaml`). Cosign keyless signature by digest, buildx provenance and SBOM.
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
2. **Build and smoke-test locally without publishing:** `mise run release:smoke` (on Linux). It
   builds the snapshot and checks the archives, SBOMs and checksums, the image contract, and that
   the image serves.
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
5. **Wait for `ci` on the exact commit you tag.** That is `main` for a release from main, or the
   head of the `release/X.Y` branch for a patch or a release candidate cut there. `ci` runs on every
   push to `main` and to `release/**`, so the merged commit gets a run of its own; a green pull request
   before the squash merge is not enough. Check it passed:

   ```sh
   git fetch origin
   gh run list --workflow ci --commit "$(git rev-parse origin/main)"   # or origin/release/X.Y
   ```

6. **Tag that commit** with an annotated tag and push it. The tag push runs `release.yml`, which
   builds, signs and pushes the image and creates a **draft** GitHub release with the archives:

   ```sh
   git tag -a vX.Y.Z -m "vX.Y.Z" origin/main   # or origin/release/X.Y
   git push origin vX.Y.Z
   ```

7. **Verify what was published** with the commands in
   [docs/reference/packaging.md](../reference/packaging.md) (`cosign verify` for the image and
   the checksums, `gh attestation verify` for the image and an archive).
8. **Publish the draft release** with the notes from step 4. For a security release, publish the
   advisory at the same time (SECURITY.md).
9. **Point the docs at the new image** in a pull request: put the tag in `scripts/docs-image-tag`,
   then run `sh scripts/docs-lint.sh`, which lists every `ghcr.io/byward-dev/byward:<tag>` in the
   docs that still names the old one.

## Release candidates and patches

- **A release candidate** is a tag `vX.Y.Z-rc.N`, cut with the same steps. Its image gets only that
  tag; `latest` stays on the last final release. Check that the GitHub release is marked as a
  pre-release before you publish the draft.
- **A patch to an earlier minor** is cut from that minor's `release/X.Y` branch (for example
  `release/0.1`): open a pull request against the branch with the fix taken from `main`, wait for
  `ci` on the branch's head (step 5), and tag there. Only the latest minor gets security fixes
  (SECURITY.md).

## If something goes wrong

- Never move or reuse a published tag. Fix forward with the next patch version.
- If a broken release is out, mark the GitHub release as a pre-release or edit its notes to warn, and
  release the fix as the next patch.
