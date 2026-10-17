# Publishing

Publishing is deliberately tied to a non-prerelease GitHub Release whose tag matches `vMAJOR.MINOR.PATCH`. Pull requests and ordinary pushes have no package, attestation or release-write permissions.

Before the first release, maintainers must:

1. Enable GitHub Actions and GitHub artifact attestations for the repository.
2. Allow the repository `GITHUB_TOKEN` to write GHCR packages and release assets. No long-lived registry password is used.
3. Create a protected `release` environment with required reviewers. Binary, image and moving `vMAJOR` jobs all require this environment; the tag moves only after publication and scanning succeed.
4. Protect release tags and `main`, require CI, and require review for `.github/workflows/`, `Dockerfile`, `scripts/`, and dependency files.
5. Publish the GHCR package publicly if external reusable workflows must pull it without credentials.
6. Configure `TRUSTFALL_INTEGRATION_IMAGE` to the resulting immutable `ghcr.io/...@sha256:...` reference, then manually run the hosted container integration once before recommending the release.

## Initial bootstrap

There is intentionally no self-referential dependency on an already published TrustFall image. After reviewing a commit, a maintainer may dispatch `runtime-validation.yml`; it builds and publishes a commit-scoped, non-release image and then consumes the returned digest in genuine GitHub-hosted container jobs. This operation requires `packages: write` but does not create a release. See [runtime validation](RUNTIME_VALIDATION.md) for exact commands and evidence requirements.

Do not make the package public, change repository settings, publish a GitHub Release, or approve the protected `release` environment as an incidental test step. Those are deliberate maintainer operations. If public consumers are intended, separately verify anonymous digest pulls after changing package visibility.

The Trivy action and scanner version are both explicit and reviewable. This is especially important after the upstream March 2026 supply-chain incident: do not replace the full action SHA or scanner version with a floating tag, and check the upstream security advisory during updates.

The workflow uses GitHub's OIDC-backed artifact attestations as the release-signing mechanism. Verify archives with both `sha256sum` and `gh attestation verify`, and verify the container attestation by digest. The checksum is an integrity check, not an independent trust root. The release uploads `trustfall-image.txt` only after the digest-pinned image scan succeeds, giving consumers an exact reference rather than a mutable tag.

After verification, approve the protected `major-tag` job. This intentionally moves `vMAJOR` for Marketplace/reusable-workflow convenience. Security-sensitive consumers should continue pinning the full commit SHA and image digest. Dependabot proposals do not publish; reviewers validate new full action SHAs and Docker base digests before merge.
