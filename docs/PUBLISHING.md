# Publishing

Publishing is deliberately tied to a non-prerelease GitHub Release whose tag matches `vMAJOR.MINOR.PATCH`. Pull requests and ordinary pushes have no package, attestation or release-write permissions.

Before the first release, maintainers must:

1. Enable GitHub Actions and GitHub artifact attestations for the repository.
2. Allow the repository `GITHUB_TOKEN` to write GHCR packages and release assets. No long-lived registry password is used.
3. Create a protected `release` environment with required reviewers. Binary, image and moving `vMAJOR` jobs all require this environment; the tag moves only after publication and scanning succeed.
4. Protect release tags and `main`, require CI, and require review for `.github/workflows/`, `Dockerfile`, `scripts/`, and dependency files.
5. Publish the GHCR package publicly if external reusable workflows must pull it without credentials.
6. Configure `TRUSTFALL_INTEGRATION_IMAGE` to the resulting immutable `ghcr.io/...@sha256:...` reference, then manually run the hosted container integration once before recommending the release.

The workflow uses GitHub’s OIDC-backed artifact attestations as the release-signing mechanism. Verify archives with both `sha256sum` and `gh attestation verify`, and verify the container attestation by digest. The checksum is an integrity check, not an independent trust root.

After verification, approve the protected `major-tag` job. This intentionally moves `vMAJOR` for Marketplace/reusable-workflow convenience. Security-sensitive consumers should continue pinning the full commit SHA and image digest. Dependabot proposals do not publish; reviewers validate new full action SHAs and Docker base digests before merge.
