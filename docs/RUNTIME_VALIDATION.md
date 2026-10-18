# Runtime validation

Local tests can validate the engine, schemas, policy behavior and OCI build mechanics. They cannot prove that GitHub's hosted runner successfully started a `jobs.<job_id>.container` job. TrustFall therefore keeps hosted runtime evidence separate from local evidence.

## Hosted validation workflow

[`runtime-validation.yml`](../.github/workflows/runtime-validation.yml) is manual-only. It deliberately publishes a commit-scoped, non-release `linux/amd64` image to GHCR, captures the immutable digest, and uses that digest for every subsequent container job in the run. It does not create a GitHub Release or move a version tag.

The matrix checks:

| Scenario | Hosted assertion |
|---|---|
| Default container | Shell, CLI, runner temp, step-output and job-summary interfaces work; audit completes and artifacts upload. |
| Hardened container | The same baseline assessment runs with capability dropping and no-new-privileges, producing separately comparable evidence. |
| No OIDC permission | An attempted issuance is visible as unknown, not secure or verified. |
| OIDC-enabled | Token issuance succeeds and selected issuer, audience, subject and temporal claims pass local semantic validation; the raw JWT is discarded. |
| Network disabled | Network-capable probes remain visible as disabled/unknown evidence. |
| Network enabled | Three explicit public DNS/TCP/HTTPS operations must verify; body-free metadata probes remain visible whether verified or inconclusive. |
| Enforcement | A deliberately mismatched expectation returns exit code 2. |
| Malformed policy | Strict decoding returns exit code 1. |
| Reports | JSON and SARIF are generated and uploaded; comparison uses the two actual runtime reports. |

Run it only after reviewing the commit because the build job has `packages: write`:

```sh
gh workflow run runtime-validation.yml --repo LOhZee/trustfall --ref main
gh run list --repo LOhZee/trustfall --workflow runtime-validation.yml --limit 1
gh run watch RUN_ID --repo LOhZee/trustfall --exit-status
gh run view RUN_ID --repo LOhZee/trustfall --log
```

The workflow refuses package-writing dispatches from any ref other than `refs/heads/main`; verify the run's commit SHA before relying on it. Download and retain the artifacts with the run URL. A successful run proves execution for that commit, image digest, hosted-runner generation and point in time only. It does not establish universal isolation or public anonymous pull access.

## Current publication dependency

The preferred reusable workflows require an immutable `ghcr.io/lohzee/trustfall@sha256:...` input. Before the first public release there is no release digest to embed or recommend. Do not replace it with `latest`, a tag, or a placeholder in an executable production workflow.

After a validated release:

1. Copy `trustfall-image.txt` from the release assets.
2. Verify that its digest matches the GHCR manifest and the build attestation.
3. Confirm anonymous pull access from a clean environment if the package is intended for public reusable-workflow consumers.
4. Set `TRUSTFALL_INTEGRATION_IMAGE` to that digest and dispatch `container-integration.yml`.
5. Record both hosted run URLs in the release notes.

## Evidence status

The repository's [initial CI run](https://github.com/LOhZee/trustfall/actions/runs/39027368144) demonstrated a hosted Go test and a local Docker build/smoke test, but it failed during vulnerability-scanner setup and did not contain a GitHub Actions container job. It must not be cited as hosted container-job validation. Update this document only with actual run URLs and outcomes; use `NOT TESTED` or `BLOCKED` while evidence is absent.

The [2026-10-17 hosted CI run](https://github.com/LOhZee/trustfall/actions/runs/39039538566) passed race tests, vet, CLI and OCI builds, report validation against the project and official SARIF schemas, a local Docker smoke test, and the configured HIGH/CRITICAL image-vulnerability gate.

The [2026-10-17 runtime validation](https://github.com/LOhZee/trustfall/actions/runs/39039660078) completed genuine GitHub-hosted container jobs against `ghcr.io/lohzee/trustfall@sha256:ad0fb83f2779f15e86139caf3ae4d4ea2d1505b262bb0a0648cca788e9fbcbb4`. Its job records contain successful `Initialize containers` steps. Under the same baseline assessment policy, the default job observed 14 bounding capabilities and no-new-privileges disabled; the hardened job observed zero bounding capabilities and no-new-privileges enabled. The no-OIDC job reported issuance unknown, while the explicitly authorised OIDC job verified issuance and selected claim semantics without recording the raw token. The artifacts passed a JWT/bearer-pattern check.

The [2026-10-18 runtime validation](https://github.com/LOhZee/trustfall/actions/runs/39129368073) repeated those container-job checks at commit `62c87346ef52e3c8d9f160bffe26e8d6b96e4089` against `ghcr.io/lohzee/trustfall@sha256:7de79738d9bdb63f96092e3fcc0bb94e5dd81e66ab46cf12741bc7b4d3be0a43`. All six runtime and comparison jobs completed their `Initialize containers` steps. The three explicitly allowlisted GitHub DNS, TCP and HTTPS operations were verified. Body-free metadata HEAD requests received HTTP 400 from the AWS and Azure paths, while GCP metadata DNS resolution remained unknown; none retrieved a response body. Downloaded JSON, comparison and SARIF artifacts validated against their schemas and passed a token/credential-pattern scan. An anonymous manifest lookup resolved the exact digest and its `linux/amd64` platform manifest. This validates only that commit, digest, hosted-runner generation and point in time; AWS, Azure and GCP workload federation still require separately authorised provider environments and were not exercised by this run.

During the 2026-10-17 readiness work, `go test ./...`, `go vet ./...`, actionlint, CLI build, policy/exit tests, and report validation against the project schemas and official OASIS SARIF 2.1.0 schema succeeded locally. Two environment limitations remained: local Docker daemon access was denied at `/var/run/docker.sock`, and the local Linux/arm64 race runtime stopped before tests with `ThreadSanitizer: unsupported VMA range`. These are `BLOCKED` local checks, not product passes or failures; the hosted amd64 CI race test remains authoritative for that platform.
