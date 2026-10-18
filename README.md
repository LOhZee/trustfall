# TrustFall

**Your pipeline says it’s isolated. Let’s find out.**

[![CI](https://github.com/LOhZee/trustfall/actions/workflows/ci.yml/badge.svg)](https://github.com/LOhZee/trustfall/actions/workflows/ci.yml)

TrustFall is a runtime trust-boundary assessment tool for GitHub Actions container jobs. It inspects what the running workload can actually see and performs only explicitly authorised, bounded capability tests. It is not a workflow linter, vulnerability scanner, or claim that compliant configuration equals isolation.

Every result says what kind of evidence supports it:

- **Observed** — directly inspected in this process or its kernel interfaces.
- **Verified** — a particular authorised operation was executed and its bounded outcome was evidenced.
- **Inferred** — configuration suggests a capability, but TrustFall did not establish it.
- **Unknown** — evidence was unavailable or inconclusive. Unknown never means secure.

## Quick start

Build and run locally:

```sh
go build -o trustfall ./cmd/trustfall
./trustfall doctor
./trustfall assess --profile baseline --no-network --output report.json --sarif report.sarif
```

Build the OCI image and apply the same hardening used by the reusable workflow:

```sh
docker build -t trustfall:local .
docker run --rm --init --cap-drop=ALL --security-opt=no-new-privileges \
  trustfall:local assess --profile hardened --no-network
```

The preferred GitHub integration is the reusable workflow. Pin both the workflow to a full commit SHA and the image to its published digest:

```yaml
jobs:
  trustfall:
    uses: LOhZee/trustfall/.github/workflows/scan.yml@FULL_COMMIT_SHA
    with:
      image: ghcr.io/lohzee/trustfall@sha256:RELEASE_DIGEST
      profile: hardened
```

This creates a genuine `jobs.scanner.container` job with `--init --cap-drop=ALL --security-opt=no-new-privileges`. The digest is deliberately required: the repository cannot know a release digest before that release is published.

## What it assesses

| Module | Passive evidence | Optional active evidence |
|---|---|---|
| Runtime identity | UID/GID, GitHub run context, token-facility presence | Selected OIDC claims; raw JWT is excluded from reports |
| Container isolation | capabilities, seccomp, LSM label, user mappings, cgroups, mounts, runtime sockets | none |
| Credential exposure | matching environment names and credential-file metadata | none; values and file contents are never read |
| Network boundaries | configured target definitions | DNS, one TCP connection, or one HTTPS HEAD per allowlisted target; optional body-free metadata HEAD |
| Cloud capabilities | configured provider and operation | AWS, Azure, or GCP workload federation and explicit read-only targets |

TrustFall never scans address ranges, enumerates hosts, retrieves metadata credentials, modifies cloud resources, attempts a breakout, or uploads an environment dump. Active cloud support is operation-oriented: AWS uses GitHub OIDC with `AssumeRoleWithWebIdentity` and SigV4-signed GET/HEAD requests, Azure uses workload identity exchange and `management.azure.com` GET/HEAD requests, and GCP uses direct Workload Identity Federation with `*.googleapis.com` GET/HEAD requests. Response bodies and temporary credentials are not recorded. See [Security model](docs/SECURITY_MODEL.md).

## CLI

```text
trustfall version [--json]
trustfall doctor
trustfall assess --profile baseline|hardened|custom [--policy trustfall.yaml]
                  [--output report.json] [--sarif report.sarif]
                  [--summary "$GITHUB_STEP_SUMMARY"] [--fail-on high]
                  [--timeout 5s] [--format json|text] [--verbose] [--no-network]
                  [--request-oidc] [--oidc-audience trustfall]
trustfall compare baseline.json hardened.json
trustfall validate --policy trustfall.yaml
```

Exit codes are deterministic:

| Code | Meaning |
|---:|---|
| 0 | completed; audit findings do not fail the command |
| 1 | invalid invocation or policy |
| 2 | explicit enforcement policy was violated |
| 3 | operational failure, such as report I/O or an engine error |

`--fail-on` explicitly changes the run to enforcement mode. Without enforcement, findings alone never change the exit code. A custom policy is strict-decoded: unknown fields, unsafe endpoint schemes, unsupported methods, duplicate target names, and invalid concurrency fail validation.

## Reports and comparison

JSON follows [report-v1.schema.json](schemas/report-v1.schema.json). SARIF is 2.1.0 and contains stable partial fingerprints but no fabricated source locations for runtime findings. The Markdown summary is designed for `$GITHUB_STEP_SUMMARY`.

```sh
trustfall compare default.json hardened.json > comparison.json
```

Comparison labels regressions, improvements, changed evidence, missing evidence, and inconclusive changes. It records assessment-policy and runtime-context differences and does not claim that a workflow or image change caused an observed difference. The `baseline` and `hardened` profiles are assessment policies; they do not alter the container. A meaningful hardening comparison must run the same assessment against deliberately different container options, as shown in [the comparison example](examples/workflows/hardened-comparison.yml).

## Marketplace composite action

[`action.yml`](action.yml) is a composite action for assessing the **existing job**. It cannot create or change `jobs.<id>.container`; GitHub’s action model does not permit an action to introduce a job boundary. Use it only in a suitable existing Linux job (including an existing container job) with Bash, curl, tar and `sha256sum`. It downloads an exact release archive, requires the caller to provide the published SHA-256, validates its inputs, and exposes the CLI exit code.

```yaml
- uses: LOhZee/trustfall@FULL_COMMIT_SHA
  with:
    version: v1.2.3
    sha256: PUBLISHED_PLATFORM_ARCHIVE_SHA256
    profile: baseline
    no-network: true
```

The reusable workflow is preferred because it owns and assesses a real container-job boundary. The composite action does not create, configure, or harden `jobs.<id>.container`.

## Active probes and OIDC

Network, metadata and cloud destinations come only from the policy allowlist. `--no-network` overrides every network-capable probe. A negative expectation is intentionally narrow: set `expect_reachable: false` and explicitly choose `negative_evidence: dns_nxdomain` or `connection_refused`. Only that exact bounded outcome passes; timeout, cancellation and TLS errors remain inconclusive and no result claims universal isolation.

Passive [`scan.yml`](.github/workflows/scan.yml) has only `contents: read`; it observes OIDC facility presence and explicitly reports that issuance was not tested. OIDC-enabled [`scan-oidc.yml`](.github/workflows/scan-oidc.yml) declares `id-token: write`, requests a token, and locally validates issuer, requested audience, subject presence and temporal claims. It excludes the JWT from reports and does not independently verify its signature. External callers must also explicitly grant `id-token: write` to the job that calls the reusable workflow.

OIDC facility presence is not token issuance. Token issuance is not cloud federation. Cloud federation is not successful resource access. TrustFall reports each operation separately and never requests cloud credentials merely because OIDC is enabled. Every cloud provider additionally requires its own `cloud.<provider>.enabled: true` configuration and explicit read-only targets. AWS query APIs accept only a small operation allowlist, Azure targets are restricted to `management.azure.com`, and GCP targets are restricted to `*.googleapis.com`. An Azure role-assignment list target records only the returned object count, never assignment fields or a response body. Protected manual examples are provided for [AWS](examples/workflows/aws-federation.yml), [Azure](examples/workflows/azure-federation.yml), and [GCP](examples/workflows/gcp-federation.yml).

Do not add `id-token: write` to pull-request workflows merely to remove an unknown result. That permission gives the job additional identity-minting authority. The cloud federation examples are manual, environment-protected, and read-only.

## Supply chain and releases

Releases use semantic `vMAJOR.MINOR.PATCH` tags and run only from a published, non-prerelease GitHub Release. CI/release actions are pinned to full commits. The release workflow builds amd64/arm64 binaries and a multi-architecture GHCR image, emits SHA-256 files, SBOM and maximal provenance, and creates GitHub artifact/container attestations. Publishing requires repository Actions to allow attestations and GHCR package writes; no credential or repository setting is assumed.

Consumers should pin an image digest and full action/workflow SHA. Maintainers update the moving major tag only after verifying the release attestations, then update examples and the hosted-integration `TRUSTFALL_INTEGRATION_IMAGE` variable to the new digest. Dependabot proposes Go, Docker base and GitHub Action updates; reviewers must verify upstream release provenance and preserve full-SHA pins.

The hosted integration workflow is intentionally gated on an immutable-image repository variable. The manual [runtime validation workflow](.github/workflows/runtime-validation.yml) bootstraps a commit-scoped, non-release image and then runs a real container-job matrix. Dispatching it publishes a GHCR package and is therefore a deliberate maintainer operation; see [runtime validation](docs/RUNTIME_VALIDATION.md). Local Docker is never represented as equivalent to a GitHub-hosted container job.

## Documentation

- [Architecture and decisions](docs/ARCHITECTURE.md)
- [Security model and probe guarantees](docs/SECURITY_MODEL.md)
- [Threat model](docs/THREAT_MODEL.md)
- [Publishing and trusted release configuration](docs/PUBLISHING.md)
- [Runtime validation matrix and current evidence](docs/RUNTIME_VALIDATION.md)
- [Example workflows](examples/workflows)
- [Contributing](CONTRIBUTING.md) and [security policy](SECURITY.md)

Licensed under Apache-2.0.
