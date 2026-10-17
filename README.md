# TrustFall

**Your pipeline says it’s isolated. Let’s find out.**

TrustFall is a runtime trust-boundary assessment tool for GitHub Actions container jobs. It inspects what the running workload can actually see and performs only explicitly authorised, bounded capability tests. It is not a workflow linter, vulnerability scanner, or claim that compliant configuration equals isolation.

Every result says what kind of evidence supports it:

- **Observed** — directly inspected in this process or its kernel interfaces.
- **Verified** — a particular authorised operation was attempted and succeeded.
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
    uses: trustfall-ci/trustfall/.github/workflows/scan.yml@FULL_COMMIT_SHA
    with:
      image: ghcr.io/trustfall-ci/trustfall@sha256:RELEASE_DIGEST
      profile: hardened
```

This creates a genuine `jobs.scanner.container` job with `--init --cap-drop=ALL --security-opt=no-new-privileges`. The digest is deliberately required: the repository cannot know a release digest before that release is published.

## What it assesses

| Module | Passive evidence | Optional active evidence |
|---|---|---|
| Runtime identity | UID/GID, GitHub run context, token-facility presence | Selected OIDC claims; raw JWT is discarded |
| Container isolation | capabilities, seccomp, LSM label, user mappings, cgroups, mounts, runtime sockets | none |
| Credential exposure | matching environment names and credential-file metadata | none; values and file contents are never read |
| Network boundaries | configured target definitions | DNS, one TCP connection, or one HTTPS HEAD per allowlisted target; optional body-free metadata HEAD |
| Cloud capabilities | configured provider and operation | Azure OIDC exchange and explicit GET/HEAD targets only |

TrustFall never scans address ranges, enumerates hosts, retrieves metadata credentials, modifies cloud resources, attempts a breakout, or uploads an environment dump. AWS and GCP implement the provider interface only at the architecture level in this initial release; active cloud capability operations currently support Azure. See [Security model](docs/SECURITY_MODEL.md).

## CLI

```text
trustfall version [--json]
trustfall doctor
trustfall assess --profile baseline|hardened|custom [--policy trustfall.yaml]
                  [--output report.json] [--sarif report.sarif]
                  [--summary "$GITHUB_STEP_SUMMARY"] [--fail-on high]
                  [--timeout 5s] [--format json|text] [--verbose] [--no-network]
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

Comparison labels regressions, improvements, changed/new/removed evidence, and inconclusive changes. It does not claim that a workflow or image change caused an observed difference.

## Marketplace composite action

[`action.yml`](action.yml) is a composite action for assessing the **existing job**. It cannot create or change `jobs.<id>.container`; GitHub’s action model does not permit an action to introduce a job boundary. Use it only in a suitable existing Linux container job with Bash, curl, tar and `sha256sum`. It downloads an exact release archive and requires the caller to provide the published SHA-256 before executing it.

```yaml
- uses: trustfall-ci/trustfall@FULL_COMMIT_SHA
  with:
    version: v1.2.3
    sha256: PUBLISHED_PLATFORM_ARCHIVE_SHA256
    profile: baseline
    no-network: true
```

The reusable workflow is preferred because it owns and assesses a real container-job boundary.

## Active probes and OIDC

Network, metadata and cloud destinations come only from the policy allowlist. `--no-network` overrides every network-capable probe. OIDC claim retrieval requires `identity.request_oidc: true` and the job’s explicit `id-token: write`; it never requests cloud credentials by itself. Azure testing additionally requires `cloud.azure.enabled: true`, valid workload-identity identifiers, and explicit `management.azure.com` GET/HEAD targets. A role-assignment list target records only the returned object count, never assignment fields or a response body.

Do not add `id-token: write` to pull-request workflows merely to remove an unknown result. That permission gives the job additional identity-minting authority. The Azure example is manual, environment-protected, and read-only.

## Supply chain and releases

Releases use semantic `vMAJOR.MINOR.PATCH` tags and run only from a published, non-prerelease GitHub Release. CI/release actions are pinned to full commits. The release workflow builds amd64/arm64 binaries and a multi-architecture GHCR image, emits SHA-256 files, SBOM and maximal provenance, and creates GitHub artifact/container attestations. Publishing requires repository Actions to allow attestations and GHCR package writes; no credential or repository setting is assumed.

Consumers should pin an image digest and full action/workflow SHA. Maintainers update the moving major tag only after verifying the release attestations, then update examples and the hosted-integration `TRUSTFALL_INTEGRATION_IMAGE` variable to the new digest. Dependabot proposes Go, Docker base and GitHub Action updates; reviewers must verify upstream release provenance and preserve full-SHA pins.

The hosted integration workflow is intentionally gated on that repository variable. It is a real container job when configured, but this development environment cannot execute GitHub-hosted jobs, so local Docker is not represented as equivalent validation.

## Documentation

- [Architecture and decisions](docs/ARCHITECTURE.md)
- [Security model and probe guarantees](docs/SECURITY_MODEL.md)
- [Threat model](docs/THREAT_MODEL.md)
- [Publishing and trusted release configuration](docs/PUBLISHING.md)
- [Example workflows](examples/workflows)
- [Contributing](CONTRIBUTING.md) and [security policy](SECURITY.md)

Historical Azure policy/OIDC demonstration material remains in `infra/`, `attack/`, and `assets/`. Its executable workflows were moved to `docs/legacy/azure-demo-workflows/*.disabled`; they are not part of TrustFall and GitHub will not run them.

Licensed under Apache-2.0.
