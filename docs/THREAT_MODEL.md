# Threat model

TrustFall assumes the runner, container runtime, workflow definition, repository contents, policy and remote services may sit on different trust boundaries. It assesses evidence available to its own process; it cannot establish that a compromised runner or kernel reported truthfully.

## Threats and controls

| Threat | Control | Residual risk |
|---|---|---|
| Untrusted repository contents and malicious pull requests | PR example grants only `contents: read`, no OIDC/secrets, uses no active network, and pins workflow/image. Checkout credentials should not persist. | Repository code can affect later steps in the same job; use a dedicated assessment job and never `pull_request_target` to execute fork code. |
| Token leakage | Values and credential files are never read into reports; token response bodies are discarded; redaction runs before serialization. | A compromised runner or modified binary can steal tokens. Verify release digest/attestation and protect workflow changes. |
| Excessive cloud permissions | Cloud testing is off by default, requires explicit OIDC and provider opt-in, and permits only explicit read operations. | A federated cloud identity may have broader rights than the tested operation; successful/failed probes are not exhaustive. |
| Network probe abuse | Exact allowlist, HTTPS-only web targets, strict validation, deadlines, concurrency cap, no ranges/port sweeps, and `--no-network` engine gate. | An authorised external endpoint can redirect within its origin or behave maliciously. Review targets as code. |
| Metadata credential theft | Separate opt-in, fixed provider endpoints, HEAD only, no credential subpaths, no body reporting. | Some services may treat HEAD unusually; reachability alone can still be sensitive. Keep disabled by default. |
| Artifact leakage | No env dumps or secret values; short example retention; reports are documented as sensitive. | Repository/ref/OIDC claims, paths and endpoint names can reveal internal context. Restrict artifact readers. |
| Supply-chain compromise | Full-SHA actions, digest-pinned consumer images, archive SHA-256, SBOM, provenance/attestations, Dependabot review. | Checksums from a compromised release account are insufficient alone; verify GitHub attestations and protect release environments/tags. |
| Runner compromise | No privileged requirement or runtime socket; assessment container drops capabilities. | A hostile host controls kernel interfaces, network and files and can forge evidence. TrustFall cannot attest the host. |
| Container isolation limitations | Reports caps/seccomp/LSM/namespaces/cgroups/mounts/sockets separately and never calls configuration proof. | Shared-kernel isolation remains dependent on runtime/kernel correctness; no breakout testing occurs. |
| Untrusted policy/configuration | Strict schema fields, 1 MiB limit, constrained methods/schemes/hosts, no shell evaluation. | Policy can authorise external targets and OIDC/cloud activity. Only reviewed policy should run with credentials. |
| Workflow expression injection | Examples pass inputs through environment variables; shell commands do not evaluate input strings. Active cloud examples construct a static, validated policy from constrained repository variables. | A maintainer-controlled image reference or workflow revision is executable authority. Pin and review it. |
| Validation-image publication | The manual validation workflow alone has a narrowly scoped build job with `packages: write`; runtime jobs receive only package read where needed and consume its returned digest. | Dispatch creates a non-release GHCR artifact. Review the commit and retain the hosted run record. |
| Report tampering | Stable fingerprints, run provenance, release attestation guidance, immutable artifacts once uploaded. | A job with write access to report files can alter them before upload. For high assurance, attest reports externally after the job. |
| Misleading/inconclusive evidence | Four evidence classes, unknown on denial/timeouts, explicit operation wording, no fabricated SARIF locations or confidence score. | Users may still overgeneralise point-in-time results. Preserve limitations with downstream presentation. |

## Fail-closed behavior

Unsafe policy forms fail validation. Cloud redirects are refused. AWS, Azure, and GCP never fall back to broader hosts or methods. `--no-network` wins over policy configuration. Missing permissions/interfaces produce unknown/not-applicable. TrustFall never silently adds privilege, credentials, destinations, or a container socket.

## Credential authorisation

Any OIDC or cloud authority must be deliberately granted to the assessment job and scoped to a protected environment and read-only resource where possible. Do not expose cloud identity to fork PR code. GitHub `id-token: write` is additional authority even though it reveals no static secret; it allows minting identity tokens and must not be enabled merely to make a report look complete.

The passive and OIDC-enabled reusable workflows are separate entry points because job permissions are established before steps execute. A shell command or boolean input cannot safely add `id-token: write` at runtime, and the called workflow cannot expand authority withheld by its caller.
