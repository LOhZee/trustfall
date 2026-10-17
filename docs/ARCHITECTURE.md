# Architecture

TrustFall separates evidence collection from judgment. A probe returns facts with a declared evidence classification; policy evaluation can then compare those facts with an explicit expectation. Configuration presence never upgrades a result to verified.

## Components

`cmd/trustfall` is a thin command/exit-code layer. `internal/engine` runs registered probes under individual deadlines and converts incomplete probes to unknown evidence. `internal/evidence` owns the versioned model, ordering, fingerprints and mandatory redaction. Probe packages contain no policy decisions beyond describing the risk of their own observed condition. `internal/policy` strict-decodes YAML, validates active target boundaries and evaluates explicit expectations. Reporting produces JSON, SARIF and a job summary from the same normalized report. Comparison matches stable rule/target identities and describes differences without causal attribution.

The engine runs passive probes first and active network/cloud probes afterward. `--no-network` prevents network-marked probes from running at the engine boundary, so a provider implementation cannot accidentally bypass it.

## Probe contract

Each probe declares a name, version, module, whether it uses network or performs an active operation, and its required interfaces. It receives a context with a per-probe deadline. Findings include the actual duration and timeout state. A missing `/proc` interface, OIDC permission, network response, or cloud permission becomes unknown/not-applicable—not pass.

Stable rules describe one security property. Multi-target operations add the policy target name to their fingerprint identity. Reports sort rules deterministically; timestamps and run IDs are intentionally variable evidence provenance.

## Trust boundaries

The CLI treats the process environment, procfs, mounts, policy file, DNS, remote endpoints and provider responses as untrusted input. It limits policy files and HTTP bodies to 1 MiB, never records token responses, follows no cloud redirects, restricts HTTPS redirects to the original origin for generic probes, and restricts Azure targets to `management.azure.com` GET/HEAD operations.

The reusable workflow owns a real GitHub container job. The composite Marketplace action runs inside the caller’s already-created job and therefore cannot assess a boundary it did not create. This is a GitHub Actions platform distinction, not an implementation detail.

## Deliberate limitations

- JWT claims are decoded, not cryptographically verified by TrustFall. Token issuance itself is verified by the authenticated GitHub endpoint; `signature_verified: false` is recorded.
- Seccomp mode and LSM labels are observations, not proof that their policies block a particular exploit.
- Filesystem credential probes inspect metadata and accessibility only, never contents.
- TCP/HTTPS success proves one connection/request. Failure remains inconclusive.
- Azure permission discovery is operation-based. TrustFall does not synthesize a universal effective permission set from one response.
- AWS/GCP active cloud providers are not implemented in v1. Metadata reachability has explicit, body-free probes for all three providers.
