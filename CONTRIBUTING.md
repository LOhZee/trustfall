# Contributing

Use Go 1.26.5 or newer. Run `gofmt -w cmd internal`, `go test -race ./...`, `go vet ./...`, and a local container build before opening a pull request. New probes need deterministic rule IDs, explicit requirements/timeouts, safe fixture tests, evidence classification tests, and documentation of what success and failure do **not** prove.

Never add a probe that reads secret values, scans an address range, mutates cloud resources, requires privileged execution, or silently broadens scope. Changes to active probes, release dependencies, policies and workflows require security review. Pin third-party actions to full commit SHAs and explain the upstream version in a comment.

Releases follow semantic versioning. Breaking report/policy schema changes require a new schema major version. A maintainer creates a signed `vMAJOR.MINOR.PATCH` GitHub Release after CI and security review. The release workflow then publishes checksummed binaries and an attested multi-architecture image. Verify artifacts and the image digest before moving the signed `vMAJOR` tag or updating integration variables; ordinary pushes and pull requests cannot publish.
