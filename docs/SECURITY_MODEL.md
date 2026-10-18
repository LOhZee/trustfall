# Security model

## Safety invariants

TrustFall does not require a privileged container, added capabilities, host PID namespace, or a Docker/runtime socket. Baseline assessment is passive and defaults to no configured active destinations. The supplied reusable job drops all Linux capabilities and sets no-new-privileges.

Secret values are out of scope for evidence. Credential-pattern environment variables are matched by name only. Known credential paths are `lstat`/access checked; contents are not opened and usability is not inferred from presence. OIDC tokens and temporary AWS, Azure, and GCP credentials are scoped to the exchange/request path; TrustFall does not intentionally log, hash, persist, place them in findings, or include raw transport errors in reports. Response byte buffers are cleared on a best-effort basis and references are released promptly, but Go strings, decoder allocations and runtime copies cannot be reliably erased from process memory. A process-memory disclosure or compromised runner remains outside this guarantee. The generic redactor removes secret-like string values, URL userinfo and JWT-shaped strings before normalization while preserving boolean facility-presence markers.

Network operations require exact policy targets. DNS performs one lookup, TCP one connection, and HTTPS one HEAD with at most three same-origin redirects. Concurrency is 1–16 and every probe has a deadline. A negative reachability expectation passes only when the policy explicitly names `dns_nxdomain` or `connection_refused` as acceptable `negative_evidence` and that exact outcome occurs. Timeout, cancellation, TLS failure and unavailable probes never become proof of isolation.

Metadata probing is separately enabled and performs a fixed, body-free HEAD against provider endpoints. It bypasses ambient proxies, never requests a credential path and never treats an HTTP status alone as identification of a metadata service. The documented GCP `Metadata-Flavor: Google` response marker can identify GCP; an unmarked AWS/Azure response records only an HTTP interaction. In every case, `metadata_retrieved` and `credential_exposure_tested` remain false. These results are informational/unknown rather than high-severity credential-exposure findings.

Credential-bearing GitHub and cloud clients disable ambient proxies and refuse redirects. AWS signs only validated endpoint GET/HEAD operations and allowlisted query actions using the maintained AWS SDK v2 SigV4 signer, including S3-specific URI behavior. Azure accepts only HTTPS `management.azure.com` GET/HEAD targets; GCP accepts only HTTPS `*.googleapis.com` GET/HEAD targets. Cloud response bodies are not recorded. For an explicitly targeted Azure role-assignment list operation, TrustFall may parse the bounded response solely to record an object count and discards all role fields.

## Evidence semantics

Observed means local inspection occurred. Verified means the precise recorded operation was executed successfully or received a provider response. Inferred means available configuration suggests, but does not establish, access. Unknown means the operation was unavailable, refused, timed out, disabled, or otherwise insufficient. These classifications describe evidence strength; status describes comparison with an expected condition.

A denied request is useful evidence about that request but is not universal proof of no access. Ambiguous transport failures remain unknown; exact NXDOMAIN, connection-refused, TLS-validation and local-policy-denial outcomes may be recorded as verified outcomes of that one test, without establishing broader isolation. An authenticated provider denial is verified only for the exact operation and conditions recorded. A successful endpoint connection does not imply authentication.

Linux ID maps are parsed entry-by-entry with overlap and overflow validation. They describe a relationship to the immediately enclosing user namespace only. Even `0 0 ...` does not prove that the parent is the host's initial user namespace; TrustFall records `initial_user_namespace_established: false` and never equates container UID 0 with demonstrated host-root authority.

## Policy and exits

Audit mode records findings and exits zero unless an operational error occurs. Enforce mode exits 2 only for a failing finding meeting `fail_on`, a denied rule, or a conclusive mismatch with an explicit expectation. Unknown and not-applicable expectation results remain inconclusive rather than violations. Organisations that require evidence availability should separately require specific rule classifications in report-processing controls; v1 intentionally does not reinterpret unknown as pass or fail.

Policy files can expand active scope and must be code-reviewed. Validation rejects unknown fields and unsafe target forms, but it cannot decide whether a syntactically valid external target is organisationally authorised.

## Report handling

Reports may contain repository, actor, ref, workflow, mount path, target name and selected OIDC claims. Treat them as internal security artifacts. Retention should be short, access controlled, and separate from public logs. Report files are created mode `0600`; a non-append output is truncated before rendering so a failed render cannot leave stale prior content. This does not provide crash-consistent or encrypted storage. SARIF omits locations rather than assigning runtime findings to arbitrary source files.
