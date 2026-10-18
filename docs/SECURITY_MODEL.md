# Security model

## Safety invariants

TrustFall does not require a privileged container, added capabilities, host PID namespace, or a Docker/runtime socket. Baseline assessment is passive and defaults to no configured active destinations. The supplied reusable job drops all Linux capabilities and sets no-new-privileges.

Secret values are out of scope for evidence. Credential-pattern environment variables are matched by name only. Known credential paths are `lstat`/access checked; contents are not opened and usability is not inferred from presence. OIDC tokens and temporary AWS, Azure, and GCP credentials live only in request-local memory; they are never logged, hashed, persisted, placed in findings, or included in errors. The generic redactor removes secret-like string values, URL userinfo and JWT-shaped strings before normalization while preserving boolean facility-presence markers.

Network operations require exact policy targets. DNS performs one lookup, TCP one connection, and HTTPS one HEAD with at most three same-origin redirects. Concurrency is 1–16 and every probe has a deadline. Metadata probing is separately enabled and performs a fixed HEAD against provider endpoints, never reads its body, and never requests a credential path. Cloud redirects are refused. AWS signs only validated endpoint GET/HEAD operations and allowlisted query actions; Azure accepts only HTTPS `management.azure.com` GET/HEAD targets; GCP accepts only HTTPS `*.googleapis.com` GET/HEAD targets. Cloud response bodies are not recorded. For an explicitly targeted Azure role-assignment list operation, TrustFall may parse the bounded response solely to record an object count and discards all role fields.

## Evidence semantics

Observed means local inspection occurred. Verified means the precise recorded operation was executed successfully or received a provider response. Inferred means available configuration suggests, but does not establish, access. Unknown means the operation was unavailable, refused, timed out, disabled, or otherwise insufficient. These classifications describe evidence strength; status describes comparison with an expected condition.

A denied request is useful evidence about that request but is not universal proof of no access. TrustFall therefore keeps transport failures unknown; an authenticated provider denial is a verified outcome only for the exact operation and conditions recorded. A successful endpoint connection does not imply authentication. UID 0 inside a remapped user namespace is reported separately from host UID 0 and is never treated as proof of host-root access.

## Policy and exits

Audit mode records findings and exits zero unless an operational error occurs. Enforce mode exits 2 only for a failing finding meeting `fail_on`, a denied rule, or a conclusive mismatch with an explicit expectation. Unknown and not-applicable expectation results remain inconclusive rather than violations. Organisations that require evidence availability should separately require specific rule classifications in report-processing controls; v1 intentionally does not reinterpret unknown as pass or fail.

Policy files can expand active scope and must be code-reviewed. Validation rejects unknown fields and unsafe target forms, but it cannot decide whether a syntactically valid external target is organisationally authorised.

## Report handling

Reports may contain repository, actor, ref, workflow, mount path, target name and selected OIDC claims. Treat them as internal security artifacts. Retention should be short, access controlled, and separate from public logs. SARIF omits locations rather than assigning runtime findings to arbitrary source files.
