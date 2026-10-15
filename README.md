# Demo: Stealing & Abusing Azure Identities via Policy-as-Code (GitHub OIDC)

## Scenario
A platform team deploys Azure Policy (deployIfNotExists / modify) through a GitHub Actions
pipeline. The pipeline authenticates to Azure using a **user-assigned managed identity (UAMI)**
trusted via a **federated identity credential (FIC)** — no client secret, no stored credential.
The pipeline identity itself holds only **Resource Policy Contributor** (least privilege, no
`roleAssignments/write`).

The twist: every policy **assignment** with a `deployIfNotExists`/`modify` effect needs its own
**separate runtime managed identity** to perform the actual remediation deployment. That identity
is granted whatever roles the policy's `roleDefinitionIds` lists — commonly **Contributor**. The
pipeline never holds `roleAssignments/write`, but code it deploys controls what that *other*
identity does. This is the privilege-laundering seam the demo exploits.

## Folder structure

What's in `files/azure-identity-demo/` (saved to your session storage)

| File | Purpose |
| --- | --- |
| `infra/pipeline-identity.bicep` | **Secure baseline**: UAMI + FIC scoped to `environment:production` (exact match), Resource Policy Contributor only |
| `infra/pipeline-identity.VULNERABLE.bicep` | **Demo variant**: wildcard FIC subject (`ref:refs/heads/*`), Contributor at management-group scope |
| `infra/policy-definition.bicep` | Realistic custom `deployIfNotExists` policy (diagnostic settings) |
| `infra/remediation-identity.bicep` | **Admin-run, out of band**: pre-provisioned remediation UAMI with only Log Analytics Contributor on one RG |
| `infra/policy-assignment.bicep` / `.VULNERABLE.bicep` | Contrast: pre-provisioned minimal remediation identity vs. broad auto-granted Contributor |
| `.github/workflows/deploy-identity.yml` | Manually bootstrap the secure pipeline identity |
| `.github/workflows/deploy-policy.yml` | Deploy the secure policy definition, then its assignment bound to the pre-provisioned remediation identity |
| `attack/malicious-template-injection.json` | The attacker payload — injects an Owner role assignment, laundered through the remediation identity |
| `attack/attack-walkthrough.md` | Full live-demo script: setup, attack steps, reset commands, closing mitigation slide |


## Two configurations to contrast

| | Secure baseline | Vulnerable demo variant |
|---|---|---|
| FIC subject | `repo:org/repo:environment:production` (exact match) | `repo:org/repo:ref:refs/heads/*` (wildcard — any branch) |
| GitHub Environment protection | Required reviewers + restricted to `main` | None |
| Pipeline identity scope | Resource Policy Contributor at **subscription scope** in the identity template; management-group access must be provisioned separately for policy deployment | Resource Policy Contributor at **management group** |
| Remediation MI role grant | Pre-provisioned UAMI with explicit, minimal `Log Analytics Contributor` on the target RG, granted out of band by an admin; no pipeline identity holds `roleAssignments/write` | `Contributor` at management group scope, auto-expanded by a "helper" policy initiative |
| Branch protection on policy repo | Required PR review, no direct push to `main` | Direct push allowed / stale unpinned third-party Action |

1. Run the secure baseline first to show "this looks airtight, OIDC, no secrets, least privilege."
2. Switch to the vulnerable variant to show how a single loosened control (wildcard FIC subject,
   or an unpinned/compromised Action in the workflow) reopens the exact same escalation path from
   earlier in the talk this time laundered through a CI/CD pipeline instead of a human.

## Deploying with GitHub Actions

The workflows deploy only the secure Bicep templates, never the `.VULNERABLE`
variants or attack payloads. Both workflows run only from `main` and use OIDC
with commit-pinned actions. No client secrets are needed.

### Environments and variables

Create `production` and `production-bootstrap` GitHub environments. Configure
required reviewers and restrict deployment branches to `main` on **both**
environments; these protections must be configured in repository settings.
Protect `main` with required PR reviews, especially for workflow and Bicep changes.

Set the following repository-level Actions variables:

| Variable | Value |
| --- | --- |
| `AZURE_TENANT_ID` | Azure tenant ID |
| `AZURE_SUBSCRIPTION_ID` | Subscription containing the pipeline identity |
| `MANAGEMENT_GROUP_ID` | Management group containing the policy definition and assignment |
| `LOG_ANALYTICS_WORKSPACE_ID` | Full resource ID of an existing Log Analytics workspace |
| `REMEDIATION_IDENTITY_RESOURCE_ID` | Full resource ID of the remediation UAMI (`remediationIdentityResourceId` output of `infra/remediation-identity.bicep`) |
| `AZURE_LOCATION` | Optional deployment/identity location; defaults to `westeurope` |
| `IDENTITY_RESOURCE_GROUP` | Optional identity RG name; defaults to `rg-policy-pipeline` |

Set `AZURE_CLIENT_ID` **separately on each environment**:

- `production-bootstrap`: an independently provisioned bootstrap identity with
  an exact federated subject
  `repo:<owner>/<repo>:environment:production-bootstrap`. It must already exist
  before either workflow can use it. Grant it resource-group, managed-identity,
  federated-credential, and deployment management permissions in the identity
  subscription, plus permission to create the template's subscription role
  assignment. For policy assignment deployment it needs only policy assignment
  and deployment permissions at the management group (e.g. Resource Policy
  Contributor) and Managed Identity Operator on the remediation UAMI. It needs
  **no** RBAC administration rights for the policy assignment: the remediation
  role grant is made out of band by an administrator.
- `production`: the `uamiClientId` output of the identity deployment. Its FIC
  trusts exactly `repo:<owner>/<repo>:environment:production`. The template
  grants Resource Policy Contributor at subscription scope, **not** management
  group scope. An administrator must separately grant Resource Policy Contributor
  at the configured management group so it can deploy the policy definition.
  Do not grant this identity RBAC administration permissions.

Environment-scoped tenant/subscription variables may override the repository
values if the bootstrap identity uses a different login subscription.

### Deployment order

1. Provision the bootstrap identity and environment protections out of band.
   An administrator also deploys `infra/remediation-identity.bicep` (never from a
   pipeline), passing the bootstrap identity's object ID as
   `assignmentDeployerPrincipalId`, and sets `REMEDIATION_IDENTITY_RESOURCE_ID`
   to its output:

   ```bash
   az deployment sub create --location westeurope \
     --template-file infra/remediation-identity.bicep \
     --parameters remediationTargetSubscriptionId=<sub-id> \
       remediationTargetResourceGroupName=<rg> \
       assignmentDeployerPrincipalId=<bootstrap-sp-object-id>
   ```
2. Run **Deploy Pipeline Identity** manually from `main`. It creates the
   identity RG, UAMI, production FIC, and subscription policy-contributor grant.
   The final step prints the template outputs, including `uamiClientId`.
3. Set the `production` environment's `AZURE_CLIENT_ID` to that output and grant
   its management-group policy permissions as described above.
4. Run **Deploy Policy** manually from `main`, or push a change to its workflow
   or secure policy templates. The production job deploys the definition; the
   separately approved bootstrap job then deploys the assignment, bound to the
   pre-provisioned remediation UAMI, using the definition's output ID.

The workspace and remediation target RG must already exist, and the target
subscription must belong to the selected management group's hierarchy. The
workflows build the Bicep templates before deployment and serialize runs to
avoid overlapping updates. They do not create remediation tasks for existing
noncompliant resources; trigger those separately when needed.

**Trade-off:** the remediation role grant moves out of the PR-reviewed pipeline
into an admin-run IaC step. In exchange, no identity reachable from GitHub can
write role assignments, so pipeline-deployed code can only *bind* the existing,
minimally scoped remediation identity — it cannot widen its permissions.

## Authenticated interactive diagnostic shell

The historical `.github/workflows/OIDC Interactive Shell.yml` filename is retained,
but the workflow is now **Interactive Diagnostic Shell**: it does not request OIDC,
log in to Azure, or inject application credentials. Use only for approved diagnostics
on trusted code. It provides arbitrary Bash execution to authenticated operators,
not a sandbox against those operators. It does not change any cloud resources.

### Files and dependencies

`tools/interactive-shell/` contains:

- `public/index.html`, `terminal.css`, `terminal.js`: the terminal UI, using local
  xterm and fit-addon bundles (no CDN or remote executable loader).
  The branded console layout and cyan/purple palette come from `git-s-hell.yml`;
  local gradients and system fonts replace its remote background image and fonts.
  The xterm theme is configured in `terminal.js`, since page CSS alone cannot
  change xterm's rendered terminal colors.
- `server.js`: explicit static routes, authentication, WebSocket protocol, and PTYs.
- `lifecycle.js`: verified SSH tunnel, endpoint discovery, timeout, and cleanup.
- `*.test.js`: Node's built-in tests, including a real local PTY and mocked tunnels.
- `package.json`, `package-lock.json`: exact direct versions and integrity-locked
  dependency tree. Node 24 LTS is required; the workflow uses Node 24.22.0.

Install with `npm ci` in that directory, not `npm install` during a workflow run.
Linux needs OpenSSH client, Python 3, make, and g++ (the workflow installs these).
`node-pty` has native installation scripts; review dependency changes and commit
the updated lockfile. No code or assets are fetched from arbitrary executable URLs.

### Provisioning and operator connection

1. Separately provision a dedicated repository Actions secret,
   `INTERACTIVE_SHELL_ACCESS_SECRET`, containing a cryptographically random value
   (for example, 32 random bytes encoded as 64 hex characters). Accepted length is
   32–256 printable non-space characters. Share through an approved secret manager,
   **not** Actions logs, outputs, URLs, workflow inputs, or source files.
2. Set repository Actions variable `INTERACTIVE_SHELL_SSH_KNOWN_HOSTS` to a
   `known_hosts` entry for `localhost.run`. Independently verify the current host
   key against the tunnel provider's published information before provisioning;
   do not blindly trust `ssh-keyscan` output. Missing or changed keys fail closed.
   No provisioning or credential rotation is performed by this workflow.
3. Dispatch **Interactive Diagnostic Shell** (or its caller) on a reviewed ref.
   Read the credential-free HTTPS endpoint in the run log. Only open this endpoint
   from a trusted browser. Paste the dedicated secret into the password field.
   Authentication uses an Authorization header, then a five-minute, single-use
   HttpOnly/Secure/SameSite cookie; the secret is cleared from the form and is never
   saved in browser storage. Never append credentials to the URL.
4. Type normally; terminal resizing is automatic. Exit Bash or close the page to
   end the run. A disconnected session is not resumable; dispatch a new run.

The public tunnel uses `localhost.run`; its HTTPS termination is a **trust boundary**:
the provider can observe or alter traffic, including credentials and terminal data.
Use only where this third-party trust is approved. The dedicated secret must not be
reused for other systems. Protect workflow edits and restrict Actions execution to
trusted maintainers. The PTY receives HOME, PATH, TERM, and LANG plus the optional
`AZURE_CLIENT_ID` and `AZURE_TENANT_ID` identifiers described below (Bash adds its
own standard variables), with a temporary home and the checked-out workspace as cwd.
This environment allowlist is not isolation from the server: a trusted shell operator
runs as the same container user and can inspect files/processes. Do not place unrelated
secrets in the job, workspace, or container.

### Optional Azure demo identifiers

Set `AZURE_CLIENT_ID` and `AZURE_TENANT_ID` as repository Actions variables
(recommended for these non-credential identifiers) or repository Actions secrets.
Explicitly supplied secrets take precedence over variables. Both values are
optional and must be UUIDs when supplied; unset/empty values are omitted from the
shell. Direct dispatch and the example caller support both configurations.
External reusable-workflow callers may explicitly map these two optional secrets;
variable fallbacks are read from the caller repository. For local mode, export
the two identifiers before `npm start`.

These values are available to commands as `$AZURE_CLIENT_ID` and
`$AZURE_TENANT_ID`; **they do not authenticate to Azure**. This change does not
install Azure CLI or automatically sign in. Use a separately approved interactive
authentication method with available tooling for the demo. Client secrets, access
tokens, GitHub tokens, OIDC request credentials, and the shell access secret are
still excluded from the PTY environment. No OIDC permissions are added. Never
paste cloud credentials into this third-party-terminated public tunnel.

### Reusable-workflow migration (intentional breaking changes)

`.github/workflows/use-remote.yml` demonstrates a same-commit local call. External
callers should pin `uses: azurekid/policy-as-code/.github/workflows/OIDC Interactive Shell.yml@<full-SHA>`
and pass that **same full SHA** as the required `implementation_ref` input. The
workflow explicitly checks out this repository at that SHA, **not the caller's
repository**. A read-only token must be able to read this public repository.

Pass `INTERACTIVE_SHELL_ACCESS_SECRET` and, if needed, only the optional
`AZURE_CLIENT_ID` and `AZURE_TENANT_ID` identifiers in the caller's `secrets`
mapping, not `secrets: inherit`. All other old Azure/PAT/gallery secret declarations
remain removed; explicit mappings for them must be removed from callers. Set the verified SSH
host-key variable in the caller repository too. Only `contents: read` is needed;
remove caller `id-token: write`. Application-secret inheritance and unauthenticated
public shells are deliberately unsupported. Container privileged mode is removed.

### Local validation and lifecycle

From `tools/interactive-shell/` on Linux with Node 24:

```bash
npm ci
npm run check
npm test
npm audit --omit=dev
read -rsp 'Dedicated test secret: ' INTERACTIVE_SHELL_ACCESS_SECRET; echo
export INTERACTIVE_SHELL_ACCESS_SECRET
npm start
unset INTERACTIVE_SHELL_ACCESS_SECRET
```

Use a disposable random **test-only** secret meeting the length requirement. Open
`http://127.0.0.1:8080`; the local-only mode does not open a tunnel and uses a
non-Secure cookie solely for loopback HTTP. Local mode has a 30-minute limit and
uses the current package directory as cwd (override with `GITHUB_WORKSPACE`).
Tests generate disposable credentials internally and never contact the tunnel service.

The workflow allows at most one active shell and ends after that shell exits or
disconnects. Credentials and the exact discovered Origin are checked **before**
WebSocket upgrade or PTY creation; missing/cross-origin requests are rejected.
Only six explicit static routes are served; arbitrary paths, source files, and
query strings are not served. WebSocket input and dimensions are bounded and typed;
malformed/binary messages close the terminal.

One supervisor owns the server and SSH child. Startup/endpoint-discovery failure
(60 seconds), tunnel/server failure, cancellation signals, and the 115-minute
supervisor timeout all close sockets, kill the PTY and its Linux session's jobs, remove temporary
homes/host-key files, and stop SSH (with a forced-kill fallback). Heartbeats detect
lost clients within about 30 seconds. The Actions job has a 120-minute backstop and
an unprivileged container with an init process; container teardown is the final
cleanup boundary, including jobs deliberately detached by an authorized operator.
SIGKILL/runner loss cannot execute application cleanup. A local shell is likewise
not a containment boundary for deliberately detached processes.

Local tests cover auth rejection, single-use sessions, static assets/content types,
terminal I/O/resize validation, cleanup, and supervisor failures. They do not verify
live `localhost.run` availability, host keys, forwarding behavior, or GitHub runner
cancellation/container teardown. Validate those only in an approved environment,
never by exposing a live secret-bearing shell as a test.
