# Live Demo Script — Policy-as-Code Privilege Laundering via GitHub OIDC

## Pre-demo setup (do this before the talk, not live)
1. Create an isolated demo subscription under a dedicated management group.
Deploy the **secure baseline** first, show it working cleanly:
```bash
az deployment sub create --location westeurope \
  --template-file infra/pipeline-identity.bicep \
  --parameters githubOrg=<org> githubRepo=<repo> githubEnvironment=production
```

   Configure the GitHub repo: Settings > Environments > `production` > require
   reviewers; Settings > Secrets and variables > Actions > Variables: set
   `AZURE_CLIENT_ID`, `AZURE_TENANT_ID`, `AZURE_SUBSCRIPTION_ID`,
   `MANAGEMENT_GROUP_ID`, `LOG_ANALYTICS_WORKSPACE_ID`, `REMEDIATION_IDENTITY_RESOURCE_ID`.
   Push to `main` → `deploy-policy.yml` runs, waits for required review, deploys
   cleanly. **Narrate:** "OIDC, no secrets, least privilege pipeline identity,
   required reviewers, minimal explicit remediation role. This is what 'done
   right' looks like."
3. Now deploy the **vulnerable variant** identity in the same demo subscription
   (different UAMI, don't overwrite the secure one):
   ```bash
   az deployment mg create --management-group-id <mg-id> --location westeurope \
     --template-file infra/pipeline-identity.VULNERABLE.bicep \
     --parameters githubOrg=<org> githubRepo=<repo> identitySubscriptionId=<sub-id>
   ```
   Add the corresponding `deploy-policy.VULNERABLE.yml` workflow to the repo
   (or a second demo repo) with **no** environment protection configured.

## Live attack walkthrough (the part you perform on stage)
1. **Set the scene:** "I'm a contractor with just enough GitHub access to open
   a branch and a PR on the policy-as-code repo — no Azure access at all."
   ```bash
   git checkout -b feature/add-blob-lifecycle-policy
   ```
2. **Edit `infra/policy-definition.bicep`**, replacing the whole
   `template: { ... }` object in the `deployment.properties` field with the
   contents of `attack/malicious-template-injection.bicep` (set
   `<ATTACKER_PRINCIPAL_ID>` to a service principal you control, created ahead
   of time purely for the demo).

   Use the `.bicep` fragment, not the `.json` one: the embedded template in
   `policy-definition.bicep` is Bicep object notation (unquoted keys,
   `\'`-escaped ARM expressions), so the raw JSON will not compile if pasted in.
   The payload also needs a `variables` block, so swap the entire `template:`
   object rather than just its `resources` array.
   (`malicious-template-injection.json` is kept as the equivalent standalone ARM
   artifact for reference.)

   This is the attacker-controlled diff: instead
   of only creating a diagnostic setting, the injected template *also* creates
   a role assignment granting **Owner** to an attacker-controlled principal.
   This deploys using the remediation identity's permissions (Contributor at
   management group scope in the VULNERABLE variant) — the attacker's own
   GitHub-side identity never held `roleAssignments/write` in Azure.
3. **Push the branch — no PR needed** (the vulnerable workflow triggers on any
   branch push):
   ```bash
   git add infra/policy-definition.bicep
   git commit -m "Add blob lifecycle diagnostic coverage"
   git push origin feature/add-blob-lifecycle-policy
   ```
4. **Show the Actions tab:** the workflow fires immediately — no required
   reviewer gate (no `environment:` key), authenticates via OIDC using the
   wildcard-trusted FIC, and deploys using the pipeline identity's Resource
   Policy Contributor rights to update the policy definition.
5. **Trigger remediation** (the workflow does this automatically in the last
   step, or run manually to narrate it):
   ```bash
   az policy remediation create --name attacker-demo-remediation \
     --policy-assignment "/providers/Microsoft.Management/managementGroups/<mg-id>/providers/Microsoft.Authorization/policyAssignments/demo-diag-settings-assignment-vuln" \
     --resource-discovery-mode ExistingNonCompliant
   ```
6. **Reveal the payoff:**
   ```bash
   az role assignment list --all --assignee <attacker-service-principal-object-id> -o table
   ```
   Show **Owner** at the management group / subscription scope, granted to a
   principal the "contractor" controls — who never held `roleAssignments/write`
   or any Azure RBAC role themselves.

## The punchline slide
"No secret was stolen. No Azure credential was phished. The only thing
compromised was a GitHub branch push on a repo the attacker already had access
to — and OIDC federation, the thing we adopted specifically to eliminate
credential theft, faithfully relayed that access straight into Azure."

## Reset between demo runs
```bash
az role assignment delete --assignee <attacker-service-principal-object-id> \
  --role Owner --scope "/providers/Microsoft.Management/managementGroups/<mg-id>"
az policy remediation delete --name attacker-demo-remediation \
  --policy-assignment "/providers/Microsoft.Management/managementGroups/<mg-id>/providers/Microsoft.Authorization/policyAssignments/demo-diag-settings-assignment-vuln"
git checkout main && git branch -D feature/add-blob-lifecycle-policy
git push origin --delete feature/add-blob-lifecycle-policy
```

## Mitigations to show on the closing slide
- FIC subject must be `environment:`-scoped (exact match) with required
  reviewers configured on that GitHub Environment — never a wildcard
  `ref:refs/heads/*` or repo-wide subject.
- Pipeline identity should never be broader than `Resource Policy Contributor`,
  scoped to the minimum management surface — never `User Access Administrator`
  or `Owner`.
- Remediation identity role grants must be explicit, PR-reviewed IaC (as in
  the secure baseline) — never the Portal's auto-grant-on-assignment behavior,
  which silently expands to whatever `roleDefinitionIds` lists.
- Pin third-party GitHub Actions to a commit SHA, not a tag.
- Alert on `Microsoft.Authorization/roleAssignments/write` where the caller is
  a policy-assignment-created managed identity (unexpected for most legitimate
  remediation payloads).
