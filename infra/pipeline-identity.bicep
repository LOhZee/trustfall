// pipeline-identity.bicep
// SECURE BASELINE: user-assigned managed identity + federated identity credential
// for a GitHub Actions pipeline that deploys Azure Policy. Least privilege:
// Resource Policy Contributor only, scoped to a single resource group's management
// surface (no roleAssignments/write, no Owner/Contributor).
//
// Deploy at subscription scope:
//   az deployment sub create --location westeurope --template-file pipeline-identity.bicep \
//     --parameters githubOrg=contoso githubRepo=policy-as-code githubEnvironment=production

targetScope = 'subscription'

@description('GitHub organization name')
param githubOrg string

@description('GitHub repository name')
param githubRepo string

@description('GitHub Actions environment name that must match the workflow\'s `environment:` key')
param githubEnvironment string = 'production'

@description('Resource group where the UAMI is created')
param identityResourceGroupName string = 'rg-policy-pipeline'

@description('Location for the identity resource group')
param location string = 'westeurope'

// Built-in role: Resource Policy Contributor
var resourcePolicyContributorRoleId = '36243c78-bf99-498c-9df9-86d9f8d28608'
var uamiName = 'uami-gha-policy-pipeline'
// Computed directly (not via module output) because `guid()` in a resource's
// `name` property must be calculable before the module actually deploys.
var uamiResourceId = resourceId(subscription().subscriptionId, identityResourceGroupName, 'Microsoft.ManagedIdentity/userAssignedIdentities', uamiName)

resource identityRg 'Microsoft.Resources/resourceGroups@2023-07-01' = {
  name: identityResourceGroupName
  location: location
}

module uamiModule 'modules/uami-and-fic.bicep' = {
  name: 'uamiAndFic'
  scope: identityRg
  params: {
    location: location
    uamiName: uamiName
    githubOrg: githubOrg
    githubRepo: githubRepo
    githubEnvironment: githubEnvironment
    // SECURE: exact environment-scoped subject, not a wildcard branch/ref
    ficSubject: 'repo:${githubOrg}/${githubRepo}:environment:${githubEnvironment}'
  }
}

// Least-privilege grant: Resource Policy Contributor ONLY — no roleAssignments/write,
// so this identity alone can never directly grant itself or anything else elevated access.
resource policyContributorAssignment 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(uamiResourceId, resourcePolicyContributorRoleId)
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', resourcePolicyContributorRoleId)
    principalId: uamiModule.outputs.principalId
    principalType: 'ServicePrincipal'
  }
}

output uamiClientId string = uamiModule.outputs.clientId
output uamiPrincipalId string = uamiModule.outputs.principalId
output tenantId string = subscription().tenantId
output subscriptionId string = subscription().subscriptionId
