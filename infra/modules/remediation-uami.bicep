// modules/remediation-uami.bicep
// Creates the user-assigned managed identity used by the policy assignment for
// deployIfNotExists remediation, and optionally lets the policy-assignment
// deployer attach it (Managed Identity Operator on this identity only).

@description('Location for the identity')
param location string

@description('Name of the remediation user-assigned managed identity')
param uamiName string

@description('Object ID of the principal that deploys the policy assignment. Leave empty to skip the grant.')
param assignmentDeployerPrincipalId string = ''

var managedIdentityOperatorRoleId = 'f1a07417-d97a-45cb-824c-7a7467783830'

resource uami 'Microsoft.ManagedIdentity/userAssignedIdentities@2023-01-31' = {
  name: uamiName
  location: location
  tags: {
    purpose: 'policy-remediation'
  }
}

// Scoped to this single identity: lets the deployer reference it in a policy
// assignment (userAssignedIdentities/assign/action) without any RBAC rights.
resource deployerCanAssign 'Microsoft.Authorization/roleAssignments@2022-04-01' = if (!empty(assignmentDeployerPrincipalId)) {
  name: guid(uami.id, assignmentDeployerPrincipalId, managedIdentityOperatorRoleId)
  scope: uami
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', managedIdentityOperatorRoleId)
    principalId: assignmentDeployerPrincipalId
    principalType: 'ServicePrincipal'
  }
}

output resourceId string = uami.id
output principalId string = uami.properties.principalId
