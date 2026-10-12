// remediation-identity.bicep
// SECURE BASELINE: pre-provisioned remediation identity for the policy assignment.
// Deployed OUT OF BAND by an administrator (not by any pipeline), so that no
// GitHub-federated identity ever needs Microsoft.Authorization/roleAssignments/write.
//
// It creates a user-assigned managed identity, grants it ONLY Log Analytics
// Contributor on ONE target resource group, and (optionally) grants the
// policy-assignment deployer Managed Identity Operator on that identity alone.
//
//   az deployment sub create --location westeurope \
//     --template-file infra/remediation-identity.bicep \
//     --parameters remediationTargetSubscriptionId=<sub-id> \
//       remediationTargetResourceGroupName=<rg> \
//       assignmentDeployerPrincipalId=<bootstrap-sp-object-id>

targetScope = 'subscription'

@description('Resource group where the remediation identity is created')
param identityResourceGroupName string = 'rg-policy-remediation'

@description('Name of the remediation user-assigned managed identity')
param uamiName string = 'uami-policy-remediation'

@description('Location for the identity resource group')
param location string = 'westeurope'

@description('Subscription ID that contains the remediation target resource group')
param remediationTargetSubscriptionId string

@description('Resource group the remediation identity may modify')
param remediationTargetResourceGroupName string

@description('Object ID of the principal that deploys the policy assignment (production-bootstrap). Leave empty to grant later.')
param assignmentDeployerPrincipalId string = ''

var logAnalyticsContributorRoleId = '92aaf0da-9dab-42b6-94a3-d43ce8d16293'

resource identityRg 'Microsoft.Resources/resourceGroups@2023-07-01' = {
  name: identityResourceGroupName
  location: location
}

module remediationUami 'modules/remediation-uami.bicep' = {
  name: 'remediationUami'
  scope: identityRg
  params: {
    location: location
    uamiName: uamiName
    assignmentDeployerPrincipalId: assignmentDeployerPrincipalId
  }
}

// Explicit, minimal grant: only the role the policy needs, on one resource group.
module grantRemediationRole 'modules/scoped-role-assignment.bicep' = {
  name: 'grantRemediationRole'
  scope: resourceGroup(remediationTargetSubscriptionId, remediationTargetResourceGroupName)
  params: {
    principalId: remediationUami.outputs.principalId
    roleDefinitionId: logAnalyticsContributorRoleId
    nameSeed: '${subscription().subscriptionId}/${identityResourceGroupName}/${uamiName}'
  }
}

output remediationIdentityResourceId string = remediationUami.outputs.resourceId
output remediationIdentityPrincipalId string = remediationUami.outputs.principalId
