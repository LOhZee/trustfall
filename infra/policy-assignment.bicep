// policy-assignment.bicep
// Assigns the custom policy with a PRE-PROVISIONED user-assigned remediation
// identity (see remediation-identity.bicep, deployed out of band by an admin).
// That identity already holds ONLY Log Analytics Contributor on ONE target
// resource group. This template creates no role assignments, so the pipeline
// identity never needs Microsoft.Authorization/roleAssignments/write.
// This is the secure baseline; contrast with policy-assignment.VULNERABLE.bicep.

targetScope = 'managementGroup'

@description('Resource ID of the policy definition to assign')
param policyDefinitionId string

@description('Resource ID of the Log Analytics workspace parameter value')
param logAnalyticsWorkspaceId string

@description('Resource ID of the pre-provisioned remediation user-assigned managed identity')
param remediationIdentityResourceId string

@description('Location for the assignment identity metadata')
param location string = 'westeurope'

resource policyAssignment 'Microsoft.Authorization/policyAssignments@2022-06-01' = {
  name: 'demo-diag-settings'
  location: location
  identity: {
    type: 'UserAssigned'
    userAssignedIdentities: {
      '${remediationIdentityResourceId}': {}
    }
  }
  properties: {
    displayName: 'Demo - Deploy diagnostic settings (secure baseline)'
    policyDefinitionId: policyDefinitionId
    parameters: {
      logAnalyticsWorkspaceId: {
        value: logAnalyticsWorkspaceId
      }
    }
  }
}

output policyAssignmentId string = policyAssignment.id
output remediationIdentityResourceId string = remediationIdentityResourceId
