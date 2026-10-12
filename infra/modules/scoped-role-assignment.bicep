// modules/scoped-role-assignment.bicep
// Helper module so a subscription/management-group-scoped deployment can grant a role at a
// specific resource group scope (Bicep requires the deployment's own scope to
// match the resource being created when using a bare `scope:` property).

targetScope = 'resourceGroup'

@description('Principal ID to grant the role to')
param principalId string

@description('Role definition GUID (not the full resource ID)')
param roleDefinitionId string

@description('A unique seed so the assignment name is deterministic and idempotent')
param nameSeed string

resource roleAssignment 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(resourceGroup().id, nameSeed, roleDefinitionId)
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', roleDefinitionId)
    principalId: principalId
    principalType: 'ServicePrincipal'
  }
}
