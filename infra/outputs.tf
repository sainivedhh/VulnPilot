output "api_url" {
  description = "Public URL of the VulnPilot API"
  value       = "https://${azurerm_container_app.api.ingress[0].fqdn}"
}

output "acr_login_server" {
  description = "ACR login server for pushing images"
  value       = azurerm_container_registry.acr.login_server
}

output "key_vault_id" {
  description = "Key Vault resource ID"
  value       = azurerm_key_vault.kv.id
}

output "app_identity_principal_id" {
  description = "Principal ID of the managed identity (for RBAC assignments)"
  value       = azurerm_user_assigned_identity.app_identity.principal_id
}

output "log_analytics_workspace_id" {
  description = "Log Analytics workspace ID"
  value       = azurerm_log_analytics_workspace.logs.id
}
