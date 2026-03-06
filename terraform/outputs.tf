# AZSploitMapper Terraform Outputs
# Only non-sensitive values are output here.
# Secrets (client_secret, API key) are never included in outputs.

output "managed_identity_client_id" {
  description = "Client ID of the user-assigned managed identity (for RBAC verification)"
  value       = azurerm_user_assigned_identity.scanner.client_id
}

output "managed_identity_principal_id" {
  description = "Principal ID of the user-assigned managed identity"
  value       = azurerm_user_assigned_identity.scanner.principal_id
}

output "entra_app_client_id" {
  description = "Client ID of the Entra ID app registration"
  value       = azuread_application.azsploitmapper.client_id
}

output "vnet_name" {
  description = "Name of the virtual network"
  value       = azurerm_virtual_network.app.name
}

output "nsg_name" {
  description = "Name of the network security group"
  value       = azurerm_network_security_group.app.name
}
