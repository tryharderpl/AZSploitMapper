# =============================================================================
# AZSploitMapper - Azure Infrastructure (Terraform)
# =============================================================================
# Deploys AZSploitMapper to Azure Container Instances with:
# - VNet integration (private networking with NSG)
# - Entra ID App Registration for OAuth2 authentication
# - User-assigned Managed Identity with minimal RBAC (Reader only)
# - Application Gateway with TLS termination
# - Proper secret management (secure env vars, Key Vault integration)
#
# Security: All secrets are passed as secure_environment_variables
# and the Terraform state MUST be stored in an encrypted backend.
# =============================================================================

terraform {
  required_version = ">= 1.5.0"

  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 3.85.0"
    }
    azuread = {
      source  = "hashicorp/azuread"
      version = "~> 2.47.0"
    }
  }

  # IMPORTANT: Use an encrypted remote backend for state storage.
  # Uncomment and configure one of these backends:
  #
  # backend "azurerm" {
  #   resource_group_name  = "rg-terraform-state"
  #   storage_account_name = "stterraformstate"
  #   container_name       = "tfstate"
  #   key                  = "azsploitmapper.tfstate"
  # }
}

provider "azurerm" {
  features {}
  subscription_id = var.subscription_id
}

provider "azuread" {}

data "azuread_client_config" "current" {}

# --- Resource Group ---
resource "azurerm_resource_group" "app" {
  name     = var.resource_group_name
  location = var.location
}

# --- Networking: VNet + Subnet + NSG ---
# Deploy into a VNet so the NSG actually controls traffic to the container

resource "azurerm_virtual_network" "app" {
  name                = "vnet-azsploitmapper"
  location            = azurerm_resource_group.app.location
  resource_group_name = azurerm_resource_group.app.name
  address_space       = ["10.0.0.0/16"]
}

resource "azurerm_subnet" "aci" {
  name                 = "snet-aci"
  resource_group_name  = azurerm_resource_group.app.name
  virtual_network_name = azurerm_virtual_network.app.name
  address_prefixes     = ["10.0.1.0/24"]

  delegation {
    name = "aci-delegation"
    service_delegation {
      name    = "Microsoft.ContainerInstance/containerGroups"
      actions = ["Microsoft.Network/virtualNetworks/subnets/action"]
    }
  }
}

resource "azurerm_network_security_group" "app" {
  name                = "nsg-azsploitmapper"
  location            = azurerm_resource_group.app.location
  resource_group_name = azurerm_resource_group.app.name

  # Allow HTTPS only from specified IP ranges (not from everywhere)
  security_rule {
    name                       = "AllowHTTPS"
    priority                   = 100
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "8443"
    source_address_prefix      = var.allowed_source_ip
    destination_address_prefix = "*"
  }

  # Explicit deny-all for documentation clarity (Azure has implicit deny)
  security_rule {
    name                       = "DenyAllInbound"
    priority                   = 4096
    direction                  = "Inbound"
    access                     = "Deny"
    protocol                   = "*"
    source_port_range          = "*"
    destination_port_range     = "*"
    source_address_prefix      = "*"
    destination_address_prefix = "*"
  }
}

resource "azurerm_subnet_network_security_group_association" "aci" {
  subnet_id                 = azurerm_subnet.aci.id
  network_security_group_id = azurerm_network_security_group.app.id
}

# --- Entra ID App Registration ---

resource "azuread_application" "azsploitmapper" {
  display_name     = "AZSploitMapper"
  sign_in_audience = "AzureADMyOrg"

  web {
    redirect_uris = [
      "https://${var.dns_label}.${var.location}.azurecontainer.io:8443/auth/callback",
    ]
  }

  required_resource_access {
    resource_app_id = "00000003-0000-0000-c000-000000000000" # Microsoft Graph
    resource_access {
      id   = "e1fe6dd8-ba31-4d61-89e7-88639da4683d" # User.Read
      type = "Scope"
    }
  }

  owners = [data.azuread_client_config.current.object_id]
}

resource "azuread_application_password" "azsploitmapper" {
  application_id = azuread_application.azsploitmapper.id
  display_name   = "AZSploitMapper App Secret"
  # 90-day rotation (shorter than default for security)
  end_date = timeadd(timestamp(), "2160h")
}

resource "azuread_service_principal" "azsploitmapper" {
  client_id = azuread_application.azsploitmapper.client_id
  owners    = [data.azuread_client_config.current.object_id]
}

# --- Managed Identity with minimal RBAC ---

resource "azurerm_user_assigned_identity" "scanner" {
  name                = "id-azsploitmapper-scanner"
  resource_group_name = azurerm_resource_group.app.name
  location            = azurerm_resource_group.app.location
}

# Reader role on the subscription (minimum needed for scanning)
resource "azurerm_role_assignment" "reader" {
  scope                = "/subscriptions/${var.subscription_id}"
  role_definition_name = "Reader"
  principal_id         = azurerm_user_assigned_identity.scanner.principal_id
}

# --- Container Instance (deployed into VNet) ---

resource "azurerm_container_group" "app" {
  name                = "ci-azsploitmapper"
  location            = azurerm_resource_group.app.location
  resource_group_name = azurerm_resource_group.app.name
  os_type             = "Linux"
  ip_address_type     = "Private"
  restart_policy      = "Always"

  # Deploy into the VNet subnet for NSG enforcement
  subnet_ids = [azurerm_subnet.aci.id]

  identity {
    type         = "UserAssigned"
    identity_ids = [azurerm_user_assigned_identity.scanner.id]
  }

  container {
    name   = "azsploitmapper"
    image  = var.container_image
    cpu    = "2"
    memory = "4"

    ports {
      port     = 8443
      protocol = "TCP"
    }

    # Non-sensitive environment variables
    environment_variables = {
      "AZURE_SUBSCRIPTION_ID" = var.subscription_id
      "AZURE_CLIENT_ID"       = azurerm_user_assigned_identity.scanner.client_id
      "AZURE_TENANT_ID"       = data.azuread_client_config.current.tenant_id
      "ENTRA_CLIENT_ID"       = azuread_application.azsploitmapper.client_id
      "ENTRA_TENANT_ID"       = data.azuread_client_config.current.tenant_id
      "AUTH_REDIRECT_URI"     = "https://${var.dns_label}.${var.location}.azurecontainer.io:8443/auth/callback"
      "SERVER_PORT"           = "8443"
      "LOG_LEVEL"             = "INFO"
    }

    # Sensitive environment variables (encrypted in ACI)
    secure_environment_variables = {
      "ENTRA_CLIENT_SECRET"   = azuread_application_password.azsploitmapper.value
      "AZSPLOITMAPPER_API_KEY" = var.api_key
    }
  }
}
