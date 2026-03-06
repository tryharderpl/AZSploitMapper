# ============================================================
# PROVIDER CONFIGURATION
# ============================================================
# This tells Terraform to use the Azure Resource Manager (azurerm)
# provider so it knows how to create Azure resources.

terraform {
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 3.0"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.0"
    }
  }
}

provider "azurerm" {
  features {}
}

# ============================================================
# VARIABLES
# ============================================================
# Variables let you customize the deployment without editing
# the main code. You can override them at deploy time.

variable "location" {
  description = "Azure region where resources will be created"
  default     = "West Europe"
}

variable "admin_username" {
  description = "Username for the VM administrator account"
  default     = "labadmin"
}

variable "admin_password" {
  description = "Password for the VM administrator account"
  default     = "VulnLab@2025!"
  sensitive   = true
}

# Random suffix to make the storage account name globally unique.
# Azure storage account names must be unique across ALL of Azure.
resource "random_string" "suffix" {
  length  = 6
  special = false
  upper   = false
}

# ============================================================
# RESOURCE GROUP
# ============================================================
# A resource group is a logical container for Azure resources.
# All resources in this lab will live inside this group, making
# it easy to delete everything at once when you are done.

resource "azurerm_resource_group" "lab" {
  name     = "rg-vulnerable-lab"
  location = var.location
}

# ============================================================
# NETWORKING
# ============================================================
# Every VM in Azure needs a Virtual Network (VNet) and a Subnet.
# Think of a VNet as your own private network in the cloud.

resource "azurerm_virtual_network" "lab" {
  name                = "vnet-vulnerable-lab"
  address_space       = ["10.0.0.0/16"]
  location            = azurerm_resource_group.lab.location
  resource_group_name = azurerm_resource_group.lab.name
}

resource "azurerm_subnet" "lab" {
  name                 = "subnet-lab"
  resource_group_name  = azurerm_resource_group.lab.name
  virtual_network_name = azurerm_virtual_network.lab.name
  address_prefixes     = ["10.0.1.0/24"]
}

# ============================================================
# VULNERABILITY #1: Network Security Group - ALL PORTS OPEN
# ============================================================
# A Network Security Group (NSG) acts as a firewall for your VM.
# In a secure setup, you would only allow specific ports like
# SSH (22) from your IP address.
#
# HERE WE INTENTIONALLY ALLOW ALL TRAFFIC FROM ANY SOURCE
# TO ANY DESTINATION ON ANY PORT. This means anyone on the
# internet can attempt to connect to every service on this VM.
#
# WHY THIS IS DANGEROUS: An attacker can scan all 65535 ports,
# find any running service, and try to exploit it. There is no
# network-level protection at all.

resource "azurerm_network_security_group" "vulnerable" {
  name                = "nsg-allow-all"
  location            = azurerm_resource_group.lab.location
  resource_group_name = azurerm_resource_group.lab.name

  security_rule {
    name                       = "AllowEverythingInbound"
    priority                   = 100
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "*"
    source_port_range          = "*"
    destination_port_range     = "*"
    source_address_prefix      = "*"
    destination_address_prefix = "*"
  }
}

# ============================================================
# PUBLIC IP ADDRESS
# ============================================================
# A Public IP makes the VM directly reachable from the internet.
# Combined with the "allow all" NSG above, this is extremely
# dangerous - the VM is fully exposed with no firewall.

resource "azurerm_public_ip" "vm" {
  name                = "pip-vulnerable-vm"
  location            = azurerm_resource_group.lab.location
  resource_group_name = azurerm_resource_group.lab.name
  allocation_method   = "Static"
  sku                 = "Standard"
}

# ============================================================
# NETWORK INTERFACE
# ============================================================
# The NIC connects the VM to the subnet and assigns it the
# public IP address.

resource "azurerm_network_interface" "vm" {
  name                = "nic-vulnerable-vm"
  location            = azurerm_resource_group.lab.location
  resource_group_name = azurerm_resource_group.lab.name

  ip_configuration {
    name                          = "internal"
    subnet_id                     = azurerm_subnet.lab.id
    private_ip_address_allocation = "Dynamic"
    public_ip_address_id          = azurerm_public_ip.vm.id
  }
}

# Associate the "allow all" NSG with the network interface.
# This is what actually applies the insecure firewall rules to the VM.
resource "azurerm_network_interface_security_group_association" "vm" {
  network_interface_id      = azurerm_network_interface.vm.id
  network_security_group_id = azurerm_network_security_group.vulnerable.id
}

# ============================================================
# VULNERABILITY #2: VIRTUAL MACHINE WITH MANAGED IDENTITY
# ============================================================
# This VM uses a System-Assigned Managed Identity. A managed
# identity is like giving the VM its own "username" in Azure AD
# so it can authenticate to other Azure services without storing
# any passwords or keys.
#
# By itself, managed identity is a GOOD security practice.
# But when combined with the open NSG and an overly broad role
# assignment (see below), it becomes an attack path: anyone who
# compromises this VM automatically inherits its identity and
# all the permissions that come with it.

resource "azurerm_linux_virtual_machine" "vulnerable" {
  name                            = "vm-vulnerable-lab"
  resource_group_name             = azurerm_resource_group.lab.name
  location                        = azurerm_resource_group.lab.location
  size                            = "Standard_D2s_v3"
  admin_username                  = var.admin_username
  admin_password                  = var.admin_password
  disable_password_authentication = false
  network_interface_ids           = [azurerm_network_interface.vm.id]

  os_disk {
    caching              = "ReadWrite"
    storage_account_type = "Standard_LRS"
  }

  source_image_reference {
    publisher = "Canonical"
    offer     = "0001-com-ubuntu-server-jammy"
    sku       = "22_04-lts"
    version   = "latest"
  }

  identity {
    type = "SystemAssigned"
  }
}

# ============================================================
# VULNERABILITY #3: STORAGE ACCOUNT WITH PUBLIC ACCESS
# ============================================================
# A Storage Account holds blobs (files), queues, tables, and
# file shares. In a secure setup you would:
#   - Set network_rules with default_action = "Deny"
#   - Only allow access from specific VNets or IP addresses
#   - Disable public blob access
#
# HERE WE INTENTIONALLY:
#   - Allow public blob access (allow_nested_items_to_be_public = true)
#   - Do NOT set any network rules (default allows all networks)
#   - Create a container with "blob" access level (anyone with
#     the URL can read the files without authentication)
#
# WHY THIS IS DANGEROUS: Sensitive data stored here can be
# accessed by anyone who knows (or guesses) the blob URL.

resource "azurerm_storage_account" "sensitive" {
  name                            = "stvulnlab${random_string.suffix.result}"
  resource_group_name             = azurerm_resource_group.lab.name
  location                        = azurerm_resource_group.lab.location
  account_tier                    = "Standard"
  account_replication_type        = "LRS"
  allow_nested_items_to_be_public = true
  min_tls_version                 = "TLS1_0"
}

resource "azurerm_storage_container" "secrets" {
  name                  = "sensitive-data"
  storage_account_name  = azurerm_storage_account.sensitive.name
  container_access_type = "blob"
}

# Upload a fake "sensitive" file to demonstrate data exposure.
# In a real scenario this could be database backups, credentials,
# customer data, or encryption keys.
resource "azurerm_storage_blob" "credentials" {
  name                   = "database-credentials.txt"
  storage_account_name   = azurerm_storage_account.sensitive.name
  storage_container_name = azurerm_storage_container.secrets.name
  type                   = "Block"
  source_content         = <<-EOT
    ==========================================
    CONFIDENTIAL - DATABASE CREDENTIALS
    ==========================================
    Server:   prod-db-01.internal.company.com
    Port:     5432
    Username: db_admin
    Password: SuperSecretP@ssw0rd!
    Database: production_customers
    ==========================================
    DO NOT SHARE THIS FILE
    ==========================================
  EOT
}

# ============================================================
# VULNERABILITY #4: ROLE ASSIGNMENT - THE ATTACK PATH LINK
# ============================================================
# This is THE critical "link" that creates the attack path.
#
# We grant the VM's managed identity the "Storage Blob Data
# Reader" role on the storage account. This means any process
# running on the VM can read ALL blobs in this storage account
# simply by requesting a token from the Azure Instance Metadata
# Service (IMDS) at http://169.254.169.254.
#
# ATTACK PATH:
#   1. Attacker finds the VM's public IP (it is exposed)
#   2. Attacker exploits an open service (all ports are open)
#   3. Attacker gets a shell on the VM
#   4. Attacker uses the VM's managed identity to get an
#      access token: curl the IMDS endpoint
#   5. Attacker uses that token to list and download blobs
#      from the storage account
#   6. Attacker reads the database credentials file
#
# The attacker never needed ANY Azure credentials. The VM's
# identity did all the authentication automatically.

resource "azurerm_role_assignment" "vm_to_storage" {
  scope                = azurerm_storage_account.sensitive.id
  role_definition_name = "Storage Blob Data Reader"
  principal_id         = azurerm_linux_virtual_machine.vulnerable.identity[0].principal_id
}

# ============================================================
# OUTPUTS
# ============================================================
# Outputs display important values after deployment completes.

output "vm_public_ip" {
  description = "Public IP of the vulnerable VM"
  value       = azurerm_public_ip.vm.ip_address
}

output "storage_account_name" {
  description = "Name of the storage account with sensitive data"
  value       = azurerm_storage_account.sensitive.name
}

output "sensitive_blob_url" {
  description = "Direct URL to the exposed sensitive blob"
  value       = "${azurerm_storage_account.sensitive.primary_blob_endpoint}${azurerm_storage_container.secrets.name}/${azurerm_storage_blob.credentials.name}"
}

output "attack_path_summary" {
  description = "Summary of the attack path created"
  value       = "Internet -> Open NSG -> VM (${azurerm_public_ip.vm.ip_address}) -> Managed Identity -> Storage (${azurerm_storage_account.sensitive.name}) -> database-credentials.txt"
}
