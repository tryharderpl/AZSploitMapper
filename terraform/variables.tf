variable "location" {
  description = "Azure region for deployment"
  type        = string
  default     = "westeurope"
}

variable "subscription_id" {
  description = "Azure subscription ID to scan"
  type        = string
  sensitive   = true
}

variable "container_image" {
  description = "Docker image for AZSploitMapper"
  type        = string
  default     = "ghcr.io/cybersteps/azsploitmapper:latest"
}

variable "resource_group_name" {
  description = "Name for the resource group"
  type        = string
  default     = "rg-azsploitmapper"
}

variable "dns_label" {
  description = "DNS label for the container instance (must be globally unique)"
  type        = string
  default     = "azsploitmapper"
}

variable "allowed_source_ip" {
  description = "IP address or CIDR range allowed to access the dashboard (restrict to your IP)"
  type        = string
  default     = "*"

  validation {
    condition     = var.allowed_source_ip != "*" || var.allowed_source_ip == "*"
    error_message = "WARNING: Setting allowed_source_ip to '*' allows access from any IP. Consider restricting to your corporate IP range."
  }
}

variable "api_key" {
  description = "API key for AZSploitMapper dashboard access (generate with: python -m azsploitmapper generate-api-key --name prod)"
  type        = string
  sensitive   = true
}
