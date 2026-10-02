variable "resource_group_name" {
  description = "Name of the Azure Resource Group"
  type        = string
  default     = "vulnpilot-rg"
}

variable "location" {
  description = "Azure region for all resources"
  type        = string
  default     = "eastus"
}

variable "app_name" {
  description = "Base name for application resources"
  type        = string
  default     = "vulnpilot"
}

variable "acr_name" {
  description = "Azure Container Registry name (must be globally unique, alphanumeric only)"
  type        = string
  default     = "vulnpilotacr"
}

variable "openai_key_vault_secret_id" {
  description = "Key Vault secret ID for the OpenAI API key. Leave empty to disable LLM integration."
  type        = string
  default     = ""
  sensitive   = true
}

variable "tags" {
  description = "Tags applied to all resources"
  type        = map(string)
  default = {
    project     = "vulnpilot"
    environment = "production"
    managed_by  = "terraform"
  }
}
