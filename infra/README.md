# VulnPilot Infrastructure (Azure)

This module deploys VulnPilot to **Azure Container Apps** using Terraform.

## Architecture

```
Azure Resource Group
├── Container Registry (ACR)          ← Docker images
├── User-Assigned Managed Identity    ← No credentials in code/state
├── Key Vault                         ← OpenAI API key (never in Terraform state)
├── Log Analytics Workspace           ← Centralised logging
└── Container App Environment
    └── Container App (VulnPilot API) ← Autoscaling, HTTPS, health checks
```

## Pre-requisites
- Terraform ≥ 1.5
- Azure CLI authenticated (`az login`)
- An existing Azure subscription

## Usage

```bash
cd infra/
terraform init
terraform plan -var="resource_group_name=my-rg"
terraform apply
```

## Secrets Handling

The OpenAI API key is **never** stored in Terraform state.
Store it in Key Vault manually:
```bash
az keyvault secret set --vault-name vulnpilot-kv --name openai-api-key --value "sk-..."
```
Then pass the secret ID as a variable:
```bash
terraform apply -var="openai_key_vault_secret_id=https://vulnpilot-kv.vault.azure.net/secrets/openai-api-key/..."
```

## Notes
- This module has been syntax-validated with `terraform validate` but **not tested in a live cloud**.
- The managed identity grants `AcrPull` only — least-privilege principle.
- `purge_protection_enabled = true` on Key Vault prevents accidental deletion.
