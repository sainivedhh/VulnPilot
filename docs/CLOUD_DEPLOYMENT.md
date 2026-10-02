# Cloud Deployment Guide

## Architecture

VulnPilot is deployed to **Azure Container Apps** — a fully managed serverless
container platform that handles autoscaling, HTTPS termination, and log aggregation.

## Shared Responsibility Model

| Layer | Microsoft Responsibility | VulnPilot Responsibility |
|-------|------------------------|------------------------|
| Physical infrastructure | ✅ | — |
| Network / hypervisor | ✅ | — |
| Container runtime | ✅ (Container Apps) | — |
| OS patching (host) | ✅ | — |
| Container image | — | ✅ Pinned base, non-root user |
| Application code | — | ✅ Secure coding, type checking |
| Secret management | ✅ (Key Vault) | ✅ Reference secrets; never inline |
| Identity / access | ✅ (Entra ID) | ✅ Managed identity; no static creds |
| Logging | ✅ (Log Analytics) | ✅ Application-level logs |

## Identity and Secrets

All secrets are stored in **Azure Key Vault** and referenced via the
**User-Assigned Managed Identity** — no static credentials anywhere:

```
Container App → Managed Identity → Key Vault Secret → OPENAI_API_KEY env var
```

The OpenAI API key is:
1. Stored in Key Vault by a human operator (`az keyvault secret set ...`)
2. Referenced in Terraform by `key_vault_secret_id` — the **value** is never in state
3. Injected into the container as an environment variable at runtime
4. Never logged or returned in API responses

## Deployment Steps

```bash
# 1. Authenticate
az login
az account set --subscription <YOUR_SUBSCRIPTION_ID>

# 2. Store the LLM API key
az keyvault create --name vulnpilot-kv --resource-group vulnpilot-rg --location eastus
az keyvault secret set --vault-name vulnpilot-kv --name openai-api-key --value "sk-..."

# 3. Deploy infrastructure
cd infra/
terraform init
terraform plan
terraform apply

# 4. Push image
az acr login --name vulnpilotacr
docker build -t vulnpilotacr.azurecr.io/vulnpilot:latest .
docker push vulnpilotacr.azurecr.io/vulnpilot:latest
```

## Important Limitations

> **Not tested in a live Azure subscription.**
> The Terraform configuration has been validated with `terraform validate` but
> has not been applied to a real cloud account. Treat it as a reference implementation.
