# APIM Deployment - Onboarding Guide

Automated API deployment to Azure APIM using GitHub workflows.

## Quick Start

1. Create OpenAPI spec: `apis/your-api.yml`
2. Create extractor config: `configuration.extractor.your-project.yml`
3. (Optional) Add policies and products
4. Run workflow or push to main/develop

**Result:** API deployed to non-prod → PR created → merge for prod deployment.

## Prerequisites

**GitHub Environment Secrets** (`api-ops-non-prod`):
- `AZURE_CLIENT_ID`, `AZURE_CLIENT_SECRET`, `AZURE_TENANT_ID`, `AZURE_SUBSCRIPTION_ID`
- `AZURE_RESOURCE_GROUP_NAME`, `API_MANAGEMENT_SERVICE_NAME`

Location: Settings → Environments → api-ops-non-prod → Environment secrets

## Required Files

**1. OpenAPI Spec (Required):** `apis/your-api.yml`
```yaml
openapi: 3.0.0
info:
  title: Customer API
  version: 1.0.0
paths:
  /customers:
    get:
      responses:
        '200':
          description: OK
```

**2. Extractor Config (Required):** `configuration.extractor.your-project.yml`
```yaml
# Basic - extract specific APIs
apiNames:
  - customer-api
  - order-api
```

**Advanced Extractor Options:**
```yaml

apiNames:
  - apiName1
  - apiName2

backendNames:
  - backendName1

diagnosticNames:
  - diagnosticName1

loggerNames:
  - loggerName1

namedValueNames:
  - namedValueName1

productNames:
  - productName1

subscriptionNames:
  - subscriptionName1

tagNames:
  - tagName1

policyFragmentNames:
  - policyFragment1
```

**Tip:** Use workspaces in APIM to organize and limit extraction scope whenever possible.

**3. Policy (Optional):** `policies/your-api-policy.xml`
```xml
<policies>
  <inbound>
    <base />
    <rate-limit calls="100" renewal-period="60" />
  </inbound>
  <backend><base /></backend>
  <outbound><base /></outbound>
  <on-error><base /></on-error>
</policies>
```

**4. Product (Optional):** Must exist in APIM (e.g., `starter`, `unlimited`). Workflow links only, doesn't create.

## Deployment Options

**Manual:** Actions → APIM Full Deployment → Fill inputs (PROJECT_NAME, API_NAME, OPENAPI_FILE_PATH, etc.)

**Automatic:** Push to main/develop triggers when changes in:
- `apis/**/*.{yml,yaml,json}`
- `policies/**/*.xml`
- `configuration.extractor.*.yml`

---

## 🔄 Deployment Flow

Here's what happens when you run the workflow:

```
1. Push OpenAPI ──────────┐
   to APIM (non-prod)     │
                          │
2. Link Policies ─────────┤
   (optional)             ├──> All steps run
                          │    in parallel or
3. Link Products ─────────┤    sequence as needed
   (optional)             │
                          │
4. Extract Configuration ─┘
   from APIM
   
5. Create Pull Request ────┐
   with extracted config   │
                           │
6. Review & Approve PR ────┤──> Manual approval
                           │    step
7. Merge PR ───────────────┘

8. Auto-deploy to ─────────┐
   non-prod                │──> Triggered by
                           │    merge to main
9. Auto-deploy to ─────────┘
   prod (with approval)
```

---

## 🧩 Workflow Components

### Main Orchestration Workflow

**File:** `.github/workflows/apim-full-deployment.yml`

**Purpose:** Coordinates the entire API deployment lifecycle from push to extraction.

**What it does:**
- Orchestrates all deployment steps
- Calls individual workflows in sequence
- Creates PR with extracted configuration
- Provides visibility into deployment status

**When to use:** Full API deployments including policies and products.

---

### Component Workflows (Reusable)

**`apim-push-openapi.yml`** - Upload/update API spec to APIM (idempotent)

**`apim-link-policy.yml`** - Apply policies with change detection (API/operation/all-operations scope)

**`apim-link-product.yml`** - Link API to existing products (skips if already linked)

**`apim-run-extractor.yml`** - Extract APIM config to Git

**`apim-run-publisher.yml`** - Publish to non-prod & prod (with approval)

## Extracted Artifact Structure

After extraction, the `apimartifacts/` folder contains:

| Type | Path |
|------|------|
| APIM global policy | `./policy.xml` |
| Product info | `./products/product_name/productInformation.json` |
| Product policy | `./products/product_name/policy.xml` |
| Product groups | `./products/product_name/groups.json` (associates with existing groups) |
| Gateway info | `./gateways/gateway_name/gatewayInformation.json` |
| Auth server | `./authorizationServers/auth_server_name/authorizationServerInformation.json` |
| Diagnostics | `./diagnostics/diagnostic_name/diagnosticInformation.json` |
| Loggers | `./loggers/logger_name/loggerInformation.json` |
| API info | `./apis/api_name/Original/1/apiInformation.json` |
| API spec | `./apis/api_name/Original/1/specification.yaml` |
| OpenAPI spec | `./apis/api_name/specification.{yaml\|json}` |
| API policy | `./apis/api_name/policy.xml` |
| Operation policy | `./apis/api_name/operations/operation_name/policy.xml` |
| Tags | `./tags/tag_name` |
| Backends | `./backends/backend_name` |
| **Versioned APIs** | `./apis/api_name/Original` (v1) + version folders |
| **Revisioned APIs** | `./apis/api_name/Original[revision_number]/` |

**Note:** Groups are not created by extractor - only associated with existing ones created via IaC (ARM/Bicep/Terraform).

## Reusable Workflow Example
```yaml
jobs:
  deploy-api:
    uses: ./.github/workflows/apim-push-openapi.yml
    with:
      API_NAME: "my-api"
      OPENAPI_FILE_PATH: "apis/my-api.yml"
    secrets: inherit
```

## Common Scenarios

**New API:** Create `apis/my-api.yml` + `configuration.extractor.my-team.yml` → push or run workflow

**Update API:** Edit `apis/my-api.yml` → push (auto-triggers)

**Update Policy:** Edit `policies/my-policy.xml` → push or run `apim-link-policy`

**Extract APIM:** Actions → APIM Extract → select config → creates PR

## Troubleshooting

| Issue | Solution |
|-------|----------|
| API not found | Check API_NAME case-sensitivity |
| Invalid policy XML | Validate syntax, check `<policies>` root |
| Product not found | Verify exists in APIM, use product ID |
| OpenAPI not found | Check path relative to repo root |
| Config not found | Name: `configuration.extractor.PROJECT_NAME.yml` at root |

## Best Practices

- Use semantic versioning • Test policies locally • Review PRs before merge • Run extractions regularly • Leverage change detection

## Resources

[Azure APIM Docs](https://learn.microsoft.com/azure/api-management/) • [OpenAPI Spec](https://swagger.io/specification/) • [APIops Toolkit](https://github.com/Azure/apiops)