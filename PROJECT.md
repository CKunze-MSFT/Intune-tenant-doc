# Intune Tenant Documentation Exporter — Project Overview

## Problem Statement

IT administrators managing Microsoft Intune tenants lack a simple way to generate comprehensive, human-readable documentation of their entire tenant configuration. Manually documenting device profiles, compliance policies, apps, scripts, and enrollment settings across Windows, macOS, iOS, and Android is time-consuming, error-prone, and quickly becomes outdated.

## Goal

Users will be able to:

- Generate a complete inventory of all Intune tenant configurations in minutes
- Produce Markdown documentation organized by platform (Windows, macOS, iOS, Android, Cross-platform)
- Create a combined full-tenant document with table of contents for audits, migrations, or onboarding
- Identify assignment targets (groups, filters) for every policy and app

## Primary Users

| User Type | Use Case |
|-----------|----------|
| **IT Administrators** | Document and audit their Intune tenant configurations |
| **MSPs / Consultants** | Generate client environment documentation for handoffs or reviews |
| **Security / Compliance Teams** | Audit configurations against security baselines and policies |
| **Migration Engineers** | Plan tenant-to-tenant migrations with complete configuration inventory |

## MVP Scope

### Input

- PowerShell command line with optional `-TenantId` and `-OutputPath` parameters
- Interactive browser-based authentication to Microsoft Graph

### Actions

- Connect to any Intune tenant via Microsoft Graph
- Collect 30+ configuration categories:
  - Device configuration profiles (legacy + Settings Catalog + Admin Templates)
  - Compliance policies and custom compliance scripts
  - App protection (MAM), app configuration, and managed apps
  - Endpoint security baselines
  - Scripts (PowerShell, shell) and proactive remediations
  - Enrollment configurations (Autopilot, ADE/DEP, Android Enterprise)
  - Update policies (feature, quality, driver)
  - Conditional Access policies
  - Assignment filters, scope tags, RBAC roles
  - Apple Push certificate, VPP tokens, policy sets
  - Branding, terms and conditions, notification templates
- Classify items by platform automatically using metadata
- Resolve group names for human-readable assignment documentation

### Output

| File | Description |
|------|-------------|
| `Windows.md` | All Windows-specific configurations |
| `macOS.md` | All macOS-specific configurations |
| `iOS.md` | All iOS/iPadOS-specific configurations |
| `Android.md` | All Android-specific configurations |
| `Cross-platform.md` | Tenant-wide settings (CA, RBAC, filters, etc.) |
| `Full-Tenant-Documentation.md` | Combined document with table of contents |
| `_warnings.md` | Any sections skipped due to permissions or licensing |

## Out of Scope (MVP)

| Capability | Reason |
|------------|--------|
| Write operations | Script is intentionally read-only for safety |
| Device inventory / compliance status | Documents configuration, not device state |
| Historical change tracking | Point-in-time snapshot only |
| Automated scheduling | Manual execution required |
| Full Entra ID configuration | Limited to Conditional Access; no full Entra export |
| HTML / PDF export | Markdown output only |
| Multi-tenant batch export | Single tenant per execution |
| Diff between exports | Manual comparison required |

## Success Metrics

| Metric | Target |
|--------|--------|
| Complete export without manual intervention | 100% of accessible sections |
| Tenant modifications | Zero (read-only) |
| Execution time | < 5 minutes for typical tenants |
| Sections skipped (with Global Reader role) | < 10% |
| Documentation usable for audits/migrations | Yes |

## Tech Considerations

### Integration

- **Microsoft Graph API** — v1.0 and beta endpoints for Intune and Azure AD
- **Microsoft.Graph PowerShell SDK** — handles authentication and token management
- **OAuth 2.0** — interactive browser-based flow with delegated permissions

### AI Layer

- **Current scope:** None
- **Future opportunities:**
  - AI-generated summaries of script content
  - Policy recommendations based on best practices
  - Configuration drift detection between exports

### Security

| Aspect | Implementation |
|--------|----------------|
| API Access | Read-only — all scopes are `.Read.All` |
| Authentication | Interactive browser login (delegated permissions) |
| Authorization | Requires Azure AD roles with Intune read access (e.g., Global Reader) |
| Credential Storage | None — session disconnects on completion |
| Sensitive Data | Script content is exported; users should review before sharing |
| Tenant Impact | Zero modifications possible |

### Telemetry

| Type | Implementation |
|------|----------------|
| External telemetry | None — script runs locally |
| Console output | Real-time progress and warnings |
| Error logging | `_warnings.md` captures permission/API errors |
| Audit trail | None beyond local file output |

## Required Permissions

All permissions are **read-only** and may require admin consent:

| Scope | Purpose |
|-------|---------|
| `DeviceManagementConfiguration.Read.All` | Device configs, Settings Catalog, compliance, admin templates |
| `DeviceManagementApps.Read.All` | Apps, MAM policies, app configurations |
| `DeviceManagementManagedDevices.Read.All` | Scripts, remediations, enrollment profiles |
| `DeviceManagementServiceConfig.Read.All` | Enrollment settings, APNs, VPP tokens |
| `DeviceManagementRBAC.Read.All` | RBAC roles, scope tags |
| `Policy.Read.All` | Conditional Access policies |
| `Directory.Read.All` | Organization info, group resolution |
| `Group.Read.All` | Resolve group names for assignments |

## Demo URL and/or Repo URLs

| Type | URL |
|------|-----|
| **Published Demo URL** | N/A (PowerShell script, not a web app) |
| **Published GitHub URL** | *Add your repo URL here* |
