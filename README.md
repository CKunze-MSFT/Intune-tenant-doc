# Intune Tenant Configuration Exporter

A PowerShell script that connects to any Intune tenant via Microsoft Graph and generates a complete configuration inventory as Markdown files — one per platform plus a combined full-tenant document.

## Prerequisites

- **PowerShell 7+** (recommended) or Windows PowerShell 5.1
- **Microsoft.Graph PowerShell module:**
  ```powershell
  Install-Module Microsoft.Graph -Scope CurrentUser
  ```

## Quick Start

```powershell
# Basic export (interactive browser login)
.\Export-IntuneTenantDoc.ps1

# Export a specific tenant
.\Export-IntuneTenantDoc.ps1 -TenantId "contoso.onmicrosoft.com"

# Custom output directory
.\Export-IntuneTenantDoc.ps1 -OutputPath ./contoso-export
```

## Output

Creates a folder (default: `IntuneExport-YYYY-MM-DD/`) containing:

| File | Contents |
|------|----------|
| `Windows.md` | Windows device configs, compliance, apps, Autopilot, admin templates, update rings, scripts, remediations, driver updates, custom ADMX |
| `macOS.md` | macOS device configs, compliance, apps, shell scripts, ADE/DEP enrollment |
| `iOS.md` | iOS/iPadOS device configs, compliance, MAM, VPP apps, ADE enrollment |
| `Android.md` | Android device configs, compliance, MAM, managed Google Play, device owner enrollment |
| `Cross-platform.md` | Conditional Access, RBAC, scope tags, device categories, filters, APNs cert, VPP tokens, policy sets, branding, T&C, MTD, notifications, cleanup |
| `Full-Tenant-Documentation.md` | **Combined document** with all platforms, table of contents, and complete inventory |
| `Unclassified.md` | Items that couldn't be auto-classified (review and re-categorize) |
| `_errors.md` | Any sections that failed (permissions, licensing, API errors) |

## What It Documents

| Category | API Source | Notes |
|----------|-----------|-------|
| Device Configuration Profiles | v1.0 | Template-based legacy profiles with all setting values |
| Settings Catalog Policies | beta | Modern policy engine with all configured settings |
| Administrative Templates | beta | GPO-style Edge/Office/OneDrive policies with full setting values |
| Compliance Policies | v1.0 | Per-platform compliance rules |
| Custom Compliance Scripts | beta | Detection scripts for custom compliance |
| App Protection Policies (MAM) | v1.0 | iOS, Android, Windows WIP |
| App Configuration Policies | beta | Managed device + managed app configs |
| Applications | v1.0 | All app types with install intents and assignments |
| Endpoint Security / Baselines | beta | Security baselines, AV, firewall, EDR, ASR |
| Scripts | beta | PowerShell (Windows), shell (macOS) with full content and analysis |
| Proactive Remediations | beta | Device health scripts (custom only) |
| Enrollment Configuration | v1.0 + beta | Restrictions, ESP, Autopilot, ADE/DEP, Android Enterprise |
| Android Device Owner Enrollment | beta | Dedicated/fully managed enrollment profiles |
| Update Policies | beta | Feature updates, quality updates, update rings |
| Driver Update Profiles | beta | Windows driver update management |
| Conditional Access | v1.0 | All CA policies with conditions and controls |
| Assignment Filters | beta | Platform-specific filters with rules |
| Scope Tags | beta | Custom and built-in scope tags |
| RBAC Roles | v1.0 | Role definitions and assignment counts |
| Device Categories | v1.0 | Tenant-defined device categories |
| Apple Push Certificate | v1.0 | APNs certificate status and expiration |
| VPP / ABM Tokens | beta | Apple Volume Purchase Program tokens |
| Policy Sets | beta | Bundled policy deployments |
| Custom ADMX Imports | beta | Uploaded ADMX definition files |
| Intune Branding | beta | Company Portal branding profiles |
| Mobile Threat Defense | beta | MTD connector status |
| Device Management Partners | beta | Third-party management integrations |
| Terms and Conditions | v1.0 | Enrollment T&C with assignments |
| Notification Templates | beta | Notification message templates with localization |
| Device Cleanup Settings | beta | Automatic device cleanup rules |

## Required Permissions (Read-Only)

The script requests these Microsoft Graph scopes (all read-only):

- `DeviceManagementConfiguration.Read.All`
- `DeviceManagementApps.Read.All`
- `DeviceManagementManagedDevices.Read.All`
- `DeviceManagementServiceConfig.Read.All`
- `DeviceManagementRBAC.Read.All`
- `Policy.Read.All`
- `Directory.Read.All`
- `Group.Read.All`

## Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `-OutputPath` | string | `./IntuneExport-<date>` | Directory for output files |
| `-TenantId` | string | (interactive) | Tenant ID or domain to connect to |

Setting values and script content are always exported for complete documentation.

## Error Handling

- Each section exports independently — one failure doesn't stop the rest
- Permission denials (403) and unlicensed features (404) are logged and skipped
- Throttling (429) triggers automatic retry with exponential backoff
- All errors are recorded in `_errors.md`

## Platform Classification

Items are classified by explicit metadata, never by display name:
- `@odata.type` for legacy profiles, compliance, and apps
- `platforms` property for Settings Catalog
- `platformType` for security baselines
- `platform` for assignment filters
- Ambiguous items go to Cross-platform or Unclassified

## Security Notes

- All API calls are **read-only** — the script makes no changes to the tenant
- Script content is always exported — review output before sharing if scripts may contain secrets
- Group names are resolved for readability but no group membership data is exported
