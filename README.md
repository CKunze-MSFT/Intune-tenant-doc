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

# Export and embed full script content in the Markdown files
.\Export-IntuneTenantDoc.ps1 -EmbedScripts

# Export a specific tenant
.\Export-IntuneTenantDoc.ps1 -TenantId "contoso.onmicrosoft.com"

# Custom output directory
.\Export-IntuneTenantDoc.ps1 -OutputPath ./contoso-export
```

## Step-by-Step Usage

1. **Install the Microsoft Graph module** (if not already installed):

   ```powershell
   Install-Module Microsoft.Graph -Scope CurrentUser
   ```

2. **Navigate to the script directory**:

   ```powershell
   cd /path/to/Intune-tenant-doc
   ```

3. **Run the script**:

   ```powershell
   .\Export-IntuneTenantDoc.ps1
   ```

   To include full script bodies and generated script analysis in the Markdown output:

   ```powershell
   .\Export-IntuneTenantDoc.ps1 -EmbedScripts
   ```

4. **Sign in** when the browser window opens — use an account with appropriate permissions (see [Account Requirements](#account-requirements))

5. **Wait for completion** — the script will display progress as it collects each configuration category

6. **Review the output** — check the generated folder (e.g., `IntuneExport-2026-04-23/`) for your Markdown documentation

## Output

Creates a folder (default: `IntuneExport-YYYY-MM-DD/`) containing:

| File | Contents |
| ------ | ---------- |
| `Windows.md` | Windows device configs, compliance, apps, Autopilot, admin templates, update rings, scripts, remediations, driver updates, custom ADMX |
| `macOS.md` | macOS device configs, compliance, apps, shell scripts, ADE/DEP enrollment |
| `iOS.md` | iOS/iPadOS device configs, compliance, MAM, VPP apps, ADE enrollment |
| `Android.md` | Android device configs, compliance, MAM, managed Google Play, device owner enrollment |
| `Cross-platform.md` | Conditional Access, RBAC, scope tags, device categories, filters, APNs cert, VPP tokens, policy sets, branding, T&C, MTD, notifications, cleanup |
| `Full-Tenant-Documentation.md` | **Combined document** with all platforms, table of contents, and complete inventory |
| `Unclassified.md` | Items that couldn't be auto-classified (review and re-categorize) |
| `_warnings.md` | Any sections that were skipped (permissions, licensing, API errors) |

## What It Documents

| Category | API Source | Notes |
| ---------- | ----------- | ------- |
| Device Configuration Profiles | v1.0 | Template-based legacy profiles with all setting values |
| Settings Catalog Policies | beta | Modern policy engine with all configured settings |
| Administrative Templates | beta | GPO-style Edge/Office/OneDrive policies with full setting values |
| Compliance Policies | v1.0 | Per-platform compliance rules |
| Custom Compliance Scripts | beta | Detection scripts for custom compliance |
| App Protection Policies (MAM) | v1.0 | iOS, Android, Windows WIP |
| App Configuration Policies | beta | Managed device + managed app configs |
| Applications | v1.0 | All app types with install intents and assignments |
| Endpoint Security / Baselines | beta | Security baselines, AV, firewall, EDR, ASR |
| Scripts | beta | PowerShell (Windows), shell (macOS), and macOS PKG app pre/post install scripts; full content and analysis when `-EmbedScripts` is used |
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
| ----------- | ------ | --------- | ------------- |
| `-OutputPath` | string | `./IntuneExport-<date>` | Directory for output files |
| `-TenantId` | string | (interactive) | Tenant ID or domain to connect to |
| `-EmbedScripts` | switch | Off | Embed full PowerShell and shell script content in the Markdown output |

Setting values are always exported. Script bodies and generated script analysis are embedded only when `-EmbedScripts` is used.

## Error Handling

- Each section exports independently — one failure doesn't stop the rest
- Permission denials (403) and unlicensed features (404) are logged and skipped
- Throttling (429) triggers automatic retry with exponential backoff
- All warnings are recorded in `_warnings.md`

## Platform Classification

Items are classified by explicit metadata, never by display name:

- `@odata.type` for legacy profiles, compliance, and apps
- `platforms` property for Settings Catalog
- `platformType` for security baselines
- `platform` for assignment filters
- Ambiguous items go to Cross-platform or Unclassified

## Security Notes

- All API calls are **read-only** — the script makes no changes to the tenant
- If you use `-EmbedScripts`, review output before sharing because embedded scripts may contain secrets
- Group names are resolved for readability but no group membership data is exported

## Authentication Details

The script uses **interactive browser-based authentication** via Microsoft Graph. When you run the script:

1. A browser window opens for sign-in
2. Sign in with an account that has the required permissions (see below)
3. Consent to the requested Graph scopes if prompted (one-time per tenant)
4. The script automatically disconnects when complete

### Account Requirements

You need to sign in with an account that has at least **read access** to Intune and Azure AD. Typically:

| Role | Access Level |
| ------ | -------------- |
| **Global Reader** | Full read-only access to all settings |
| **Intune Administrator** | Full Intune access |
| **Security Reader** | Read Conditional Access and security settings |
| **Help Desk Operator** | Limited read access (some sections may be skipped) |

For complete documentation, use **Global Reader** or a custom role with all required permissions.

### Consent Requirements

The Graph scopes requested are all **read-only** and may require admin consent depending on your tenant settings:

| Scope | Why Needed |
| ------- | ----------- |
| `DeviceManagementConfiguration.Read.All` | Device configs, Settings Catalog, compliance, admin templates |
| `DeviceManagementApps.Read.All` | Apps, MAM policies, app configurations |
| `DeviceManagementManagedDevices.Read.All` | Scripts, remediations, enrollment profiles |
| `DeviceManagementServiceConfig.Read.All` | Enrollment settings, APNs, VPP tokens |
| `DeviceManagementRBAC.Read.All` | RBAC roles, scope tags |
| `Policy.Read.All` | Conditional Access policies |
| `Directory.Read.All` | Organization info, group resolution |
| `Group.Read.All` | Resolve group names for assignments |

If you see "Permission denied" warnings, your account lacks access to those specific sections—other sections will still export.
