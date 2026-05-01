<#
.SYNOPSIS
    Exports a full Intune tenant configuration to Markdown files, one per platform,
    plus a combined full-tenant document.

.DESCRIPTION
    Connects to a customer's Intune tenant via Microsoft Graph (interactive browser login)
    and documents every configured item — device configuration profiles (legacy + Settings
    Catalog + Administrative Templates), compliance policies, app protection, app config,
    managed apps, endpoint security baselines, scripts and remediations, enrollment config
    (Autopilot, ADE/DEP, Android Enterprise), update policies (feature, quality, driver),
    Conditional Access, assignment filters, scope tags, RBAC roles, device categories, Apple
    Push certificate, VPP/ABM tokens, custom compliance scripts, policy sets, custom ADMX
    imports, Intune branding, notification templates, terms and conditions, MTD connectors,
    device management partners, and device cleanup settings.

    Output is organized into per-platform Markdown files:
      Windows.md, macOS.md, iOS.md, Android.md, Cross-platform.md
    Plus a combined Full-Tenant-Documentation.md with all content and a table of contents.

    Setting values are always exported for completeness. Script content can be
    embedded in the Markdown output with -EmbedScripts.

.PARAMETER OutputPath
    Directory where MD files will be written. Defaults to ./IntuneExport-<date>.

.PARAMETER TenantId
    Optional tenant ID to connect to. If omitted, the login prompt determines the tenant.

.PARAMETER EmbedScripts
    Includes full script bodies and script analysis in the Markdown output.

.EXAMPLE
    .\Export-IntuneTenantDoc.ps1
    .\Export-IntuneTenantDoc.ps1 -TenantId "contoso.onmicrosoft.com" -OutputPath ./contoso-export
    .\Export-IntuneTenantDoc.ps1 -EmbedScripts
#>

[CmdletBinding()]
param(
    [string]$OutputPath,
    [string]$TenantId,
    [switch]$EmbedScripts
)

$ErrorActionPreference = "Stop"

# ---------------------------------------------------------------------------- #
# Constants
# ---------------------------------------------------------------------------- #
$GRAPH_SCOPES = @(
    "DeviceManagementConfiguration.Read.All",
    "DeviceManagementApps.Read.All",
    "DeviceManagementManagedDevices.Read.All",
    "DeviceManagementServiceConfig.Read.All",
    "DeviceManagementRBAC.Read.All",
    "Policy.Read.All",
    "Directory.Read.All",
    "Group.Read.All"
)

$PLATFORM_MAP = @{
    "Windows"       = @()
    "macOS"         = @()
    "iOS"           = @()
    "Android"       = @()
    "CrossPlatform" = @()
    "Unclassified"  = @()
}

# Cache for group name resolution
$script:GroupCache = @{}
$script:OrgName = ""
$script:TenantIdResolved = ""
$script:ExportErrors = @()

# ---------------------------------------------------------------------------- #
# Helper Functions
# ---------------------------------------------------------------------------- #

function Write-Status {
    param([string]$Message, [string]$Level = "Info")
    $color = switch ($Level) {
        "Info"    { "Cyan" }
        "Success" { "Green" }
        "Warning" { "Yellow" }
        "Error"   { "Red" }
        default   { "White" }
    }
    Write-Host "[$Level] $Message" -ForegroundColor $color
}

function Invoke-GraphRequestSafe {
    <#
    .SYNOPSIS
        Wrapper for Graph API calls with pagination, retry, and error handling.
    #>
    param(
        [string]$Uri,
        [string]$Section = "Unknown",
        [int]$MaxRetries = 3
    )

    $allResults = @()
    $currentUri = $Uri
    $retryCount = 0

    while ($currentUri) {
        try {
            $response = Invoke-MgGraphRequest -Method GET -Uri $currentUri -ErrorAction Stop

            if ($response.value) {
                $allResults += $response.value
            }
            elseif ($response -is [System.Collections.IDictionary] -and -not $response.ContainsKey("value")) {
                # Single object response
                return $response
            }

            $currentUri = $response.'@odata.nextLink'
            $retryCount = 0
        }
        catch {
            $statusCode = $null
            if ($_.Exception.Message -match "(\d{3})") {
                $statusCode = [int]$Matches[1]
            }

            # Also detect Forbidden/Unauthorized from exception message text
            $isForbidden = $_.Exception.Message -match 'Forbidden|Unauthorized'

            if ($statusCode -eq 429 -and $retryCount -lt $MaxRetries) {
                $retryCount++
                $waitSec = [math]::Pow(2, $retryCount) + (Get-Random -Minimum 1 -Maximum 5)
                Write-Status "Throttled on $Section — retrying in ${waitSec}s (attempt $retryCount/$MaxRetries)" "Warning"
                Start-Sleep -Seconds $waitSec
                continue
            }
            elseif ($statusCode -eq 403 -or $statusCode -eq 401 -or $isForbidden) {
                $msg = "[$Section] Permission denied. Skipping — ensure required Graph scopes are consented."
                Write-Status $msg "Warning"
                $script:ExportErrors += $msg
                return $null
            }
            elseif ($statusCode -eq 404) {
                $msg = "[$Section] Not found or not licensed (HTTP 404). Skipping."
                Write-Status $msg "Warning"
                $script:ExportErrors += $msg
                return $null
            }
            else {
                $msg = "[$Section] Error: $($_.Exception.Message)"
                Write-Status $msg "Error"
                $script:ExportErrors += $msg
                return $null
            }
        }
    }

    return $allResults
}

function Resolve-GroupName {
    param([string]$GroupId)
    if (-not $GroupId -or $GroupId -eq "00000000-0000-0000-0000-000000000000") { return "All Users/Devices" }
    if ($script:GroupCache.ContainsKey($GroupId)) { return $script:GroupCache[$GroupId] }

    try {
        $group = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/groups/$GroupId" -ErrorAction Stop
        $name = "$($group.displayName) ($GroupId)"
        $script:GroupCache[$GroupId] = $name
        return $name
    }
    catch {
        $script:GroupCache[$GroupId] = $GroupId
        return $GroupId
    }
}

function Format-Assignments {
    <#
    .SYNOPSIS
        Returns a Markdown table of all assignments for an object.
    #>
    param($Assignments)
    if (-not $Assignments -or $Assignments.Count -eq 0) { return "None" }

    $rows = @()
    foreach ($a in $Assignments) {
        $target = $a.target
        $type = $target.'@odata.type'
        $groupId = $target.groupId
        $intent = if ($a.intent) { $a.intent } else { "-" }

        # Determine action (include/exclude/all)
        $action = ""
        $groupName = ""
        switch ($type) {
            "#microsoft.graph.allDevicesAssignmentTarget"       { $action = "Include"; $groupName = "**All Devices**" }
            "#microsoft.graph.allLicensedUsersAssignmentTarget" { $action = "Include"; $groupName = "**All Users**" }
            "#microsoft.graph.groupAssignmentTarget"            { $action = "Include"; $groupName = Resolve-GroupName $groupId }
            "#microsoft.graph.exclusionGroupAssignmentTarget"   { $action = "Exclude"; $groupName = Resolve-GroupName $groupId }
            default {
                $action = ($type -replace '#microsoft.graph.', '' -replace 'AssignmentTarget', '')
                $groupName = if ($groupId) { Resolve-GroupName $groupId } else { "-" }
            }
        }

        # Filter info
        $filterInfo = "-"
        if ($target.deviceAndAppManagementAssignmentFilterId -and
            $target.deviceAndAppManagementAssignmentFilterId -ne "00000000-0000-0000-0000-000000000000") {
            $filterId = $target.deviceAndAppManagementAssignmentFilterId
            $filterMode = $target.deviceAndAppManagementAssignmentFilterType
            $filterInfo = "$filterMode ($filterId)"
        }

        $rows += @{
            Action = $action
            Group  = ($groupName -replace '\|', '\|')
            Intent = $intent
            Filter = $filterInfo
        }
    }

    # Build table
    $sb = [System.Text.StringBuilder]::new()
    [void]$sb.AppendLine("")
    [void]$sb.AppendLine("| Action | Group / Target | Intent | Filter |")
    [void]$sb.AppendLine("|--------|---------------|--------|--------|")
    foreach ($r in $rows) {
        [void]$sb.AppendLine("| $($r.Action) | $($r.Group) | $($r.Intent) | $($r.Filter) |")
    }

    return $sb.ToString()
}

function Format-AssignmentsSummary {
    <#
    .SYNOPSIS
        Returns a short one-line summary for the overview table.
    #>
    param($Assignments)
    if (-not $Assignments -or $Assignments.Count -eq 0) { return "None" }

    $includes = 0; $excludes = 0; $allTarget = $false
    foreach ($a in $Assignments) {
        $type = $a.target.'@odata.type'
        switch ($type) {
            "#microsoft.graph.allDevicesAssignmentTarget"       { $allTarget = $true }
            "#microsoft.graph.allLicensedUsersAssignmentTarget" { $allTarget = $true }
            "#microsoft.graph.groupAssignmentTarget"            { $includes++ }
            "#microsoft.graph.exclusionGroupAssignmentTarget"   { $excludes++ }
        }
    }

    $parts = @()
    if ($allTarget) { $parts += "All Users/Devices" }
    if ($includes -gt 0) { $parts += "$includes group(s)" }
    if ($excludes -gt 0) { $parts += "$excludes exclusion(s)" }
    return ($parts -join ", ")
}

function Get-PlatformFromODataType {
    param([string]$ODataType)

    if (-not $ODataType) { return "Unclassified" }
    $t = $ODataType.ToLower()

    if ($t -match "windows|win32|win10|windowsphone|edgeHomeButton|windowsDeliveryOptimization|sharedPC|windowsDefender|windowsKiosk|windowsWifi|windowsVpn|windowsUpdate|windowsHealthMonitoring") { return "Windows" }
    if ($t -match "macos|macOS|osx") { return "macOS" }
    if ($t -match "\bios\b|iphone|ipad|iosvpp|ioslobapp|iosstore|iosmanagedapp|iosgeneral|ioscustomconfiguration|ioscompliancepolicy|iosupdate") { return "iOS" }
    if ($t -match "android") { return "Android" }

    return "Unclassified"
}

function Get-PlatformFromSettingsCatalog {
    param($Policy)

    $platforms = $Policy.platforms
    if (-not $platforms) { return "Unclassified" }

    switch -Regex ($platforms.ToLower()) {
        "windows10"  { return "Windows" }
        "macos"      { return "macOS" }
        "ios"        { return "iOS" }
        "android"    { return "Android" }
        "linux"      { return "CrossPlatform" }
        default      { return "Unclassified" }
    }
}

function Get-PlatformFromAppType {
    param([string]$ODataType)

    if (-not $ODataType) { return "Unclassified" }
    $t = $ODataType.ToLower()

    if ($t -match "win32|windows|microsoftstore|officeSuite|windowsAppX|windowsMsi|windowsUniversalAppX") { return "Windows" }
    if ($t -match "macos|macOS|macOSDmg|macOSLob|macOSMicrosoftEdge|macOSMicrosoftDefender|macOSVpp|macOSOfficeSuite|macOSPkg") { return "macOS" }
    if ($t -match "\bios\b|iosVpp|iosStore|iosLob") { return "iOS" }
    if ($t -match "android|managedAndroid") { return "Android" }
    if ($t -match "webApp|managedApp") { return "CrossPlatform" }

    return "Unclassified"
}

function Add-ToPlatform {
    param(
        [string]$Platform,
        [string]$Category,
        [hashtable]$Item
    )
    $key = if ($Platform -in @("Windows","macOS","iOS","Android")) { $Platform } else { "CrossPlatform" }
    $script:PLATFORM_MAP[$key] += @{ Category = $Category; Data = $Item }
}

function Get-ScriptSummary {
    <#
    .SYNOPSIS
        Generates a high-level description of what a script does by analyzing its content.
    #>
    param(
        [string]$ScriptText,
        [string]$ScriptType = "PowerShell"
    )

    if (-not $ScriptText -or $ScriptText.Length -lt 10) { return "Empty or minimal script." }

    $lines = $ScriptText -split "`n" | ForEach-Object { $_.Trim() }
    $codeLines = $lines | Where-Object { $_ -and -not $_.StartsWith('#') -and -not $_.StartsWith('//') -and -not $_.StartsWith('<#') }
    $commentLines = $lines | Where-Object { $_ -and ($_.StartsWith('#') -or $_.StartsWith('//')) }

    $summary = @()
    $summary += "**Lines:** $($lines.Count) total ($($codeLines.Count) code, $($commentLines.Count) comments)"

    # Check for synopsis/description in comments
    if ($ScriptText -match '\.SYNOPSIS\s*\n\s*(.+)') { $summary += "**Synopsis:** $($Matches[1].Trim())" }
    elseif ($ScriptText -match '\.DESCRIPTION\s*\n\s*(.+)') { $summary += "**Description:** $($Matches[1].Trim())" }

    # Detect key patterns
    $patterns = @()
    if ($ScriptText -match 'Install-|choco |brew |apt |winget ') { $patterns += "Software installation" }
    if ($ScriptText -match 'Registry|reg add|HKLM|HKCU|New-ItemProperty|Set-ItemProperty') { $patterns += "Registry modification" }
    if ($ScriptText -match 'Set-ExecutionPolicy|Enable-|Disable-|firewall|defender') { $patterns += "Security configuration" }
    if ($ScriptText -match 'Copy-Item|Move-Item|Remove-Item|New-Item|mkdir|cp |mv |rm ') { $patterns += "File system operations" }
    if ($ScriptText -match 'Invoke-WebRequest|Invoke-RestMethod|curl|wget|Download') { $patterns += "Network/download operations" }
    if ($ScriptText -match 'Start-Service|Stop-Service|Restart-Service|systemctl|launchctl') { $patterns += "Service management" }
    if ($ScriptText -match 'Get-WmiObject|Get-CimInstance|WMI|CIM') { $patterns += "System information query" }
    if ($ScriptText -match 'Write-Output|Write-Host|echo|logging|log file') { $patterns += "Logging/output" }
    if ($ScriptText -match 'try\s*\{|catch\s*\{|trap\s*\{') { $patterns += "Error handling" }
    if ($ScriptText -match 'defaults write|defaults read|PlistBuddy|scutil|mdm|profiles') { $patterns += "macOS system configuration" }
    if ($ScriptText -match 'networksetup|wifi|dns|proxy') { $patterns += "Network configuration" }
    if ($ScriptText -match 'dscl|sysadminctl|security |keychain') { $patterns += "macOS security/user management" }
    if ($ScriptText -match 'Get-Process|Stop-Process|kill|taskkill') { $patterns += "Process management" }
    if ($ScriptText -match 'scheduled task|schtasks|cron|launchd') { $patterns += "Scheduled task management" }
    if ($ScriptText -match 'BitLocker|FileVault|encryption') { $patterns += "Disk encryption" }
    if ($ScriptText -match 'Update-|patch|Windows Update|softwareupdate') { $patterns += "Update/patching" }

    if ($patterns.Count -gt 0) {
        $summary += "**Purpose:** " + ($patterns -join ", ")
    }

    return ($summary -join "`n")
}

function Convert-GraphScriptContent {
    param([string]$ScriptContent)

    if (-not $ScriptContent) { return "" }

    try {
        return [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($ScriptContent))
    }
    catch {
        return $ScriptContent
    }
}

# ---------------------------------------------------------------------------- #
# Data Collection Functions
# ---------------------------------------------------------------------------- #

function Export-DeviceConfigurationProfiles {
    Write-Status "Collecting device configuration profiles..." "Info"

    # Legacy template-based profiles (v1.0)
    $configs = Invoke-GraphRequestSafe -Uri "https://graph.microsoft.com/v1.0/deviceManagement/deviceConfigurations" -Section "DeviceConfigurations"
    if ($configs) {
        foreach ($c in $configs) {
            $platform = Get-PlatformFromODataType $c.'@odata.type'
            $assignments = Invoke-GraphRequestSafe -Uri "https://graph.microsoft.com/v1.0/deviceManagement/deviceConfigurations/$($c.id)/assignments" -Section "DeviceConfig-Assignments"

            # Extract all configured settings from the profile object
            $settingsList = @()
            $skipKeys = @('id','displayName','description','version','createdDateTime','lastModifiedDateTime',
                          '@odata.type','roleScopeTagIds','supportsScopeTags','deviceManagementApplicabilityRuleOsEdition',
                          'deviceManagementApplicabilityRuleOsVersion','deviceManagementApplicabilityRuleDeviceMode')
            foreach ($key in $c.Keys) {
                if ($key -notin $skipKeys -and $null -ne $c[$key] -and $c[$key] -ne '' -and $c[$key] -ne $false -and $c[$key] -ne 0) {
                    $val = $c[$key]
                    if ($val -is [System.Collections.IEnumerable] -and $val -isnot [string]) {
                        $val = ($val | ConvertTo-Json -Depth 3 -Compress)
                    }
                    $settingsList += @{ Name = $key; Value = "$val" }
                }
            }

            Add-ToPlatform -Platform $platform -Category "Device Configuration Profiles" -Item @{
                Name         = $c.displayName
                Type         = ($c.'@odata.type' -replace '#microsoft.graph.', '')
                Description  = $c.description
                Created      = $c.createdDateTime
                Modified     = $c.lastModifiedDateTime
                Assignments  = $assignments
                ConfiguredSettings = $settingsList
                Id           = $c.id
            }
        }
    }

    # Settings Catalog policies (beta — not in v1.0)
    $settingsCatalog = Invoke-GraphRequestSafe -Uri "https://graph.microsoft.com/beta/deviceManagement/configurationPolicies" -Section "SettingsCatalog"
    if ($settingsCatalog) {
        foreach ($s in $settingsCatalog) {
            $platform = Get-PlatformFromSettingsCatalog $s
            $assignments = Invoke-GraphRequestSafe -Uri "https://graph.microsoft.com/beta/deviceManagement/configurationPolicies/$($s.id)/assignments" -Section "SettingsCatalog-Assignments"

            # Always fetch all settings for Settings Catalog policies
            $settings = Invoke-GraphRequestSafe -Uri "https://graph.microsoft.com/beta/deviceManagement/configurationPolicies/$($s.id)/settings" -Section "SettingsCatalog-Settings"
            $catalogSettings = @()
            if ($settings) {
                foreach ($setting in $settings) {
                    $instance = $setting.settingInstance
                    if ($instance) {
                        $defId = $instance.settingDefinitionId
                        $friendlyName = ($defId -split '_' | Select-Object -Last 1)
                        $valueData = ""
                        if ($instance.choiceSettingValue) {
                            $valueData = ($instance.choiceSettingValue.value -split '_' | Select-Object -Last 1)
                        }
                        elseif ($instance.simpleSettingValue) {
                            $valueData = "$($instance.simpleSettingValue.value)"
                        }
                        elseif ($instance.groupSettingCollectionValue) {
                            $valueData = "(Collection: $($instance.groupSettingCollectionValue.Count) items)"
                        }
                        elseif ($instance.simpleSettingCollectionValue) {
                            $valueData = ($instance.simpleSettingCollectionValue | ForEach-Object { $_.value }) -join ", "
                        }
                        else {
                            $valueData = "(configured)"
                        }
                        $catalogSettings += @{ Name = $friendlyName; Value = $valueData; DefinitionId = $defId }
                    }
                }
            }

            Add-ToPlatform -Platform $platform -Category "Settings Catalog Policies" -Item @{
                Name         = $s.name
                Type         = "Settings Catalog ($($s.technologies))"
                Description  = $s.description
                Created      = $s.createdDateTime
                Modified     = $s.lastModifiedDateTime
                Assignments  = $assignments
                CatalogSettings = $catalogSettings
                Id           = $s.id
            }
        }
    }
}

function Export-CompliancePolicies {
    Write-Status "Collecting compliance policies..." "Info"

    $policies = Invoke-GraphRequestSafe -Uri "https://graph.microsoft.com/v1.0/deviceManagement/deviceCompliancePolicies" -Section "CompliancePolicies"
    if ($policies) {
        foreach ($p in $policies) {
            $platform = Get-PlatformFromODataType $p.'@odata.type'
            $assignments = Invoke-GraphRequestSafe -Uri "https://graph.microsoft.com/v1.0/deviceManagement/deviceCompliancePolicies/$($p.id)/assignments" -Section "Compliance-Assignments"
            Add-ToPlatform -Platform $platform -Category "Compliance Policies" -Item @{
                Name         = $p.displayName
                Type         = ($p.'@odata.type' -replace '#microsoft.graph.', '')
                Description  = $p.description
                Created      = $p.createdDateTime
                Modified     = $p.lastModifiedDateTime
                Assignments  = $assignments
                Id           = $p.id
            }
        }
    }
}

function Export-AppProtectionPolicies {
    Write-Status "Collecting app protection policies (MAM)..." "Info"

    # iOS MAM
    $iosMam = Invoke-GraphRequestSafe -Uri "https://graph.microsoft.com/v1.0/deviceAppManagement/iosManagedAppProtections" -Section "iOS-MAM"
    if ($iosMam) {
        foreach ($p in $iosMam) {
            $assignments = Invoke-GraphRequestSafe -Uri "https://graph.microsoft.com/v1.0/deviceAppManagement/iosManagedAppProtections/$($p.id)/assignments" -Section "iOS-MAM-Assignments"
            Add-ToPlatform -Platform "iOS" -Category "App Protection Policies" -Item @{
                Name = $p.displayName; Type = "iOS MAM"; Description = $p.description
                Created = $p.createdDateTime; Modified = $p.lastModifiedDateTime
                Assignments = $assignments; Id = $p.id
            }
        }
    }

    # Android MAM
    $androidMam = Invoke-GraphRequestSafe -Uri "https://graph.microsoft.com/v1.0/deviceAppManagement/androidManagedAppProtections" -Section "Android-MAM"
    if ($androidMam) {
        foreach ($p in $androidMam) {
            $assignments = Invoke-GraphRequestSafe -Uri "https://graph.microsoft.com/v1.0/deviceAppManagement/androidManagedAppProtections/$($p.id)/assignments" -Section "Android-MAM-Assignments"
            Add-ToPlatform -Platform "Android" -Category "App Protection Policies" -Item @{
                Name = $p.displayName; Type = "Android MAM"; Description = $p.description
                Created = $p.createdDateTime; Modified = $p.lastModifiedDateTime
                Assignments = $assignments; Id = $p.id
            }
        }
    }

    # Windows MAM (WIP)
    $winMam = Invoke-GraphRequestSafe -Uri "https://graph.microsoft.com/v1.0/deviceAppManagement/windowsInformationProtectionPolicies" -Section "Windows-WIP"
    if ($winMam) {
        foreach ($p in $winMam) {
            $assignments = Invoke-GraphRequestSafe -Uri "https://graph.microsoft.com/v1.0/deviceAppManagement/windowsInformationProtectionPolicies/$($p.id)/assignments" -Section "Windows-WIP-Assignments"
            Add-ToPlatform -Platform "Windows" -Category "App Protection Policies" -Item @{
                Name = $p.displayName; Type = "Windows Information Protection"; Description = $p.description
                Created = $p.createdDateTime; Modified = $p.lastModifiedDateTime
                Assignments = $assignments; Id = $p.id
            }
        }
    }
}

function Export-AppConfigPolicies {
    Write-Status "Collecting app configuration policies..." "Info"

    $targeted = Invoke-GraphRequestSafe -Uri "https://graph.microsoft.com/beta/deviceAppManagement/mobileAppConfigurations" -Section "MobileAppConfigurations"

    if ($targeted) {
        foreach ($c in $targeted) {
            $platform = Get-PlatformFromODataType $c.'@odata.type'
            $assignments = Invoke-GraphRequestSafe -Uri "https://graph.microsoft.com/beta/deviceAppManagement/mobileAppConfigurations/$($c.id)/assignments" -Section "AppConfig-Assignments"
            Add-ToPlatform -Platform $platform -Category "App Configuration Policies" -Item @{
                Name = $c.displayName; Type = ($c.'@odata.type' -replace '#microsoft.graph.', '')
                Description = $c.description; Created = $c.createdDateTime
                Modified = $c.lastModifiedDateTime; Assignments = $assignments; Id = $c.id
            }
        }
    }
}

function Export-Apps {
    Write-Status "Collecting managed apps..." "Info"

    $apps = Invoke-GraphRequestSafe -Uri "https://graph.microsoft.com/v1.0/deviceAppManagement/mobileApps" -Section "MobileApps"
    if ($apps) {
        foreach ($app in $apps) {
            if ($app.isAssigned -eq $false -and -not $app.displayName) { continue }

            $platform = Get-PlatformFromAppType $app.'@odata.type'
            $assignments = Invoke-GraphRequestSafe -Uri "https://graph.microsoft.com/v1.0/deviceAppManagement/mobileApps/$($app.id)/assignments" -Section "App-Assignments"
            $extraProperties = $null
            $preInstallScriptContent = ""
            $preInstallScriptSummary = ""
            $postInstallScriptContent = ""
            $postInstallScriptSummary = ""

            # Parse install intent from assignments
            $installIntents = @()
            if ($assignments) {
                foreach ($a in $assignments) {
                    $intent = $a.intent
                    $targetType = $a.target.'@odata.type' -replace '#microsoft.graph.', ''
                    $groupId = $a.target.groupId
                    $groupName = if ($groupId) { Resolve-GroupName $groupId } elseif ($targetType -match "allDevices") { "All Devices" } elseif ($targetType -match "allLicensedUsers") { "All Users" } else { $targetType }
                    $installIntents += "$intent -> $groupName"
                }
            }

            if (($app.'@odata.type' -replace '#microsoft.graph.', '') -eq 'macOSPkgApp') {
                $detail = Invoke-GraphRequestSafe -Uri "https://graph.microsoft.com/beta/deviceAppManagement/mobileApps/$($app.id)" -Section "macOSPkgApp-Detail"
                if ($detail) {
                    $includedApps = @()
                    if ($detail.includedApps) {
                        foreach ($includedApp in $detail.includedApps) {
                            $includedApps += "$($includedApp.bundleId) ($($includedApp.bundleVersion))"
                        }
                    }

                    $minimumOs = @()
                    if ($detail.minimumSupportedOperatingSystem) {
                        foreach ($property in $detail.minimumSupportedOperatingSystem.PSObject.Properties) {
                            if ($property.Value -eq $true) {
                                $minimumOs += ($property.Name -replace '^v', '' -replace '_', '.')
                            }
                        }
                    }

                    if ($detail.preInstallScript -and $detail.preInstallScript.scriptContent) {
                        $preInstallScriptContent = Convert-GraphScriptContent -ScriptContent $detail.preInstallScript.scriptContent
                        if ($preInstallScriptContent) {
                            $preInstallScriptSummary = Get-ScriptSummary -ScriptText $preInstallScriptContent -ScriptType "Shell"
                        }
                    }

                    if ($detail.postInstallScript -and $detail.postInstallScript.scriptContent) {
                        $postInstallScriptContent = Convert-GraphScriptContent -ScriptContent $detail.postInstallScript.scriptContent
                        if ($postInstallScriptContent) {
                            $postInstallScriptSummary = Get-ScriptSummary -ScriptText $postInstallScriptContent -ScriptType "Shell"
                        }
                    }

                    $extraProperties = [ordered]@{
                        "Package File"               = $detail.fileName
                        "Bundle ID"                  = $detail.primaryBundleId
                        "Bundle Version"             = $detail.primaryBundleVersion
                        "Ignore Version Detection"   = $detail.ignoreVersionDetection
                        "Minimum Supported macOS"    = if ($minimumOs.Count -gt 0) { $minimumOs -join ', ' } else { $null }
                        "Included Apps"              = if ($includedApps.Count -gt 0) { $includedApps -join '; ' } else { $null }
                        "Has Pre-install Script"     = [bool]$preInstallScriptContent
                        "Has Post-install Script"    = [bool]$postInstallScriptContent
                    }
                }
            }

            Add-ToPlatform -Platform $platform -Category "Applications" -Item @{
                Name                     = $app.displayName
                Type                     = ($app.'@odata.type' -replace '#microsoft.graph.', '')
                Publisher                = $app.publisher
                Created                  = $app.createdDateTime
                Modified                 = $app.lastModifiedDateTime
                Assignments              = $assignments
                InstallIntents           = $installIntents
                PreInstallScriptContent  = $preInstallScriptContent
                PreInstallScriptSummary  = $preInstallScriptSummary
                PostInstallScriptContent = $postInstallScriptContent
                PostInstallScriptSummary = $postInstallScriptSummary
                ExtraProperties          = $extraProperties
                Id                       = $app.id
            }
        }
    }
}

function Export-EndpointSecurity {
    Write-Status "Collecting endpoint security policies..." "Info"

    # Intents (security baselines, endpoint security templates)
    $intents = Invoke-GraphRequestSafe -Uri "https://graph.microsoft.com/beta/deviceManagement/intents" -Section "SecurityIntents"
    if ($intents) {
        foreach ($intent in $intents) {
            $assignments = Invoke-GraphRequestSafe -Uri "https://graph.microsoft.com/beta/deviceManagement/intents/$($intent.id)/assignments" -Section "Intent-Assignments"
            $template = $null
            if ($intent.templateId) {
                $template = Invoke-GraphRequestSafe -Uri "https://graph.microsoft.com/beta/deviceManagement/templates/$($intent.templateId)" -Section "Intent-Template"
            }
            $platform = if ($template -and $template.platformType) {
                switch ($template.platformType.ToLower()) {
                    "windows10andlater" { "Windows" }
                    "macos"             { "macOS" }
                    "ios"               { "iOS" }
                    "android"           { "Android" }
                    default             { "CrossPlatform" }
                }
            } else { "Windows" }  # Most baselines are Windows

            Add-ToPlatform -Platform $platform -Category "Endpoint Security / Baselines" -Item @{
                Name        = $intent.displayName
                Type        = if ($template) { $template.displayName } else { "Security Baseline" }
                Description = $intent.description
                Created     = $intent.createdDateTime
                Modified    = $intent.lastModifiedDateTime
                Assignments = $assignments
                Id          = $intent.id
            }
        }
    }
}

function Export-Scripts {
    Write-Status "Collecting scripts and remediations..." "Info"

    # PowerShell scripts (Windows)
    $psScripts = Invoke-GraphRequestSafe -Uri "https://graph.microsoft.com/beta/deviceManagement/deviceManagementScripts" -Section "PowerShellScripts"
    if ($psScripts) {
        foreach ($s in $psScripts) {
            $assignments = Invoke-GraphRequestSafe -Uri "https://graph.microsoft.com/beta/deviceManagement/deviceManagementScripts/$($s.id)/assignments" -Section "PSScript-Assignments"

            # Always decode script content
            $content = ""
            $summary = ""
            if ($s.scriptContent) {
                try {
                    $content = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($s.scriptContent))
                    $summary = Get-ScriptSummary -ScriptText $content -ScriptType "PowerShell"
                }
                catch { $content = "(Could not decode script content)" }
            }

            Add-ToPlatform -Platform "Windows" -Category "Scripts" -Item @{
                Name = $s.displayName; Type = "PowerShell Script"
                Description = $s.description; Created = $s.createdDateTime
                Modified = $s.lastModifiedDateTime; Assignments = $assignments
                RunAsAccount = $s.runAsAccount; EnforceSignatureCheck = $s.enforceSignatureCheck
                ScriptContent = $content; ScriptSummary = $summary; Id = $s.id
            }
        }
    }

    # Shell scripts (macOS)
    $shellScripts = Invoke-GraphRequestSafe -Uri "https://graph.microsoft.com/beta/deviceManagement/deviceShellScripts" -Section "ShellScripts"
    if ($shellScripts) {
        foreach ($s in $shellScripts) {
            $assignments = Invoke-GraphRequestSafe -Uri "https://graph.microsoft.com/beta/deviceManagement/deviceShellScripts/$($s.id)/groupAssignments" -Section "ShellScript-GroupAssignments"

            # Fetch full script detail to get scriptContent
            $content = ""
            $summary = ""
            $detail = Invoke-GraphRequestSafe -Uri "https://graph.microsoft.com/beta/deviceManagement/deviceShellScripts/$($s.id)" -Section "ShellScript-Detail"
            if ($detail -and $detail.scriptContent) {
                try {
                    $content = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($detail.scriptContent))
                    $summary = Get-ScriptSummary -ScriptText $content -ScriptType "Shell"
                }
                catch { $content = "(Could not decode script content)" }
            }

            Add-ToPlatform -Platform "macOS" -Category "Scripts" -Item @{
                Name = $s.displayName; Type = "Shell Script"
                Description = $s.description; Created = $s.createdDateTime
                Modified = $s.lastModifiedDateTime; Assignments = $assignments
                ScriptContent = $content; ScriptSummary = $summary; Id = $s.id
            }
        }
    }

    # Proactive Remediations / Device Health Scripts
    $remediations = Invoke-GraphRequestSafe -Uri "https://graph.microsoft.com/beta/deviceManagement/deviceHealthScripts" -Section "HealthScripts"
    if ($remediations) {
        foreach ($r in $remediations) {
            # Skip Microsoft-published built-in scripts
            if ($r.isGlobalScript -eq $true) { continue }
            $assignments = Invoke-GraphRequestSafe -Uri "https://graph.microsoft.com/beta/deviceManagement/deviceHealthScripts/$($r.id)/assignments" -Section "Remediation-Assignments"
            Add-ToPlatform -Platform "Windows" -Category "Proactive Remediations" -Item @{
                Name = $r.displayName; Type = "Proactive Remediation"
                Description = $r.description; Created = $r.createdDateTime
                Modified = $r.lastModifiedDateTime; Assignments = $assignments
                Publisher = $r.publisher; Id = $r.id
            }
        }
    }
}

function Export-EnrollmentConfig {
    Write-Status "Collecting enrollment configurations..." "Info"

    # Enrollment restrictions, ESP, enrollment limits
    $enrollConfigs = Invoke-GraphRequestSafe -Uri "https://graph.microsoft.com/v1.0/deviceManagement/deviceEnrollmentConfigurations" -Section "EnrollmentConfigs"
    if ($enrollConfigs) {
        foreach ($e in $enrollConfigs) {
            $platform = Get-PlatformFromODataType $e.'@odata.type'
            if ($platform -eq "Unclassified") {
                # ESP and enrollment limits are cross-platform
                $platform = "CrossPlatform"
            }
            $assignments = Invoke-GraphRequestSafe -Uri "https://graph.microsoft.com/v1.0/deviceManagement/deviceEnrollmentConfigurations/$($e.id)/assignments" -Section "Enrollment-Assignments"
            Add-ToPlatform -Platform $platform -Category "Enrollment Configuration" -Item @{
                Name = $e.displayName; Type = ($e.'@odata.type' -replace '#microsoft.graph.', '')
                Description = $e.description; Created = $e.createdDateTime
                Modified = $e.lastModifiedDateTime; Assignments = $assignments
                Priority = $e.priority; Id = $e.id
            }
        }
    }

    # Windows Autopilot Deployment Profiles
    $autopilot = Invoke-GraphRequestSafe -Uri "https://graph.microsoft.com/beta/deviceManagement/windowsAutopilotDeploymentProfiles" -Section "AutopilotProfiles"
    if ($autopilot) {
        foreach ($ap in $autopilot) {
            $assignments = Invoke-GraphRequestSafe -Uri "https://graph.microsoft.com/beta/deviceManagement/windowsAutopilotDeploymentProfiles/$($ap.id)/assignments" -Section "Autopilot-Assignments"
            Add-ToPlatform -Platform "Windows" -Category "Autopilot Deployment Profiles" -Item @{
                Name = $ap.displayName; Type = ($ap.'@odata.type' -replace '#microsoft.graph.', '')
                Description = $ap.description; Created = $ap.createdDateTime
                Modified = $ap.lastModifiedDateTime; Assignments = $assignments
                OutOfBoxExperienceSettings = $ap.outOfBoxExperienceSetting
                Id = $ap.id
            }
        }
    }

    # Apple Enrollment (DEP/ADE)
    $appleEnroll = Invoke-GraphRequestSafe -Uri "https://graph.microsoft.com/beta/deviceManagement/depOnboardingSettings" -Section "AppleDEP"
    if ($appleEnroll) {
        foreach ($dep in $appleEnroll) {
            $profiles = Invoke-GraphRequestSafe -Uri "https://graph.microsoft.com/beta/deviceManagement/depOnboardingSettings/$($dep.id)/enrollmentProfiles" -Section "DEP-Profiles"
            $platform = if ($dep.tokenType -eq "dep") { "iOS" } else { "macOS" }
            Add-ToPlatform -Platform $platform -Category "Apple Enrollment (ADE/DEP)" -Item @{
                Name = $dep.tokenName; Type = "Apple DEP Token"
                AppleIdentifier = $dep.appleIdentifier
                TokenExpiration = $dep.tokenExpirationDateTime
                ProfileCount = if ($profiles) { $profiles.Count } else { 0 }
                Id = $dep.id
            }
        }
    }

    # Android Enterprise
    $androidEnterprise = Invoke-GraphRequestSafe -Uri "https://graph.microsoft.com/beta/deviceManagement/androidManagedStoreAccountEnterpriseSettings" -Section "AndroidEnterprise"
    if ($androidEnterprise) {
        Add-ToPlatform -Platform "Android" -Category "Android Enterprise" -Item @{
            Name = "Android Enterprise Binding"
            Type = "Managed Google Play"
            BindStatus = $androidEnterprise.bindStatus
            OwnerOrganizationName = $androidEnterprise.ownerOrganizationName
            EnrollmentTarget = $androidEnterprise.enrollmentTarget
            LastModifiedDateTime = $androidEnterprise.lastModifiedDateTime
        }
    }
}

function Export-UpdatePolicies {
    Write-Status "Collecting update policies..." "Info"

    # Feature Update Profiles (beta)
    $featureUpdates = Invoke-GraphRequestSafe -Uri "https://graph.microsoft.com/beta/deviceManagement/windowsFeatureUpdateProfiles" -Section "FeatureUpdateProfiles"
    if ($featureUpdates) {
        foreach ($fu in $featureUpdates) {
            $assignments = Invoke-GraphRequestSafe -Uri "https://graph.microsoft.com/beta/deviceManagement/windowsFeatureUpdateProfiles/$($fu.id)/assignments" -Section "FeatureUpdate-Assignments"
            Add-ToPlatform -Platform "Windows" -Category "Feature Update Profiles" -Item @{
                Name = $fu.displayName; Type = "Feature Update"
                Description = $fu.description
                FeatureUpdateVersion = $fu.featureUpdateVersion
                RolloutSettings = $fu.rolloutSettings
                Created = $fu.createdDateTime; Modified = $fu.lastModifiedDateTime
                Assignments = $assignments; Id = $fu.id
            }
        }
    }

    # Quality Update Profiles (beta — expedited/driver)
    $qualityUpdates = Invoke-GraphRequestSafe -Uri "https://graph.microsoft.com/beta/deviceManagement/windowsQualityUpdateProfiles" -Section "QualityUpdateProfiles"
    if ($qualityUpdates) {
        foreach ($qu in $qualityUpdates) {
            $assignments = Invoke-GraphRequestSafe -Uri "https://graph.microsoft.com/beta/deviceManagement/windowsQualityUpdateProfiles/$($qu.id)/assignments" -Section "QualityUpdate-Assignments"
            Add-ToPlatform -Platform "Windows" -Category "Quality Update Profiles" -Item @{
                Name = $qu.displayName; Type = "Quality Update"
                Description = $qu.description
                Created = $qu.createdDateTime; Modified = $qu.lastModifiedDateTime
                Assignments = $assignments; Id = $qu.id
            }
        }
    }

    # Apple Software Update policies are captured via deviceConfigurations and classified by odata.type.
}

function Export-ConditionalAccess {
    Write-Status "Collecting Conditional Access policies..." "Info"

    $caPolicies = Invoke-GraphRequestSafe -Uri "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies" -Section "ConditionalAccess"
    if ($caPolicies) {
        foreach ($ca in $caPolicies) {
            Add-ToPlatform -Platform "CrossPlatform" -Category "Conditional Access Policies" -Item @{
                Name        = $ca.displayName
                State       = $ca.state
                Description = $ca.description
                Created     = $ca.createdDateTime
                Modified    = $ca.modifiedDateTime
                Conditions  = $ca.conditions | ConvertTo-Json -Depth 3 -Compress
                GrantControls = $ca.grantControls | ConvertTo-Json -Depth 3 -Compress
                SessionControls = $ca.sessionControls | ConvertTo-Json -Depth 3 -Compress
                Id          = $ca.id
            }
        }
    }
}

function Export-Filters {
    Write-Status "Collecting assignment filters..." "Info"

    $filters = Invoke-GraphRequestSafe -Uri "https://graph.microsoft.com/beta/deviceManagement/assignmentFilters" -Section "AssignmentFilters"
    if ($filters) {
        foreach ($f in $filters) {
            $platform = switch ($f.platform) {
                "windows10AndLater" { "Windows" }
                "macOS"             { "macOS" }
                "iOS"               { "iOS" }
                "androidForWork"    { "Android" }
                "android"           { "Android" }
                default             { "CrossPlatform" }
            }
            Add-ToPlatform -Platform $platform -Category "Assignment Filters" -Item @{
                Name = $f.displayName; Type = "Filter ($($f.platform))"
                Description = $f.description; Rule = $f.rule
                Created = $f.createdDateTime; Modified = $f.lastModifiedDateTime
                Id = $f.id
            }
        }
    }
}

function Export-ScopeTags {
    Write-Status "Collecting scope tags..." "Info"

    $tags = Invoke-GraphRequestSafe -Uri "https://graph.microsoft.com/beta/deviceManagement/roleScopeTags" -Section "ScopeTags"
    if ($tags) {
        foreach ($t in $tags) {
            Add-ToPlatform -Platform "CrossPlatform" -Category "Scope Tags" -Item @{
                Name = $t.displayName; Description = $t.description
                IsBuiltIn = $t.isBuiltIn; Id = $t.id
            }
        }
    }
}

function Export-RBAC {
    Write-Status "Collecting RBAC roles..." "Info"

    $roles = Invoke-GraphRequestSafe -Uri "https://graph.microsoft.com/v1.0/deviceManagement/roleDefinitions" -Section "RBACRoles"
    if ($roles) {
        foreach ($r in $roles) {
            $assignments = Invoke-GraphRequestSafe -Uri "https://graph.microsoft.com/v1.0/deviceManagement/roleDefinitions/$($r.id)/roleAssignments" -Section "RBAC-Assignments"
            Add-ToPlatform -Platform "CrossPlatform" -Category "RBAC Roles" -Item @{
                Name = $r.displayName; Description = $r.description
                IsBuiltIn = $r.isBuiltInRoleDefinition
                AssignmentCount = if ($assignments) { $assignments.Count } else { 0 }
                Id = $r.id
            }
        }
    }
}

function Export-DeviceCategories {
    Write-Status "Collecting device categories..." "Info"

    $categories = Invoke-GraphRequestSafe -Uri "https://graph.microsoft.com/v1.0/deviceManagement/deviceCategories" -Section "DeviceCategories"
    if ($categories) {
        foreach ($c in $categories) {
            Add-ToPlatform -Platform "CrossPlatform" -Category "Device Categories" -Item @{
                Name = $c.displayName; Description = $c.description; Id = $c.id
            }
        }
    }
}

# ---------------------------------------------------------------------------- #
# Additional Data Collection Functions (P0/P1/P2/P3)
# ---------------------------------------------------------------------------- #

function Export-AdminTemplates {
    Write-Status "Collecting Administrative Templates (GPO)..." "Info"

    $gpoConfigs = Invoke-GraphRequestSafe -Uri "https://graph.microsoft.com/beta/deviceManagement/groupPolicyConfigurations" -Section "AdminTemplates"
    if ($gpoConfigs) {
        $total = $gpoConfigs.Count
        $i = 0
        foreach ($gpo in $gpoConfigs) {
            $i++
            if ($total -gt 10) { Write-Host "`r  [$i/$total] $($gpo.displayName)                    " -NoNewline }

            $assignments = Invoke-GraphRequestSafe -Uri "https://graph.microsoft.com/beta/deviceManagement/groupPolicyConfigurations/$($gpo.id)/assignments" -Section "AdminTemplate-Assignments"

            # Fetch definition values with expanded definition and presentation values
            $defValues = Invoke-GraphRequestSafe -Uri "https://graph.microsoft.com/beta/deviceManagement/groupPolicyConfigurations/$($gpo.id)/definitionValues?`$expand=definition" -Section "AdminTemplate-DefValues"
            $settingsList = @()
            if ($defValues) {
                foreach ($dv in $defValues) {
                    $settingName = if ($dv.definition -and $dv.definition.displayName) { $dv.definition.displayName } else { "Unknown Setting" }
                    $categoryPath = if ($dv.definition -and $dv.definition.categoryPath) { $dv.definition.categoryPath } else { "" }
                    $enabled = $dv.enabled
                    $stateText = if ($enabled) { "Enabled" } else { "Disabled" }

                    # Fetch presentation values for the configured parameters
                    $presValues = Invoke-GraphRequestSafe -Uri "https://graph.microsoft.com/beta/deviceManagement/groupPolicyConfigurations/$($gpo.id)/definitionValues/$($dv.id)/presentationValues" -Section "AdminTemplate-PresValues"
                    $valueText = ""
                    if ($presValues -and $presValues.Count -gt 0) {
                        $vals = @()
                        foreach ($pv in $presValues) {
                            $pvVal = if ($null -ne $pv.value) { "$($pv.value)" }
                                     elseif ($pv.values) { ($pv.values | ForEach-Object { "$($_.name)=$($_.value)" }) -join "; " }
                                     else { "(set)" }
                            $vals += $pvVal
                        }
                        $valueText = $vals -join ", "
                    }

                    $fullSetting = if ($categoryPath) { "$categoryPath \ $settingName" } else { $settingName }
                    $settingsList += @{
                        Name  = $fullSetting
                        Value = "$stateText$(if ($valueText) { ": $valueText" } else { '' })"
                    }
                }
            }

            Add-ToPlatform -Platform "Windows" -Category "Administrative Templates" -Item @{
                Name         = $gpo.displayName
                Type         = "Group Policy Configuration"
                Description  = $gpo.description
                Created      = $gpo.createdDateTime
                Modified     = $gpo.lastModifiedDateTime
                Assignments  = $assignments
                ConfiguredSettings = $settingsList
                Id           = $gpo.id
            }
        }
        if ($total -gt 10) { Write-Host "" }
    }
}

function Export-ApplePushCertificate {
    Write-Status "Collecting Apple Push Notification certificate..." "Info"

    $apns = Invoke-GraphRequestSafe -Uri "https://graph.microsoft.com/v1.0/deviceManagement/applePushNotificationCertificate" -Section "APNsCertificate"
    if ($apns) {
        $expDate = if ($apns.expirationDateTime) { ([datetime]$apns.expirationDateTime).ToString("yyyy-MM-dd HH:mm UTC") } else { "Unknown" }
        Add-ToPlatform -Platform "CrossPlatform" -Category "Apple Push Certificate" -Item @{
            Name        = "Apple Push Notification Certificate"
            Type        = "APNs Certificate"
            Description = "Required for Apple device management. Subject: $($apns.certificateSerialNumber)"
            ExtraProperties = [ordered]@{
                "Apple Identifier"     = $apns.appleIdentifier
                "Subject"              = $apns.subject
                "Thumbprint"           = $apns.certificateSerialNumber
                "Expiration"           = $expDate
                "Certificate Upload"   = $apns.certificateUploadDateTime
                "Last Modified"        = $apns.lastModifiedDateTime
                "Topic Identifier"     = $apns.topicIdentifier
            }
            Id = "singleton"
        }
    }
}

function Export-VppTokens {
    Write-Status "Collecting VPP/ABM tokens..." "Info"

    $tokens = Invoke-GraphRequestSafe -Uri "https://graph.microsoft.com/beta/deviceAppManagement/vppTokens" -Section "VPPTokens"
    if ($tokens) {
        foreach ($t in $tokens) {
            $expDate = if ($t.expirationDateTime) { ([datetime]$t.expirationDateTime).ToString("yyyy-MM-dd HH:mm UTC") } else { "Unknown" }
            Add-ToPlatform -Platform "CrossPlatform" -Category "VPP / ABM Tokens" -Item @{
                Name        = if ($t.organizationName) { $t.organizationName } else { "VPP Token" }
                Type        = "VPP Token"
                Description = "Apple Volume Purchase Program token for app licensing"
                ExtraProperties = [ordered]@{
                    "State"              = $t.state
                    "Token Action State" = $t.tokenActionState
                    "Apple ID"           = $t.appleId
                    "Expiration"         = $expDate
                    "Country/Region"     = $t.countryOrRegion
                    "Last Sync"          = $t.lastSyncDateTime
                    "Last Sync Status"   = $t.lastSyncStatus
                    "Auto-Update Apps"   = $t.automaticallyUpdateApps
                }
                Id = $t.id
            }
        }
    }
}

function Export-CustomComplianceScripts {
    Write-Status "Collecting custom compliance scripts..." "Info"

    $scripts = Invoke-GraphRequestSafe -Uri "https://graph.microsoft.com/beta/deviceManagement/deviceComplianceScripts" -Section "CustomComplianceScripts"
    if ($scripts) {
        foreach ($s in $scripts) {
            $content = ""
            $summary = ""
            if ($s.detectionScriptContent) {
                try {
                    $content = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($s.detectionScriptContent))
                    $summary = Get-ScriptSummary -ScriptText $content -ScriptType "PowerShell"
                }
                catch { $content = "(Could not decode script content)" }
            }
            $assignments = Invoke-GraphRequestSafe -Uri "https://graph.microsoft.com/beta/deviceManagement/deviceComplianceScripts/$($s.id)/assignments" -Section "ComplianceScript-Assignments"

            Add-ToPlatform -Platform "CrossPlatform" -Category "Custom Compliance Scripts" -Item @{
                Name = $s.displayName; Type = "Compliance Detection Script"
                Description = $s.description; Created = $s.createdDateTime
                Modified = $s.lastModifiedDateTime; Assignments = $assignments
                Publisher = $s.publisher; RunAsAccount = $s.runAsAccount
                ScriptContent = $content; ScriptSummary = $summary; Id = $s.id
            }
        }
    }
}

function Export-PolicySets {
    Write-Status "Collecting policy sets..." "Info"

    $policySets = Invoke-GraphRequestSafe -Uri "https://graph.microsoft.com/beta/deviceAppManagement/policySets" -Section "PolicySets"
    if ($policySets) {
        foreach ($ps in $policySets) {
            $assignments = Invoke-GraphRequestSafe -Uri "https://graph.microsoft.com/beta/deviceAppManagement/policySets/$($ps.id)/assignments" -Section "PolicySet-Assignments"
            $items = Invoke-GraphRequestSafe -Uri "https://graph.microsoft.com/beta/deviceAppManagement/policySets/$($ps.id)/items" -Section "PolicySet-Items"

            $itemList = @()
            if ($items) {
                foreach ($item in $items) {
                    $itemType = ($item.'@odata.type' -replace '#microsoft.graph.', '' -replace 'PolicySetItem', '')
                    $itemList += "${itemType}: $($item.displayName)"
                }
            }

            Add-ToPlatform -Platform "CrossPlatform" -Category "Policy Sets" -Item @{
                Name = $ps.displayName; Type = "Policy Set"
                Description = $ps.description; Created = $ps.createdDateTime
                Modified = $ps.lastModifiedDateTime; Assignments = $assignments
                State = $ps.status
                ExtraProperties = [ordered]@{
                    "Bundled Items" = if ($itemList.Count -gt 0) { $itemList -join "; " } else { "None" }
                    "Item Count"    = if ($items) { $items.Count } else { 0 }
                }
                Id = $ps.id
            }
        }
    }
}

function Export-CustomADMX {
    Write-Status "Collecting custom ADMX imports..." "Info"

    $admx = Invoke-GraphRequestSafe -Uri "https://graph.microsoft.com/beta/deviceManagement/groupPolicyUploadedDefinitionFiles" -Section "CustomADMX"
    if ($admx) {
        foreach ($f in $admx) {
            Add-ToPlatform -Platform "Windows" -Category "Custom ADMX Imports" -Item @{
                Name = $f.fileName; Type = "ADMX Definition File"
                Description = $f.description; Created = $f.createdDateTime
                Modified = $f.lastModifiedDateTime
                State = $f.status
                ExtraProperties = [ordered]@{
                    "Language"      = $f.languageCodes -join ", "
                    "Target Prefix" = $f.targetPrefix
                    "Target Namespace" = $f.targetNamespace
                    "Upload Status" = $f.uploadStatus
                }
                Id = $f.id
            }
        }
    }
}

function Export-AndroidDeviceOwnerProfiles {
    Write-Status "Collecting Android Device Owner enrollment profiles..." "Info"

    $profiles = Invoke-GraphRequestSafe -Uri "https://graph.microsoft.com/beta/deviceManagement/androidDeviceOwnerEnrollmentProfiles" -Section "AndroidDOProfiles"
    if ($profiles) {
        foreach ($p in $profiles) {
            Add-ToPlatform -Platform "Android" -Category "Android Device Owner Enrollment" -Item @{
                Name = $p.displayName; Type = "Device Owner Enrollment Profile"
                Description = $p.description; Created = $p.createdDateTime
                Modified = $p.lastModifiedDateTime
                ExtraProperties = [ordered]@{
                    "Enrollment Mode"   = $p.enrollmentMode
                    "Enrollment Type"   = $p.enrollmentTokenType
                    "Token Expiration"  = $p.tokenExpirationDateTime
                    "Token Value"       = "(redacted)"
                    "QR Code Content"   = if ($p.qrCodeContent) { "(available)" } else { "N/A" }
                    "Enrolled Count"    = $p.enrolledDeviceCount
                    "Wi-Fi Hidden"      = $p.wifiHidden
                }
                Id = $p.id
            }
        }
    }
}

function Export-IntuneBranding {
    Write-Status "Collecting Intune branding profiles..." "Info"

    $branding = Invoke-GraphRequestSafe -Uri "https://graph.microsoft.com/beta/deviceManagement/intuneBrandingProfiles" -Section "IntuneBranding"
    if ($branding) {
        foreach ($b in $branding) {
            $assignments = Invoke-GraphRequestSafe -Uri "https://graph.microsoft.com/beta/deviceManagement/intuneBrandingProfiles/$($b.id)/assignments" -Section "Branding-Assignments"
            Add-ToPlatform -Platform "CrossPlatform" -Category "Intune Branding" -Item @{
                Name = if ($b.profileName) { $b.profileName } else { $b.displayName }
                Type = if ($b.isDefaultProfile) { "Default Branding Profile" } else { "Custom Branding Profile" }
                Description = $b.profileDescription; Assignments = $assignments
                ExtraProperties = [ordered]@{
                    "Company Name"          = $b.companyPortalBlockedActions
                    "Theme Color"           = $b.themeColor
                    "Show Display Name"     = $b.showDisplayNameNextToLogo
                    "Show Company Name"     = $b.showNameNextToLogo
                    "Contact IT Name"       = $b.contactITName
                    "Contact IT Phone"      = $b.contactITPhoneNumber
                    "Contact IT Email"      = $b.contactITEmailAddress
                    "Contact IT Notes"      = $b.contactITNotes
                    "Privacy URL"           = $b.privacyUrl
                    "Online Support URL"    = $b.onlineSupportSiteUrl
                    "Enrollment Avail."     = $b.enrollmentAvailability
                    "Is Default"            = $b.isDefaultProfile
                }
                Id = $b.id
            }
        }
    }
}

function Export-DriverUpdates {
    Write-Status "Collecting driver update profiles..." "Info"

    $drivers = Invoke-GraphRequestSafe -Uri "https://graph.microsoft.com/beta/deviceManagement/windowsDriverUpdateProfiles" -Section "DriverUpdateProfiles"
    if ($drivers) {
        foreach ($d in $drivers) {
            $assignments = Invoke-GraphRequestSafe -Uri "https://graph.microsoft.com/beta/deviceManagement/windowsDriverUpdateProfiles/$($d.id)/assignments" -Section "DriverUpdate-Assignments"
            Add-ToPlatform -Platform "Windows" -Category "Driver Update Profiles" -Item @{
                Name = $d.displayName; Type = "Driver Update Profile"
                Description = $d.description; Created = $d.createdDateTime
                Modified = $d.lastModifiedDateTime; Assignments = $assignments
                ExtraProperties = [ordered]@{
                    "Approval Type" = $d.approvalType
                    "Inventory Sync State" = $d.inventorySyncState
                }
                Id = $d.id
            }
        }
    }
}

function Export-MTDConnectors {
    Write-Status "Collecting Mobile Threat Defense connectors..." "Info"

    $connectors = Invoke-GraphRequestSafe -Uri "https://graph.microsoft.com/beta/deviceManagement/mobileThreatDefenseConnectors" -Section "MTDConnectors"
    if ($connectors) {
        foreach ($c in $connectors) {
            Add-ToPlatform -Platform "CrossPlatform" -Category "Mobile Threat Defense Connectors" -Item @{
                Name = if ($c.displayName) { $c.displayName } else { "MTD Connector ($($c.id))" }
                Type = "MTD Connector"
                ExtraProperties = [ordered]@{
                    "Partner State"                = $c.partnerState
                    "Android Enabled"              = $c.androidEnabled
                    "iOS Enabled"                  = $c.iosEnabled
                    "Windows Enabled"              = $c.windowsEnabled
                    "macOS Enabled"                = $c.macOsEnabled
                    "Android Device Blocked"       = $c.androidDeviceBlockedOnMissingPartnerData
                    "iOS Device Blocked"           = $c.iosDeviceBlockedOnMissingPartnerData
                    "Partner Unresponsiveness"     = $c.partnerUnresponsivenessThresholdInDays
                    "Last Heartbeat"               = $c.lastHeartbeatDateTime
                    "Allow Partner to Collect"     = $c.allowPartnerToCollectIOSApplicationMetadata
                }
                Id = $c.id
            }
        }
    }
}

function Export-DeviceManagementPartners {
    Write-Status "Collecting device management partners..." "Info"

    $partners = Invoke-GraphRequestSafe -Uri "https://graph.microsoft.com/beta/deviceManagement/deviceManagementPartners" -Section "DeviceManagementPartners"
    if ($partners) {
        foreach ($p in $partners) {
            Add-ToPlatform -Platform "CrossPlatform" -Category "Device Management Partners" -Item @{
                Name = $p.displayName; Type = "Management Partner"
                ExtraProperties = [ordered]@{
                    "Partner State"              = $p.partnerState
                    "Partner App Type"           = $p.partnerAppType
                    "Is Configured"              = $p.isConfigured
                    "When Partner Devices Will Be Marked As Non-Compliant" = $p.whenPartnerDevicesWillBeMarkedAsNonCompliantDateTime
                    "When Partner Devices Will Be Removed" = $p.whenPartnerDevicesWillBeRemovedDateTime
                    "Groups Requiring Partner Enrollment" = if ($p.groupsRequiringPartnerEnrollment) { $p.groupsRequiringPartnerEnrollment.Count } else { 0 }
                    "Last Heartbeat"             = $p.lastHeartbeatDateTime
                    "Single Tenant App ID"       = $p.singleTenantAppId
                }
                Id = $p.id
            }
        }
    }
}

function Export-TermsAndConditions {
    Write-Status "Collecting Terms and Conditions..." "Info"

    $terms = Invoke-GraphRequestSafe -Uri "https://graph.microsoft.com/v1.0/deviceManagement/termsAndConditions" -Section "TermsAndConditions"
    if ($terms) {
        foreach ($t in $terms) {
            $assignments = Invoke-GraphRequestSafe -Uri "https://graph.microsoft.com/v1.0/deviceManagement/termsAndConditions/$($t.id)/assignments" -Section "Terms-Assignments"
            Add-ToPlatform -Platform "CrossPlatform" -Category "Terms and Conditions" -Item @{
                Name = $t.displayName; Type = "Terms and Conditions"
                Description = $t.description; Created = $t.createdDateTime
                Modified = $t.lastModifiedDateTime; Assignments = $assignments
                ExtraProperties = [ordered]@{
                    "Title"             = $t.title
                    "Body Text"         = if ($t.bodyText -and $t.bodyText.Length -gt 200) { $t.bodyText.Substring(0, 200) + "..." } elseif ($t.bodyText) { $t.bodyText } else { "-" }
                    "Acceptance Statement" = $t.acceptanceStatement
                    "Version"           = $t.version
                }
                Id = $t.id
            }
        }
    }
}

function Export-NotificationTemplates {
    Write-Status "Collecting notification message templates..." "Info"

    $templates = Invoke-GraphRequestSafe -Uri "https://graph.microsoft.com/beta/deviceManagement/notificationMessageTemplates" -Section "NotificationTemplates"
    if ($templates) {
        foreach ($t in $templates) {
            # Fetch localized messages
            $localized = Invoke-GraphRequestSafe -Uri "https://graph.microsoft.com/beta/deviceManagement/notificationMessageTemplates/$($t.id)/localizedNotificationMessages" -Section "NotificationLocalized"
            $localeList = @()
            if ($localized) {
                foreach ($l in $localized) {
                    $localeList += "$($l.locale): $($l.subject)"
                }
            }
            Add-ToPlatform -Platform "CrossPlatform" -Category "Notification Message Templates" -Item @{
                Name = $t.displayName; Type = "Notification Template"
                Description = $t.description; Modified = $t.lastModifiedDateTime
                ExtraProperties = [ordered]@{
                    "Branding Options"  = $t.brandingOptions
                    "Default Locale"    = $t.defaultLocale
                    "Localized Messages" = if ($localeList.Count -gt 0) { $localeList -join "; " } else { "None" }
                }
                Id = $t.id
            }
        }
    }
}

function Export-DeviceCleanupSettings {
    Write-Status "Collecting device cleanup settings..." "Info"

    $cleanup = Invoke-GraphRequestSafe -Uri "https://graph.microsoft.com/beta/deviceManagement/managedDeviceCleanupSettings" -Section "DeviceCleanupSettings"
    if ($cleanup) {
        Add-ToPlatform -Platform "CrossPlatform" -Category "Device Cleanup Settings" -Item @{
            Name = "Device Cleanup Rule"
            Type = "Cleanup Configuration"
            Description = "Automatic device cleanup based on inactivity"
            ExtraProperties = [ordered]@{
                "Cleanup Rule Enabled" = if ($null -ne $cleanup.deviceInactivityBeforeRetirementInDays) { "Yes" } else { "No" }
                "Days Before Retirement" = $cleanup.deviceInactivityBeforeRetirementInDays
            }
            Id = "singleton"
        }
    }
}

# ---------------------------------------------------------------------------- #
# Markdown Rendering
# ---------------------------------------------------------------------------- #

function Get-PlatformMarkdown {
    param(
        [string]$Platform,
        [array]$Items
    )

    $friendlyName = switch ($Platform) {
        "CrossPlatform" { "Cross-Platform" }
        default { $Platform }
    }

    $sb = [System.Text.StringBuilder]::new()
    [void]$sb.AppendLine("# $friendlyName - Intune Tenant Configuration")
    [void]$sb.AppendLine("")
    [void]$sb.AppendLine("> **Exported:** $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss UTC' -AsUTC) | **Tenant:** $script:TenantIdResolved | **Organization:** $script:OrgName")
    [void]$sb.AppendLine("")

    # Group items by category
    $grouped = $Items | Group-Object -Property { $_.Category }

    # Summary table
    [void]$sb.AppendLine("## Summary")
    [void]$sb.AppendLine("")
    [void]$sb.AppendLine("| Category | Count |")
    [void]$sb.AppendLine("|----------|-------|")
    foreach ($g in ($grouped | Sort-Object Name)) {
        [void]$sb.AppendLine("| $($g.Name) | $($g.Count) |")
    }
    [void]$sb.AppendLine("")
    [void]$sb.AppendLine("---")
    [void]$sb.AppendLine("")

    foreach ($group in ($grouped | Sort-Object Name)) {
        [void]$sb.AppendLine("## $($group.Name)")
        [void]$sb.AppendLine("")

        # Overview table
        $hasType = $group.Group | Where-Object { $_.Data.Type }
        if ($hasType) {
            [void]$sb.AppendLine("| Name | Type | Assignments | Created | Last Modified |")
            [void]$sb.AppendLine("|------|------|-------------|---------|---------------|")
            foreach ($item in $group.Group) {
                $d = $item.Data
                $created = if ($d.Created) { ([datetime]$d.Created).ToString("yyyy-MM-dd") } else { "-" }
                $modified = if ($d.Modified) { ([datetime]$d.Modified).ToString("yyyy-MM-dd") } else { "-" }
                $name = ($d.Name -replace '\|', '\|')
                $type = if ($d.Type) { ($d.Type -replace '\|', '\|') } else { "-" }
                $assignSummary = Format-AssignmentsSummary $d.Assignments
                [void]$sb.AppendLine("| $name | $type | $assignSummary | $created | $modified |")
            }
            [void]$sb.AppendLine("")
        }

        # Detailed entries
        foreach ($item in $group.Group) {
            $d = $item.Data
            [void]$sb.AppendLine("### $($d.Name)")
            [void]$sb.AppendLine("")

            if ($d.Description) { [void]$sb.AppendLine("**Description:** $($d.Description)") ; [void]$sb.AppendLine("") }
            if ($d.Type) { [void]$sb.AppendLine("- **Type:** $($d.Type)") }
            if ($d.Id) { [void]$sb.AppendLine("- **ID:** ``$($d.Id)``") }
            if ($d.State) { [void]$sb.AppendLine("- **State:** $($d.State)") }
            if ($d.Priority) { [void]$sb.AppendLine("- **Priority:** $($d.Priority)") }
            if ($d.Publisher) { [void]$sb.AppendLine("- **Publisher:** $($d.Publisher)") }
            if ($d.Rule) { [void]$sb.AppendLine("- **Rule:** ``$($d.Rule)``") }
            if ($d.FeatureUpdateVersion) { [void]$sb.AppendLine("- **Target Version:** $($d.FeatureUpdateVersion)") }
            if ($d.RunAsAccount) { [void]$sb.AppendLine("- **Run As:** $($d.RunAsAccount)") }
            if ($d.EnforceSignatureCheck) { [void]$sb.AppendLine("- **Signature Check:** $($d.EnforceSignatureCheck)") }

            # Assignments — full table
            if ($d.Assignments -and $d.Assignments.Count -gt 0) {
                [void]$sb.AppendLine("")
                [void]$sb.AppendLine("**Assignments ($($d.Assignments.Count)):**")
                $formatted = Format-Assignments $d.Assignments
                [void]$sb.AppendLine($formatted)
            }
            else {
                [void]$sb.AppendLine("- **Assignments:** None")
            }

            # App install intents
            if ($d.InstallIntents -and $d.InstallIntents.Count -gt 0) {
                [void]$sb.AppendLine("")
                [void]$sb.AppendLine("**Install Intents:**")
                [void]$sb.AppendLine("")
                foreach ($intent in $d.InstallIntents) {
                    [void]$sb.AppendLine("- $intent")
                }
            }

            # Configured Settings (legacy device config profiles)
            if ($d.ConfiguredSettings -and $d.ConfiguredSettings.Count -gt 0) {
                [void]$sb.AppendLine("")
                [void]$sb.AppendLine("**Configured Settings:**")
                [void]$sb.AppendLine("")
                [void]$sb.AppendLine("| Setting | Value |")
                [void]$sb.AppendLine("|---------|-------|")
                foreach ($setting in $d.ConfiguredSettings) {
                    $sName = ($setting.Name -replace '\|', '\|')
                    $sVal = ("$($setting.Value)" -replace '\|', '\|')
                    if ($sVal.Length -gt 200) { $sVal = $sVal.Substring(0, 200) + "..." }
                    [void]$sb.AppendLine("| ``$sName`` | $sVal |")
                }
            }

            # Settings Catalog detailed settings
            if ($d.CatalogSettings -and $d.CatalogSettings.Count -gt 0) {
                [void]$sb.AppendLine("")
                [void]$sb.AppendLine("**Settings ($($d.CatalogSettings.Count) configured):**")
                [void]$sb.AppendLine("")
                [void]$sb.AppendLine("| Setting | Value |")
                [void]$sb.AppendLine("|---------|-------|")
                foreach ($cs in $d.CatalogSettings) {
                    $csName = ($cs.Name -replace '\|', '\|')
                    $csVal = ("$($cs.Value)" -replace '\|', '\|')
                    if ($csVal.Length -gt 200) { $csVal = $csVal.Substring(0, 200) + "..." }
                    [void]$sb.AppendLine("| ``$csName`` | $csVal |")
                }
            }

            # Script summary and content
            if ($EmbedScripts -and $d.ScriptSummary -and $d.ScriptSummary -ne "") {
                [void]$sb.AppendLine("")
                [void]$sb.AppendLine("**Script Analysis:**")
                [void]$sb.AppendLine("")
                [void]$sb.AppendLine($d.ScriptSummary)
            }

            if ($EmbedScripts -and $d.ScriptContent -and $d.ScriptContent -ne "") {
                $langHint = if ($d.Type -match "Shell") { "bash" } else { "powershell" }
                [void]$sb.AppendLine("")
                [void]$sb.AppendLine("<details><summary>Full Script Content</summary>")
                [void]$sb.AppendLine("")
                [void]$sb.AppendLine("``````$langHint")
                [void]$sb.AppendLine($d.ScriptContent)
                [void]$sb.AppendLine("``````")
                [void]$sb.AppendLine("</details>")
            }

            if ($EmbedScripts -and $d.PreInstallScriptSummary -and $d.PreInstallScriptSummary -ne "") {
                [void]$sb.AppendLine("")
                [void]$sb.AppendLine("**Pre-install Script Analysis:**")
                [void]$sb.AppendLine("")
                [void]$sb.AppendLine($d.PreInstallScriptSummary)
            }

            if ($EmbedScripts -and $d.PreInstallScriptContent -and $d.PreInstallScriptContent -ne "") {
                [void]$sb.AppendLine("")
                [void]$sb.AppendLine("<details><summary>Pre-install Script</summary>")
                [void]$sb.AppendLine("")
                [void]$sb.AppendLine("``````bash")
                [void]$sb.AppendLine($d.PreInstallScriptContent)
                [void]$sb.AppendLine("``````")
                [void]$sb.AppendLine("</details>")
            }

            if ($EmbedScripts -and $d.PostInstallScriptSummary -and $d.PostInstallScriptSummary -ne "") {
                [void]$sb.AppendLine("")
                [void]$sb.AppendLine("**Post-install Script Analysis:**")
                [void]$sb.AppendLine("")
                [void]$sb.AppendLine($d.PostInstallScriptSummary)
            }

            if ($EmbedScripts -and $d.PostInstallScriptContent -and $d.PostInstallScriptContent -ne "") {
                [void]$sb.AppendLine("")
                [void]$sb.AppendLine("<details><summary>Post-install Script</summary>")
                [void]$sb.AppendLine("")
                [void]$sb.AppendLine("``````bash")
                [void]$sb.AppendLine($d.PostInstallScriptContent)
                [void]$sb.AppendLine("``````")
                [void]$sb.AppendLine("</details>")
            }

            # Extra properties (generic key-value table for new categories)
            if ($d.ExtraProperties -and $d.ExtraProperties.Count -gt 0) {
                [void]$sb.AppendLine("")
                [void]$sb.AppendLine("**Details:**")
                [void]$sb.AppendLine("")
                [void]$sb.AppendLine("| Property | Value |")
                [void]$sb.AppendLine("|----------|-------|")
                foreach ($key in $d.ExtraProperties.Keys) {
                    $val = "$($d.ExtraProperties[$key])" -replace '\|', '\|'
                    if ($val.Length -gt 300) { $val = $val.Substring(0, 300) + "..." }
                    [void]$sb.AppendLine("| $key | $val |")
                }
            }

            # Conditional Access details
            if ($d.Conditions) {
                [void]$sb.AppendLine("")
                [void]$sb.AppendLine("<details><summary>Conditions</summary>")
                [void]$sb.AppendLine("")
                [void]$sb.AppendLine("``````json")
                [void]$sb.AppendLine($d.Conditions)
                [void]$sb.AppendLine("``````")
                [void]$sb.AppendLine("</details>")
            }
            if ($d.GrantControls) {
                [void]$sb.AppendLine("")
                [void]$sb.AppendLine("<details><summary>Grant Controls</summary>")
                [void]$sb.AppendLine("")
                [void]$sb.AppendLine("``````json")
                [void]$sb.AppendLine($d.GrantControls)
                [void]$sb.AppendLine("``````")
                [void]$sb.AppendLine("</details>")
            }

            [void]$sb.AppendLine("")
            [void]$sb.AppendLine("---")
            [void]$sb.AppendLine("")
        }
    }

    return $sb.ToString()
}

# ---------------------------------------------------------------------------- #
# Main Execution
# ---------------------------------------------------------------------------- #

try {
    Write-Host ""
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "  Intune Tenant Configuration Exporter  " -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host ""

    # Set output path
    if (-not $OutputPath) {
        $OutputPath = Join-Path (Get-Location) "IntuneExport-$(Get-Date -Format 'yyyy-MM-dd')"
    }
    if (-not (Test-Path -LiteralPath $OutputPath)) {
        New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
    }

    # Connect to Graph
    Write-Status "Connecting to Microsoft Graph..."
    $connectParams = @{ Scopes = $GRAPH_SCOPES; NoWelcome = $true }
    if ($TenantId) { $connectParams.TenantId = $TenantId }
    Connect-MgGraph @connectParams

    # Get org info
    $context = Get-MgContext
    $script:TenantIdResolved = $context.TenantId
    try {
        $org = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/organization"
        $script:OrgName = $org.value[0].displayName
    }
    catch { $script:OrgName = "Unknown" }

    Write-Status "Connected to: $($script:OrgName) ($($script:TenantIdResolved))" "Success"
    Write-Host ""

    # Phase 1: Collect all data
    Write-Host "--- Phase 1: Data Collection ---" -ForegroundColor Magenta
    Export-DeviceConfigurationProfiles
    Export-CompliancePolicies
    Export-AppProtectionPolicies
    Export-AppConfigPolicies
    Export-Apps
    Export-EndpointSecurity
    Export-Scripts
    Export-EnrollmentConfig
    Export-UpdatePolicies
    Export-ConditionalAccess
    Export-Filters
    Export-ScopeTags
    Export-RBAC
    Export-DeviceCategories
    Export-AdminTemplates
    Export-ApplePushCertificate
    Export-VppTokens
    Export-CustomComplianceScripts
    Export-PolicySets
    Export-CustomADMX
    Export-AndroidDeviceOwnerProfiles
    Export-IntuneBranding
    Export-DriverUpdates
    Export-MTDConnectors
    Export-DeviceManagementPartners
    Export-TermsAndConditions
    Export-NotificationTemplates
    Export-DeviceCleanupSettings
    Write-Host ""

    # Phase 2: Render Markdown
    Write-Host "--- Phase 2: Generating Markdown ---" -ForegroundColor Magenta
    $platformOrder = @("Windows", "macOS", "iOS", "Android", "CrossPlatform")
    $platformFiles = @{
        "Windows"       = "Windows.md"
        "macOS"         = "macOS.md"
        "iOS"           = "iOS.md"
        "Android"       = "Android.md"
        "CrossPlatform" = "Cross-platform.md"
    }

    $totalItems = 0
    $renderedPlatforms = [ordered]@{}
    foreach ($platform in $platformOrder) {
        $items = $PLATFORM_MAP[$platform]
        if (-not $items -or $items.Count -eq 0) {
            Write-Status "$platform — no items found, skipping." "Warning"
            continue
        }
        $totalItems += $items.Count
        $md = Get-PlatformMarkdown -Platform $platform -Items $items
        $filePath = Join-Path $OutputPath $platformFiles[$platform]
        $md | Out-File -LiteralPath $filePath -Encoding utf8 -Force
        Write-Status "$platform — $($items.Count) items -> $($platformFiles[$platform])" "Success"
        $renderedPlatforms[$platform] = $md
    }

    # Handle unclassified items
    $unclassified = $PLATFORM_MAP["Unclassified"]
    if ($unclassified -and $unclassified.Count -gt 0) {
        $totalItems += $unclassified.Count
        $md = Get-PlatformMarkdown -Platform "Unclassified" -Items $unclassified
        $filePath = Join-Path $OutputPath "Unclassified.md"
        $md | Out-File -LiteralPath $filePath -Encoding utf8 -Force
        Write-Status "Unclassified — $($unclassified.Count) items -> Unclassified.md" "Warning"
        $renderedPlatforms["Unclassified"] = $md
    }

    # Phase 3: Generate combined Full-Tenant-Documentation.md
    Write-Host ""
    Write-Host "--- Phase 3: Combined Tenant Document ---" -ForegroundColor Magenta
    $fullDoc = [System.Text.StringBuilder]::new()
    [void]$fullDoc.AppendLine("# Full Intune Tenant Documentation")
    [void]$fullDoc.AppendLine("")
    [void]$fullDoc.AppendLine("> **Exported:** $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss UTC' -AsUTC) | **Tenant:** $script:TenantIdResolved | **Organization:** $script:OrgName")
    [void]$fullDoc.AppendLine("")
    [void]$fullDoc.AppendLine("**Total items documented:** $totalItems across $($renderedPlatforms.Count) platforms")
    [void]$fullDoc.AppendLine("")

    # Table of Contents
    [void]$fullDoc.AppendLine("## Table of Contents")
    [void]$fullDoc.AppendLine("")
    foreach ($plat in $renderedPlatforms.Keys) {
        $friendlyName = switch ($plat) { "CrossPlatform" { "Cross-Platform" }; default { $plat } }
        $platItems = $PLATFORM_MAP[$plat]
        $platCategories = $platItems | Group-Object -Property { $_.Category }
        [void]$fullDoc.AppendLine("### $friendlyName ($($platItems.Count) items)")
        [void]$fullDoc.AppendLine("")
        foreach ($cat in ($platCategories | Sort-Object Name)) {
            $anchor = ($plat.ToLower() + "-" + $cat.Name.ToLower()) -replace '[^a-z0-9-]', '-' -replace '-+', '-'
            [void]$fullDoc.AppendLine("- [$($cat.Name) ($($cat.Count))]($('#' + $anchor))")
        }
        [void]$fullDoc.AppendLine("")
    }
    [void]$fullDoc.AppendLine("---")
    [void]$fullDoc.AppendLine("")

    # Append each platform section
    foreach ($plat in $renderedPlatforms.Keys) {
        $platMd = $renderedPlatforms[$plat]
        # Downgrade H1 to H2 and H2 to H3 for the combined doc (avoid multiple H1s)
        $platMd = $platMd -replace '(?m)^### ', '#### '
        $platMd = $platMd -replace '(?m)^## ', '### '
        $platMd = $platMd -replace '(?m)^# ', '## '
        [void]$fullDoc.AppendLine($platMd)
        [void]$fullDoc.AppendLine("")
        [void]$fullDoc.AppendLine("---")
        [void]$fullDoc.AppendLine("")
    }

    $fullDocPath = Join-Path $OutputPath "Full-Tenant-Documentation.md"
    $fullDoc.ToString() | Out-File -LiteralPath $fullDocPath -Encoding utf8 -Force
    Write-Status "Full tenant doc -> Full-Tenant-Documentation.md" "Success"

    # Export summary
    Write-Host ""
    Write-Host "========================================" -ForegroundColor Green
    Write-Status "Export complete!" "Success"
    Write-Status "Total items exported: $totalItems"
    Write-Status "Output directory: $OutputPath"
    if ($script:ExportErrors.Count -gt 0) {
        Write-Host ""
        Write-Status "$($script:ExportErrors.Count) sections were skipped (warnings):" "Warning"
        foreach ($err in $script:ExportErrors) {
            Write-Host "  - $err" -ForegroundColor Yellow
        }
    }
    Write-Host "========================================" -ForegroundColor Green

    # Write errors summary to file
    if ($script:ExportErrors.Count -gt 0) {
        $errFile = Join-Path $OutputPath "_warnings.md"
        $errContent = "# Export Warnings`n`nThe following sections were skipped during export:`n`n"
        foreach ($err in $script:ExportErrors) { $errContent += "- $err`n" }
        $errContent | Out-File -LiteralPath $errFile -Encoding utf8 -Force
    }
}
catch {
    Write-Status "Fatal error: $($_.Exception.Message)" "Error"
    Write-Status "Stack trace: $($_.ScriptStackTrace)" "Error"
    exit 1
}
finally {
    # Disconnect cleanly
    try { Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null } catch {}
}
