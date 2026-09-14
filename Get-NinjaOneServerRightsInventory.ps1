<#
.SYNOPSIS
    Deploys the local rights-collection script to servers via the NinjaOne API and
    aggregates the results into CSV reports, for the privilege-audit initiative.

.DESCRIPTION
    Companion to Get-ADRightsInventory.ps1 (on-prem AD rights) and Run-EntraUserAudit.ps1
    (Entra rights). This script answers "what rights exist at the server OS level" - local
    group membership and User Rights Assignment - which neither of those two can see.

    It uses the NinjaOne PowerShell module (already installed, v2.0.4) with client-credential
    (application) authentication against the NinjaOne v2 API, so it can be re-run
    unattended/on a schedule. Flow:

      1. Connect-NinjaOne using the app's Client ID/Secret (client-credentials grant).
      2. Resolve the Automation Library script id by name (NinjaOne\Local-RightsInventory.ps1
         must already be pasted into the Automation Library - see docs\NinjaOne-API-Setup.md).
      3. Enumerate target devices via -DeviceFilter (defaults to Windows Servers).
      4. Invoke the script on each device (Invoke-NinjaOneDeviceScript returns no job
         reference from the API itself, so completion is detected by polling the
         rightsInventoryTimestamp custom field for a value newer than the invocation time,
         rather than by any job-status API - see .NOTES).
      5. Once a device's timestamp field updates, read + decompress rightsInventoryPayload
         and fold its LocalGroups/UserRights arrays into the aggregate report.
      6. Export three CSVs: local group membership, user rights assignment, and any devices
         that errored or timed out.

.PARAMETER ClientId
    NinjaOne API application Client ID. Optional - if omitted (along with -ClientSecret),
    resolved from Microsoft.PowerShell.SecretManagement via -ClientIdSecretName instead.

.PARAMETER ClientSecret
    NinjaOne API application Client Secret. Optional - same fallback as -ClientId, via
    -ClientSecretSecretName.

.PARAMETER ClientIdSecretName
    Name of the SecretManagement secret holding the Client ID, used when -ClientId is not
    supplied directly. Defaults to 'NinjaOne-ClientId'.

.PARAMETER ClientSecretSecretName
    Name of the SecretManagement secret holding the Client Secret, used when -ClientSecret is
    not supplied directly. Defaults to 'NinjaOne-ClientSecret'.

.PARAMETER Instance
    NinjaOne region code that Connect-NinjaOne expects - one of eu, oc, us, ca, us2 (not a
    hostname). Defaults to 'us', which is what app.ninjarmm.com (confirmed for this tenant
    2026-09-14) maps to.

.PARAMETER Scopes
    OAuth scopes to request. Defaults to the scopes already granted to this tenant's API app:
    monitoring, management, control, offline_access. 'control' is required to run scripts.

.PARAMETER ScriptName
    Name of the Automation Library script (as it appears in NinjaOne) that runs
    NinjaOne\Local-RightsInventory.ps1's logic. Defaults to 'Local-RightsInventory'. Ignored
    if -ScriptId is supplied directly.

.PARAMETER ScriptId
    Automation Library script id to run, bypassing the by-name lookup.

.PARAMETER DeviceFilter
    NinjaOne device filter query. Defaults to 'class in (WINDOWS_SERVER)'. Verify this class
    value matches your tenant (confirm via Get-NinjaOneDevices -detailed | Select nodeClass
    -Unique) before a full run.

.PARAMETER MaxWaitMinutes
    How long to keep polling a device for a completed run before giving up on it. Default 10.

.PARAMETER PollIntervalSeconds
    Delay between polling rounds. Default 20.

.PARAMETER ThrottleMilliseconds
    Delay between successive script invocations, to stay well under API rate limits on large
    device counts. Default 500ms.

.PARAMETER OutputPath
    Folder to write CSV reports to. Defaults to .\output next to this script.

.EXAMPLE
    .\Get-NinjaOneServerRightsInventory.ps1 -ClientId $cid -ClientSecret $secret

    Full run against all Windows Servers using the defaults.

.EXAMPLE
    .\Get-NinjaOneServerRightsInventory.ps1 -TargetSystemNames 'TESTSVR01'

    First-test-run pattern: target exactly one device (by name, matched client-side - see
    -TargetSystemNames) to validate the Automation Library script and custom fields are wired
    up correctly before a full rollout. Credentials pulled from SecretManagement.

.NOTES
    Author  : RTillmon - InEight Technology Operations (with Claude Code)
    Version : 1.0.0
    Created : 2026-09-14

    Not yet run against a live NinjaOne tenant. The completion-detection approach (poll the
    timestamp custom field rather than a job-status API) was chosen because
    Invoke-NinjaOneDeviceScript's underlying API call (POST /v2/device/{id}/script/run)
    returns only an HTTP 204 with no job identifier to poll - confirmed by reading the
    installed module's source (NinjaOne.psm1). Validate the full loop against one device
    (see the second example above) before a broad run.
#>

#Requires -Module NinjaOne

[CmdletBinding()]
param(
    # Explicit credentials. Omit both and use -ClientIdSecretName/-ClientSecretSecretName
    # instead to pull from Microsoft.PowerShell.SecretManagement (see
    # docs\NinjaOne-API-Setup.md, "Credential storage").
    [string]$ClientId,
    [string]$ClientSecret,

    [string]$ClientIdSecretName = 'NinjaOne-ClientId',
    [string]$ClientSecretSecretName = 'NinjaOne-ClientSecret',

    [string]$Instance = 'us',   # Connect-NinjaOne takes a short region code (eu|oc|us|ca|us2), not a hostname - 'us' maps to app.ninjarmm.com
    [string[]]$Scopes = @('monitoring', 'management', 'control', 'offline_access'),

    [string]$ScriptName = 'Local-RightsInventory',
    [int]$ScriptId,

    [string]$DeviceFilter = 'class in (WINDOWS_SERVER)',

    [int]$MaxWaitMinutes = 10,
    [int]$PollIntervalSeconds = 20,
    [int]$ThrottleMilliseconds = 500,

    [string]$PayloadFieldName = 'rightsInventoryPayload',
    [string]$TimestampFieldName = 'rightsInventoryTimestamp',

    # Narrow -DeviceFilter's results to specific device names (exact, case-insensitive),
    # applied client-side after the API call. Use this for a single-device test run - the
    # NinjaOne device-filter query language does not reliably support name-based filtering
    # (confirmed 2026-09-14: 'name eq ...' / 'systemName eq ...' both return "No devices
    # found" even for a device -DeviceFilter alone returns).
    [string[]]$TargetSystemNames,

    [string]$OutputPath = (Join-Path $PSScriptRoot 'output')
)

Import-Module NinjaOne -ErrorAction Stop

# --- Resolve credentials -----------------------------------------------------------
# Prefer SecretManagement (local SecretStore today; swaps to Keeper's SecretManagement.Keeper
# vault later with no script changes) over explicit parameters, which exist mainly for
# one-off/manual testing.
if (-not $ClientId -or -not $ClientSecret) {
    if (-not (Get-Module -ListAvailable -Name Microsoft.PowerShell.SecretManagement)) {
        throw 'No -ClientId/-ClientSecret supplied and Microsoft.PowerShell.SecretManagement is not available to resolve them. Either pass credentials explicitly or set up the secret vault - see docs\NinjaOne-API-Setup.md.'
    }
    Import-Module Microsoft.PowerShell.SecretManagement -ErrorAction Stop

    if (-not $ClientId) {
        $ClientId = Get-Secret -Name $ClientIdSecretName -AsPlainText -ErrorAction Stop
    }
    if (-not $ClientSecret) {
        $ClientSecret = Get-Secret -Name $ClientSecretSecretName -AsPlainText -ErrorAction Stop
    }
}

if (-not (Test-Path $OutputPath)) {
    New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
}
$RunStamp = Get-Date -Format 'yyyyMMdd_HHmmss'

function Get-NinjaFieldText {
    # A WYSIWYG-type custom field's value comes back as an object ({text, html}), not a plain
    # string - confirmed 2026-09-14 against a live device. A Text-type field returns a plain
    # string. Normalize both to a string here so callers don't need to care which field type
    # is configured.
    param($FieldValue)
    if ($null -eq $FieldValue) { return $null }
    if ($FieldValue -is [string]) { return $FieldValue }
    if ($FieldValue.PSObject.Properties['text']) { return $FieldValue.text }
    return $FieldValue.ToString()
}

function Expand-Base64GzipString {
    param([string]$Base64)
    if ([string]::IsNullOrWhiteSpace($Base64)) { return $null }
    $bytes = [Convert]::FromBase64String($Base64)
    $msIn = New-Object System.IO.MemoryStream(, $bytes)
    $gzip = New-Object System.IO.Compression.GZipStream($msIn, [System.IO.Compression.CompressionMode]::Decompress)
    $msOut = New-Object System.IO.MemoryStream
    $gzip.CopyTo($msOut)
    return [System.Text.Encoding]::UTF8.GetString($msOut.ToArray())
}

# --- Connect --------------------------------------------------------------------
# NinjaOne's script-execution endpoint (POST /v2/device/{id}/script/run) requires a token
# with "user context" - confirmed 2026-09-14: a pure client-credentials (-UseClientAuth) token
# is rejected with "user_context_required" even though every read-only call works fine with
# it. User-context tokens only come from an interactive Authorization Code login, done once by
# a real NinjaOne user via NinjaOne\Initialize-NinjaOneUserContext.ps1 (not Connect-NinjaOne
# -UseWebAuth directly - its built-in listener has a hardcoded 15-second timeout, confirmed too
# short for a real login) - see docs\NinjaOne-API-Setup.md, "Enabling script execution
# (user-context auth)". That one-time login's refresh token is stored in SecretManagement under
# 'NinjaOneRefresh' and reused here indefinitely - Connect-NinjaOne rotates and re-saves it
# automatically each call via -WriteToSecretVault.
Write-Host "Connecting to NinjaOne ($Instance) ..." -ForegroundColor Cyan
$storedRefreshToken = $null
try {
    $storedRefreshToken = Get-Secret -Name 'NinjaOneRefresh' -AsPlainText -ErrorAction Stop
} catch { }

if ($storedRefreshToken) {
    # -ReadFromSecretVault alone does NOT wire the stored refresh token into the token-exchange
    # request (confirmed by reading NinjaOne.psm1: the exchange uses the -RefreshToken *parameter*
    # value, not the vault-populated script-scoped variable) - it must be passed explicitly.
    Write-Verbose 'Found a stored user-context refresh token - connecting with -UseTokenAuth (required for script execution).'
    Connect-NinjaOne -Instance $Instance -ClientId $ClientId -ClientSecret $ClientSecret -UseTokenAuth `
        -RefreshToken $storedRefreshToken `
        -UseSecretManagement -VaultName 'PGDLocalVault' -WriteToSecretVault -SecretPrefix 'NinjaOne' -Scopes $Scopes
} else {
    Write-Warning "No stored user-context token ('NinjaOneRefresh') found - connecting with -UseClientAuth instead. Reads will work, but Invoke-NinjaOneDeviceScript WILL FAIL with 'user_context_required'. See docs\NinjaOne-API-Setup.md, 'Enabling script execution (user-context auth)'."
    Connect-NinjaOne -Instance $Instance -ClientId $ClientId -ClientSecret $ClientSecret -UseClientAuth -Scopes $Scopes
}

# --- Resolve the Automation Library script id -----------------------------------
if (-not $ScriptId) {
    Write-Host "Resolving script id for '$ScriptName' ..."
    $match = Get-NinjaOneAutomationScripts | Where-Object { $_.name -eq $ScriptName } | Select-Object -First 1
    if (-not $match) {
        throw "No Automation Library script named '$ScriptName' was found. Paste NinjaOne\Local-RightsInventory.ps1 into the Automation Library first - see docs\NinjaOne-API-Setup.md."
    }
    $ScriptId = $match.id
}
Write-Host "  Using script id $ScriptId"

# --- Enumerate target devices ----------------------------------------------------
Write-Host "Enumerating devices matching filter: $DeviceFilter"
$devices = @(Get-NinjaOneDevices -deviceFilter $DeviceFilter -detailed)
Write-Host "  -> $($devices.Count) devices"

if ($TargetSystemNames) {
    $devices = @($devices | Where-Object { $_.systemName -in $TargetSystemNames })
    Write-Host "  -> $($devices.Count) after narrowing to -TargetSystemNames ($($TargetSystemNames -join ', '))"
}

if ($devices.Count -eq 0) {
    Write-Warning 'No devices matched - nothing to do.'
    return
}

# --- Capture "before" state, then invoke -------------------------------------------
$pending = [System.Collections.Generic.List[pscustomobject]]::new()
foreach ($device in $devices) {
    $before = $null
    try {
        $fields = Get-NinjaOneDeviceCustomFields -deviceId $device.id
        $before = Get-NinjaFieldText $fields.$TimestampFieldName
    } catch {
        Write-Warning "Could not read existing custom fields for $($device.systemName) (id $($device.id)): $_"
    }

    try {
        Invoke-NinjaOneDeviceScript -deviceId $device.id -type 'SCRIPT' -scriptId $ScriptId -runAs 'system'
        $pending.Add([pscustomobject]@{
            DeviceId       = $device.id
            SystemName     = $device.systemName
            OrganizationId = $device.organizationId
            BeforeStamp    = $before
            InvokedAt      = Get-Date
        })
    } catch {
        Write-Warning "Failed to invoke script on $($device.systemName) (id $($device.id)): $_"
    }

    Start-Sleep -Milliseconds $ThrottleMilliseconds
}
Write-Host "Invoked script on $($pending.Count) devices. Polling for completion (up to $MaxWaitMinutes min) ..."

# --- Poll for completion by watching the timestamp field change -------------------
$localGroupRows = [System.Collections.Generic.List[pscustomobject]]::new()
$userRightsRows = [System.Collections.Generic.List[pscustomobject]]::new()
$failures       = [System.Collections.Generic.List[pscustomobject]]::new()

$deadline = (Get-Date).AddMinutes($MaxWaitMinutes)
while ($pending.Count -gt 0 -and (Get-Date) -lt $deadline) {
    Start-Sleep -Seconds $PollIntervalSeconds
    $stillPending = [System.Collections.Generic.List[pscustomobject]]::new()

    foreach ($p in $pending) {
        try {
            $fields = Get-NinjaOneDeviceCustomFields -deviceId $p.DeviceId
        } catch {
            $stillPending.Add($p)
            continue
        }

        $currentStamp = Get-NinjaFieldText $fields.$TimestampFieldName
        if (-not $currentStamp -or $currentStamp -eq $p.BeforeStamp) {
            $stillPending.Add($p)
            continue
        }

        # Timestamp changed - a run completed. Decode and fold in the payload.
        try {
            $json = Expand-Base64GzipString -Base64 (Get-NinjaFieldText $fields.$PayloadFieldName)
            $result = $json | ConvertFrom-Json

            foreach ($g in $result.LocalGroups) {
                $localGroupRows.Add([pscustomobject]@{
                    DeviceId        = $p.DeviceId
                    SystemName      = $p.SystemName
                    OrganizationId  = $p.OrganizationId
                    CollectedUtc    = $result.CollectedUtc
                    LocalGroup      = $g.LocalGroup
                    MemberName      = $g.MemberName
                    MemberType      = $g.MemberType
                    PrincipalSource = $g.PrincipalSource
                })
            }
            foreach ($r in $result.UserRights) {
                $userRightsRows.Add([pscustomobject]@{
                    DeviceId       = $p.DeviceId
                    SystemName     = $p.SystemName
                    OrganizationId = $p.OrganizationId
                    CollectedUtc   = $result.CollectedUtc
                    Privilege      = $r.Privilege
                    Trustee        = $r.Trustee
                    SID            = $r.SID
                })
            }
            if ($result.Errors -and $result.Errors.Count -gt 0) {
                foreach ($e in $result.Errors) {
                    $failures.Add([pscustomobject]@{
                        DeviceId = $p.DeviceId; SystemName = $p.SystemName
                        Reason = "Collector reported: $e"
                    })
                }
            }
        } catch {
            $failures.Add([pscustomobject]@{
                DeviceId = $p.DeviceId; SystemName = $p.SystemName
                Reason = "Failed to decode/parse payload: $_"
            })
        }
    }

    $pending = $stillPending
    if ($pending.Count -gt 0) {
        Write-Host "  ... still waiting on $($pending.Count) device(s)"
    }
}

foreach ($p in $pending) {
    $failures.Add([pscustomobject]@{
        DeviceId = $p.DeviceId; SystemName = $p.SystemName
        Reason = "Timed out after $MaxWaitMinutes minutes waiting for $TimestampFieldName to update"
    })
}

# --- Export -------------------------------------------------------------------------
$localGroupRows | Export-Csv -NoTypeInformation -Path (Join-Path $OutputPath "NinjaLocalGroupMembers_$RunStamp.csv")
$userRightsRows | Export-Csv -NoTypeInformation -Path (Join-Path $OutputPath "NinjaUserRightsAssignment_$RunStamp.csv")
$failures       | Export-Csv -NoTypeInformation -Path (Join-Path $OutputPath "NinjaCollectionFailures_$RunStamp.csv")

Write-Host "`nDone." -ForegroundColor Green
Write-Host "  $($localGroupRows.Count) local group membership rows"
Write-Host "  $($userRightsRows.Count) user rights assignment rows"
Write-Host "  $($failures.Count) failures/timeouts (see NinjaCollectionFailures_$RunStamp.csv)"
Write-Host "  Reports written to $OutputPath"

# SIG # Begin signature block
# MIIsoAYJKoZIhvcNAQcCoIIskTCCLI0CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCCcC+6MT/t927Dc
# Q0pbFAzY8GtTj7XvS9i7afv2Or93O6CCJa8wggVvMIIEV6ADAgECAhBI/JO0YFWU
# jTanyYqJ1pQWMA0GCSqGSIb3DQEBDAUAMHsxCzAJBgNVBAYTAkdCMRswGQYDVQQI
# DBJHcmVhdGVyIE1hbmNoZXN0ZXIxEDAOBgNVBAcMB1NhbGZvcmQxGjAYBgNVBAoM
# EUNvbW9kbyBDQSBMaW1pdGVkMSEwHwYDVQQDDBhBQUEgQ2VydGlmaWNhdGUgU2Vy
# dmljZXMwHhcNMjEwNTI1MDAwMDAwWhcNMjgxMjMxMjM1OTU5WjBWMQswCQYDVQQG
# EwJHQjEYMBYGA1UEChMPU2VjdGlnbyBMaW1pdGVkMS0wKwYDVQQDEyRTZWN0aWdv
# IFB1YmxpYyBDb2RlIFNpZ25pbmcgUm9vdCBSNDYwggIiMA0GCSqGSIb3DQEBAQUA
# A4ICDwAwggIKAoICAQCN55QSIgQkdC7/FiMCkoq2rjaFrEfUI5ErPtx94jGgUW+s
# hJHjUoq14pbe0IdjJImK/+8Skzt9u7aKvb0Ffyeba2XTpQxpsbxJOZrxbW6q5KCD
# J9qaDStQ6Utbs7hkNqR+Sj2pcaths3OzPAsM79szV+W+NDfjlxtd/R8SPYIDdub7
# P2bSlDFp+m2zNKzBenjcklDyZMeqLQSrw2rq4C+np9xu1+j/2iGrQL+57g2extme
# me/G3h+pDHazJyCh1rr9gOcB0u/rgimVcI3/uxXP/tEPNqIuTzKQdEZrRzUTdwUz
# T2MuuC3hv2WnBGsY2HH6zAjybYmZELGt2z4s5KoYsMYHAXVn3m3pY2MeNn9pib6q
# RT5uWl+PoVvLnTCGMOgDs0DGDQ84zWeoU4j6uDBl+m/H5x2xg3RpPqzEaDux5mcz
# mrYI4IAFSEDu9oJkRqj1c7AGlfJsZZ+/VVscnFcax3hGfHCqlBuCF6yH6bbJDoEc
# QNYWFyn8XJwYK+pF9e+91WdPKF4F7pBMeufG9ND8+s0+MkYTIDaKBOq3qgdGnA2T
# OglmmVhcKaO5DKYwODzQRjY1fJy67sPV+Qp2+n4FG0DKkjXp1XrRtX8ArqmQqsV/
# AZwQsRb8zG4Y3G9i/qZQp7h7uJ0VP/4gDHXIIloTlRmQAOka1cKG8eOO7F/05QID
# AQABo4IBEjCCAQ4wHwYDVR0jBBgwFoAUoBEKIz6W8Qfs4q8p74Klf9AwpLQwHQYD
# VR0OBBYEFDLrkpr/NZZILyhAQnAgNpFcF4XmMA4GA1UdDwEB/wQEAwIBhjAPBgNV
# HRMBAf8EBTADAQH/MBMGA1UdJQQMMAoGCCsGAQUFBwMDMBsGA1UdIAQUMBIwBgYE
# VR0gADAIBgZngQwBBAEwQwYDVR0fBDwwOjA4oDagNIYyaHR0cDovL2NybC5jb21v
# ZG9jYS5jb20vQUFBQ2VydGlmaWNhdGVTZXJ2aWNlcy5jcmwwNAYIKwYBBQUHAQEE
# KDAmMCQGCCsGAQUFBzABhhhodHRwOi8vb2NzcC5jb21vZG9jYS5jb20wDQYJKoZI
# hvcNAQEMBQADggEBABK/oe+LdJqYRLhpRrWrJAoMpIpnuDqBv0WKfVIHqI0fTiGF
# OaNrXi0ghr8QuK55O1PNtPvYRL4G2VxjZ9RAFodEhnIq1jIV9RKDwvnhXRFAZ/ZC
# J3LFI+ICOBpMIOLbAffNRk8monxmwFE2tokCVMf8WPtsAO7+mKYulaEMUykfb9gZ
# pk+e96wJ6l2CxouvgKe9gUhShDHaMuwV5KZMPWw5c9QLhTkg4IUaaOGnSDip0TYl
# d8GNGRbFiExmfS9jzpjoad+sPKhdnckcW67Y8y90z7h+9teDnRGWYpquRRPaf9xH
# +9/DUp/mBlXpnYzyOmJRvOwkDynUWICE5EV7WtgwggWNMIIEdaADAgECAhAOmxiO
# +dAt5+/bUOIIQBhaMA0GCSqGSIb3DQEBDAUAMGUxCzAJBgNVBAYTAlVTMRUwEwYD
# VQQKEwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5jb20xJDAi
# BgNVBAMTG0RpZ2lDZXJ0IEFzc3VyZWQgSUQgUm9vdCBDQTAeFw0yMjA4MDEwMDAw
# MDBaFw0zMTExMDkyMzU5NTlaMGIxCzAJBgNVBAYTAlVTMRUwEwYDVQQKEwxEaWdp
# Q2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5jb20xITAfBgNVBAMTGERp
# Z2lDZXJ0IFRydXN0ZWQgUm9vdCBHNDCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCC
# AgoCggIBAL/mkHNo3rvkXUo8MCIwaTPswqclLskhPfKK2FnC4SmnPVirdprNrnsb
# hA3EMB/zG6Q4FutWxpdtHauyefLKEdLkX9YFPFIPUh/GnhWlfr6fqVcWWVVyr2iT
# cMKyunWZanMylNEQRBAu34LzB4TmdDttceItDBvuINXJIB1jKS3O7F5OyJP4IWGb
# NOsFxl7sWxq868nPzaw0QF+xembud8hIqGZXV59UWI4MK7dPpzDZVu7Ke13jrclP
# XuU15zHL2pNe3I6PgNq2kZhAkHnDeMe2scS1ahg4AxCN2NQ3pC4FfYj1gj4QkXCr
# VYJBMtfbBHMqbpEBfCFM1LyuGwN1XXhm2ToxRJozQL8I11pJpMLmqaBn3aQnvKFP
# ObURWBf3JFxGj2T3wWmIdph2PVldQnaHiZdpekjw4KISG2aadMreSx7nDmOu5tTv
# kpI6nj3cAORFJYm2mkQZK37AlLTSYW3rM9nF30sEAMx9HJXDj/chsrIRt7t/8tWM
# cCxBYKqxYxhElRp2Yn72gLD76GSmM9GJB+G9t+ZDpBi4pncB4Q+UDCEdslQpJYls
# 5Q5SUUd0viastkF13nqsX40/ybzTQRESW+UQUOsxxcpyFiIJ33xMdT9j7CFfxCBR
# a2+xq4aLT8LWRV+dIPyhHsXAj6KxfgommfXkaS+YHS312amyHeUbAgMBAAGjggE6
# MIIBNjAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBTs1+OC0nFdZEzfLmc/57qY
# rhwPTzAfBgNVHSMEGDAWgBRF66Kv9JLLgjEtUYunpyGd823IDzAOBgNVHQ8BAf8E
# BAMCAYYweQYIKwYBBQUHAQEEbTBrMCQGCCsGAQUFBzABhhhodHRwOi8vb2NzcC5k
# aWdpY2VydC5jb20wQwYIKwYBBQUHMAKGN2h0dHA6Ly9jYWNlcnRzLmRpZ2ljZXJ0
# LmNvbS9EaWdpQ2VydEFzc3VyZWRJRFJvb3RDQS5jcnQwRQYDVR0fBD4wPDA6oDig
# NoY0aHR0cDovL2NybDMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0QXNzdXJlZElEUm9v
# dENBLmNybDARBgNVHSAECjAIMAYGBFUdIAAwDQYJKoZIhvcNAQEMBQADggEBAHCg
# v0NcVec4X6CjdBs9thbX979XB72arKGHLOyFXqkauyL4hxppVCLtpIh3bb0aFPQT
# SnovLbc47/T/gLn4offyct4kvFIDyE7QKt76LVbP+fT3rDB6mouyXtTP0UNEm0Mh
# 65ZyoUi0mcudT6cGAxN3J0TU53/oWajwvy8LpunyNDzs9wPHh6jSTEAZNUZqaVSw
# uKFWjuyk1T3osdz9HNj0d1pcVIxv76FQPfx2CWiEn2/K2yCNNWAcAgPLILCsWKAO
# QGPFmCLBsln1VWvPJ6tsds5vIy30fnFqI2si/xK4VC0nftg62fC2h5b9W9FcrBjD
# TZ9ztwGpn1eqXijiuZQwggYcMIIEBKADAgECAhAz1wiokUBTGeKlu9M5ua1uMA0G
# CSqGSIb3DQEBDAUAMFYxCzAJBgNVBAYTAkdCMRgwFgYDVQQKEw9TZWN0aWdvIExp
# bWl0ZWQxLTArBgNVBAMTJFNlY3RpZ28gUHVibGljIENvZGUgU2lnbmluZyBSb290
# IFI0NjAeFw0yMTAzMjIwMDAwMDBaFw0zNjAzMjEyMzU5NTlaMFcxCzAJBgNVBAYT
# AkdCMRgwFgYDVQQKEw9TZWN0aWdvIExpbWl0ZWQxLjAsBgNVBAMTJVNlY3RpZ28g
# UHVibGljIENvZGUgU2lnbmluZyBDQSBFViBSMzYwggGiMA0GCSqGSIb3DQEBAQUA
# A4IBjwAwggGKAoIBgQC70f4et0JbePWQp64sg/GNIdMwhoV739PN2RZLrIXFuwHP
# 4owoEXIEdiyBxasSekBKxRDogRQ5G19PB/YwMDB/NSXlwHM9QAmU6Kj46zkLVdW2
# DIseJ/jePiLBv+9l7nPuZd0o3bsffZsyf7eZVReqskmoPBBqOsMhspmoQ9c7gqgZ
# YbU+alpduLyeE9AKnvVbj2k4aOqlH1vKI+4L7bzQHkNDbrBTjMJzKkQxbr6PuMYC
# 9ruCBBV5DFIg6JgncWHvL+T4AvszWbX0w1Xn3/YIIq620QlZ7AGfc4m3Q0/V8tm9
# VlkJ3bcX9sR0gLqHRqwG29sEDdVOuu6MCTQZlRvmcBMEJd+PuNeEM4xspgzraLqV
# T3xE6NRpjSV5wyHxNXf4T7YSVZXQVugYAtXueciGoWnxG06UE2oHYvDQa5mll1Ce
# HDOhHu5hiwVoHI717iaQg9b+cYWnmvINFD42tRKtd3V6zOdGNmqQU8vGlHHeBzoh
# +dYyZ+CcblSGoGSgg8sCAwEAAaOCAWMwggFfMB8GA1UdIwQYMBaAFDLrkpr/NZZI
# LyhAQnAgNpFcF4XmMB0GA1UdDgQWBBSBMpJBKyjNRsjEosYqORLsSKk/FDAOBgNV
# HQ8BAf8EBAMCAYYwEgYDVR0TAQH/BAgwBgEB/wIBADATBgNVHSUEDDAKBggrBgEF
# BQcDAzAaBgNVHSAEEzARMAYGBFUdIAAwBwYFZ4EMAQMwSwYDVR0fBEQwQjBAoD6g
# PIY6aHR0cDovL2NybC5zZWN0aWdvLmNvbS9TZWN0aWdvUHVibGljQ29kZVNpZ25p
# bmdSb290UjQ2LmNybDB7BggrBgEFBQcBAQRvMG0wRgYIKwYBBQUHMAKGOmh0dHA6
# Ly9jcnQuc2VjdGlnby5jb20vU2VjdGlnb1B1YmxpY0NvZGVTaWduaW5nUm9vdFI0
# Ni5wN2MwIwYIKwYBBQUHMAGGF2h0dHA6Ly9vY3NwLnNlY3RpZ28uY29tMA0GCSqG
# SIb3DQEBDAUAA4ICAQBfNqz7+fZyWhS38Asd3tj9lwHS/QHumS2G6Pa38Dn/1oFK
# WqdCSgotFZ3mlP3FaUqy10vxFhJM9r6QZmWLLXTUqwj3ahEDCHd8vmnhsNufJIkD
# 1t5cpOCy1rTP4zjVuW3MJ9bOZBHoEHJ20/ng6SyJ6UnTs5eWBgrh9grIQZqRXYHY
# NneYyoBBl6j4kT9jn6rNVFRLgOr1F2bTlHH9nv1HMePpGoYd074g0j+xUl+yk72M
# lQmYco+VAfSYQ6VK+xQmqp02v3Kw/Ny9hA3s7TSoXpUrOBZjBXXZ9jEuFWvilLIq
# 0nQ1tZiao/74Ky+2F0snbFrmuXZe2obdq2TWauqDGIgbMYL1iLOUJcAhLwhpAuNM
# u0wqETDrgXkG4UGVKtQg9guT5Hx2DJ0dJmtfhAH2KpnNr97H8OQYok6bLyoMZqaS
# dSa+2UA1E2+upjcaeuitHFFjBypWBmztfhj24+xkc6ZtCDaLrw+ZrnVrFyvCTWrD
# UUZBVumPwo3/E3Gb2u2e05+r5UWmEsUUWlJBl6MGAAjF5hzqJ4I8O9vmRsTvLQA1
# E802fZ3lqicIBczOwDYOSxlP0GOabb/FKVMxItt1UHeG0PL4au5rBhs+hSMrl8h+
# eplBDN1Yfw6owxI9OjWb4J0sjBeBVESoeh2YnZZ/WVimVGX/UUIL+Efrz/jlvzCC
# BrQwggScoAMCAQICEA3HrFcF/yGZLkBDIgw6SYYwDQYJKoZIhvcNAQELBQAwYjEL
# MAkGA1UEBhMCVVMxFTATBgNVBAoTDERpZ2lDZXJ0IEluYzEZMBcGA1UECxMQd3d3
# LmRpZ2ljZXJ0LmNvbTEhMB8GA1UEAxMYRGlnaUNlcnQgVHJ1c3RlZCBSb290IEc0
# MB4XDTI1MDUwNzAwMDAwMFoXDTM4MDExNDIzNTk1OVowaTELMAkGA1UEBhMCVVMx
# FzAVBgNVBAoTDkRpZ2lDZXJ0LCBJbmMuMUEwPwYDVQQDEzhEaWdpQ2VydCBUcnVz
# dGVkIEc0IFRpbWVTdGFtcGluZyBSU0E0MDk2IFNIQTI1NiAyMDI1IENBMTCCAiIw
# DQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBALR4MdMKmEFyvjxGwBysddujRmh0
# tFEXnU2tjQ2UtZmWgyxU7UNqEY81FzJsQqr5G7A6c+Gh/qm8Xi4aPCOo2N8S9SLr
# C6Kbltqn7SWCWgzbNfiR+2fkHUiljNOqnIVD/gG3SYDEAd4dg2dDGpeZGKe+42DF
# UF0mR/vtLa4+gKPsYfwEu7EEbkC9+0F2w4QJLVSTEG8yAR2CQWIM1iI5PHg62IVw
# xKSpO0XaF9DPfNBKS7Zazch8NF5vp7eaZ2CVNxpqumzTCNSOxm+SAWSuIr21Qomb
# +zzQWKhxKTVVgtmUPAW35xUUFREmDrMxSNlr/NsJyUXzdtFUUt4aS4CEeIY8y9Ia
# aGBpPNXKFifinT7zL2gdFpBP9qh8SdLnEut/GcalNeJQ55IuwnKCgs+nrpuQNfVm
# UB5KlCX3ZA4x5HHKS+rqBvKWxdCyQEEGcbLe1b8Aw4wJkhU1JrPsFfxW1gaou30y
# Z46t4Y9F20HHfIY4/6vHespYMQmUiote8ladjS/nJ0+k6MvqzfpzPDOy5y6gqzti
# T96Fv/9bH7mQyogxG9QEPHrPV6/7umw052AkyiLA6tQbZl1KhBtTasySkuJDpsZG
# Kdlsjg4u70EwgWbVRSX1Wd4+zoFpp4Ra+MlKM2baoD6x0VR4RjSpWM8o5a6D8bpf
# m4CLKczsG7ZrIGNTAgMBAAGjggFdMIIBWTASBgNVHRMBAf8ECDAGAQH/AgEAMB0G
# A1UdDgQWBBTvb1NK6eQGfHrK4pBW9i/USezLTjAfBgNVHSMEGDAWgBTs1+OC0nFd
# ZEzfLmc/57qYrhwPTzAOBgNVHQ8BAf8EBAMCAYYwEwYDVR0lBAwwCgYIKwYBBQUH
# AwgwdwYIKwYBBQUHAQEEazBpMCQGCCsGAQUFBzABhhhodHRwOi8vb2NzcC5kaWdp
# Y2VydC5jb20wQQYIKwYBBQUHMAKGNWh0dHA6Ly9jYWNlcnRzLmRpZ2ljZXJ0LmNv
# bS9EaWdpQ2VydFRydXN0ZWRSb290RzQuY3J0MEMGA1UdHwQ8MDowOKA2oDSGMmh0
# dHA6Ly9jcmwzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydFRydXN0ZWRSb290RzQuY3Js
# MCAGA1UdIAQZMBcwCAYGZ4EMAQQCMAsGCWCGSAGG/WwHATANBgkqhkiG9w0BAQsF
# AAOCAgEAF877FoAc/gc9EXZxML2+C8i1NKZ/zdCHxYgaMH9Pw5tcBnPw6O6FTGNp
# oV2V4wzSUGvI9NAzaoQk97frPBtIj+ZLzdp+yXdhOP4hCFATuNT+ReOPK0mCefSG
# +tXqGpYZ3essBS3q8nL2UwM+NMvEuBd/2vmdYxDCvwzJv2sRUoKEfJ+nN57mQfQX
# wcAEGCvRR2qKtntujB71WPYAgwPyWLKu6RnaID/B0ba2H3LUiwDRAXx1Neq9ydOa
# l95CHfmTnM4I+ZI2rVQfjXQA1WSjjf4J2a7jLzWGNqNX+DF0SQzHU0pTi4dBwp9n
# EC8EAqoxW6q17r0z0noDjs6+BFo+z7bKSBwZXTRNivYuve3L2oiKNqetRHdqfMTC
# W/NmKLJ9M+MtucVGyOxiDf06VXxyKkOirv6o02OoXN4bFzK0vlNMsvhlqgF2puE6
# FndlENSmE+9JGYxOGLS/D284NHNboDGcmWXfwXRy4kbu4QFhOm0xJuF2EZAOk5eC
# khSxZON3rGlHqhpB/8MluDezooIs8CVnrpHMiD2wL40mm53+/j7tFaxYKIqL0Q4s
# sd8xHZnIn/7GELH3IdvG2XlM9q7WP/UwgOkw/HQtyRN62JK4S1C8uw3PdBunvAZa
# psiI5YKdvlarEvf8EA+8hcpSM9LHJmyrxaFtoza2zNaQ9k+5t1wwggbeMIIFRqAD
# AgECAhAGan4e6YPA0G8haUrGz8OWMA0GCSqGSIb3DQEBCwUAMFcxCzAJBgNVBAYT
# AkdCMRgwFgYDVQQKEw9TZWN0aWdvIExpbWl0ZWQxLjAsBgNVBAMTJVNlY3RpZ28g
# UHVibGljIENvZGUgU2lnbmluZyBDQSBFViBSMzYwHhcNMjUwMTAyMDAwMDAwWhcN
# MjgwMTAyMjM1OTU5WjCBrjERMA8GA1UEBRMIMTg1ODMyNjAxEzARBgsrBgEEAYI3
# PAIBAxMCVVMxGDAWBgsrBgEEAYI3PAIBAhMHQXJpem9uYTEdMBsGA1UEDxMUUHJp
# dmF0ZSBPcmdhbml6YXRpb24xCzAJBgNVBAYTAlVTMRAwDgYDVQQIDAdBcml6b25h
# MRUwEwYDVQQKDAxJbkVpZ2h0LCBJbmMxFTATBgNVBAMMDEluRWlnaHQsIEluYzCC
# AiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBANiHPP9s/7ntSJwFAsoScqw5
# cQRGTmHuci5aAQfj2d2dIzII3UDutRbrxg9mh6gGDSs1NyKpUuSFZ2U8Ji0JaTGh
# nc4+kidT3QfiN8Wa8Pcoz4VcMY//ktXmn3zAv6t8ulj1IsEF6mVYpuQWpweQWzWk
# 5/Eov+bX7iSTbrBkfV9wpawQpTA2Z30IZ/2bkJJ7A5sL/Cu3LnwauYvqbBmaho+U
# omzXvtYJwKOa6NooVXNqpNevPdw+BskiugrnhbntuSfn9BqDLMghYbr6wiCHy80i
# ZG9yJ7N8YxPdUSzUrYOndZTOGtgfzEr/BHgT8mTepKEXy5hwEITrwhYJnsn19z6B
# tbfqX5V0GcuRP2wA2oTI2s3X7tSzb73M3bjjx45ePUsli8DDw7c0SMU9ZpLRrWhv
# 80AWBA+YaqbW/dEP7CIeXVwTlfKt8icWagCeC5M/UNJI0DLcth41fMb7bkEvPoPz
# pibaQdtsNN/tN29uNe0QSg19MjlvJEMZDc4wW4Fjq3cQkbqZuj3ox1Dsnw9bHdEe
# hawJZPNR4zAnAzbAQAYu8ebv2CrHHJHRSE9FSKmC42Tov9X4zhwHa2uP9QwjOiiR
# wDmakLstiH5jMJGGri0hjL8QmBirwlAOpHrNdPtIq9HnnnXi1TlVEZdbusrUhNb2
# bJC2xVD/5zyVQVbfsn+xAgMBAAGjggHMMIIByDAfBgNVHSMEGDAWgBSBMpJBKyjN
# RsjEosYqORLsSKk/FDAdBgNVHQ4EFgQUeruGnALQMx78XEbSGow4UbclPS4wDgYD
# VR0PAQH/BAQDAgeAMAwGA1UdEwEB/wQCMAAwEwYDVR0lBAwwCgYIKwYBBQUHAwMw
# SQYDVR0gBEIwQDA1BgwrBgEEAbIxAQIBBgEwJTAjBggrBgEFBQcCARYXaHR0cHM6
# Ly9zZWN0aWdvLmNvbS9DUFMwBwYFZ4EMAQMwSwYDVR0fBEQwQjBAoD6gPIY6aHR0
# cDovL2NybC5zZWN0aWdvLmNvbS9TZWN0aWdvUHVibGljQ29kZVNpZ25pbmdDQUVW
# UjM2LmNybDB7BggrBgEFBQcBAQRvMG0wRgYIKwYBBQUHMAKGOmh0dHA6Ly9jcnQu
# c2VjdGlnby5jb20vU2VjdGlnb1B1YmxpY0NvZGVTaWduaW5nQ0FFVlIzNi5jcnQw
# IwYIKwYBBQUHMAGGF2h0dHA6Ly9vY3NwLnNlY3RpZ28uY29tMD4GA1UdEQQ3MDWg
# IwYIKwYBBQUHCAOgFzAVDBNVUy1BUklaT05BLTE4NTgzMjYwgQ5pdEBpbmVpZ2h0
# LmNvbTANBgkqhkiG9w0BAQsFAAOCAYEAfPCuVhxoiBst2GQKDi8tbN9y9QJ4kjgm
# B6sfp84/C7LixxSOMLjtTh6QkmHkTibLAHdtwJ2cbQzM39in3a/JhF8lFwgih4N6
# 26Us+vAN5ZlASiHLxCGmeCw6XoYpZuVKJUGQqdh+CKDtMbSvJNnzBh1tuHli2WIz
# bb9WcfoaXp1fPn1UmsQa33YOtbpReMSc8L4bmL2kL1WzvbvN5cujBY7wK1/EBDIg
# WYgEHHcy2Q7xRajXrBtz85kqWYt1yjYaTyR3GJuRwA77XSHHRIJFI0hRhk9jp47u
# Qa/DDvdy3BDxeC0m777of1zow9UxYTqOs7iPe+1IzlctS3THUGsYn38kYaZ+v1Ah
# PFtUoMg+Onh4ZvZktXXpGkVg91LZ3Wy0q7LgZRdsd8IkEJUpZQcyejFW5VkjwYon
# htr/OylpECIxx3StudUXUZFTgoV3Za9xoNN+rpvHklvVlJQGM/RRXm8GYDd15OW5
# vRmVTN9mOpSydgucjsl5xkCJCeCbYQqeMIIG7TCCBNWgAwIBAgIQCE/cM09+RU7b
# ww+P+ZIYNTANBgkqhkiG9w0BAQsFADBpMQswCQYDVQQGEwJVUzEXMBUGA1UEChMO
# RGlnaUNlcnQsIEluYy4xQTA/BgNVBAMTOERpZ2lDZXJ0IFRydXN0ZWQgRzQgVGlt
# ZVN0YW1waW5nIFJTQTQwOTYgU0hBMjU2IDIwMjUgQ0ExMB4XDTI2MDgwNTAwMDAw
# MFoXDTM3MTEwNDIzNTk1OVowYzELMAkGA1UEBhMCVVMxFzAVBgNVBAoTDkRpZ2lD
# ZXJ0LCBJbmMuMTswOQYDVQQDEzJEaWdpQ2VydCBTSEEyNTYgUlNBNDA5NiBUaW1l
# c3RhbXAgUmVzcG9uZGVyIDIwMjYgMTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCC
# AgoCggIBALZ7pvLJ/s1K+NSbTGWz/TjGMPh8CQ6RucZCLv5anHzWJjF/NWJrFIhy
# 24fcpKXlgRiky4WAawDfU3YP0BMxt9l3Dm5oCG5Z69AqEN1kgHg2epx+l+lZBcmJ
# CcN0ASURML5uFIS80sZsDwO3BSkUxDjLJhBI+qiZP3aixAC/qEGLjsBNlLol9VZ7
# pfGEXiMlneJIC5/YKuizVzNFKZZEeoy/0B8Zm+nzKBgSWG52lCO1w+nCg6XpCtkl
# TJXeIg283hw7TmmsZXR+SMbjbrEOvZ3fP2VxIgeR28Y90ZStd3F9VuA5RVynb/wh
# ITPAo9b75Zr4Ta6Mj3URm26QZYMn/FnbuTegcoRcFEZ9FOqM5T6MTdtr/n74lIT/
# ug0eeOzmZ6QTFg33otX+bFRsIolvykE1jive4PuESaT8zzVeFWDAMDtozNgLctkG
# D1ZjkEyZtJrLl5ya0m5doH/ScpaZCZVl6pNUOCybMc/kxC6EAmSJY24L0yYKD1Nk
# ddsnb/ItVKi/2nXpQNMu1PT5prW83vV8d67WowuUs0HdY4H8AMLGvdL/WHEj3Znq
# MqAQQP9u3Ai9t+5eQ02GDwy0ODjdzi0xlp70W+ow63/0++YDEX1M0iwgUHwbrJvf
# pklkZQvw3+kv3vUPItdwroczk9icflf55W1zOEKAcJVAIXpcMCU9AgMBAAGjggGV
# MIIBkTAMBgNVHRMBAf8EAjAAMB0GA1UdDgQWBBQUyWOKMC7USvtulPPm40B+9ezN
# 4jAfBgNVHSMEGDAWgBTvb1NK6eQGfHrK4pBW9i/USezLTjAOBgNVHQ8BAf8EBAMC
# B4AwFgYDVR0lAQH/BAwwCgYIKwYBBQUHAwgwgZUGCCsGAQUFBwEBBIGIMIGFMCQG
# CCsGAQUFBzABhhhodHRwOi8vb2NzcC5kaWdpY2VydC5jb20wXQYIKwYBBQUHMAKG
# UWh0dHA6Ly9jYWNlcnRzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydFRydXN0ZWRHNFRp
# bWVTdGFtcGluZ1JTQTQwOTZTSEEyNTYyMDI1Q0ExLmNydDBfBgNVHR8EWDBWMFSg
# UqBQhk5odHRwOi8vY3JsMy5kaWdpY2VydC5jb20vRGlnaUNlcnRUcnVzdGVkRzRU
# aW1lU3RhbXBpbmdSU0E0MDk2U0hBMjU2MjAyNUNBMS5jcmwwIAYDVR0gBBkwFzAI
# BgZngQwBBAIwCwYJYIZIAYb9bAcBMA0GCSqGSIb3DQEBCwUAA4ICAQCNxTphHp1S
# Ct+ZrAmAfn0oQLFr0mLywSLaDXQIENoyKqxrFbJblzCVP/pkXmwXOdrOpWygLzlT
# 12os5ipDCy35RBCg2UMeApEtrfGhz45F4Wt4WGdNdIbRWt3YTYJmpR+b7lr4d7Uw
# n+H600u4D7RnOGf8Wj4UNgAdZkfHhHv1mx9EVh71SJelcEN/oORSjXzdjfw1iZH9
# d8Nh/thn6hH23d+VsPAr6GAYyzSA02nXD1nYLI7Ijmiv+xLCiYC41DSFYL3GhTiy
# 0PxpawPtGRyaBVGzq+UiTfM8pD7KVyF5aQyWP4KhVGUUTnmm/RlYJoW3TiXA/+t0
# YcT2oRVBm3JETjajHug2AL+v5jhtKVnd3D0rbHXEu27o+Q8p4sEWPMqKDB+qbceb
# 6T/6WcwTwXmQ9lOCLLYcsQeSWmvKqzpAec9etE14jOQAzLKWdE3w/TCaKtLRaRT7
# LCkRYVnhA2D73FLje1O5b3HR5eHs0NzU/+xX7NbEdcofy0W3Wdwd1XOqtlpg/Jgw
# tKfZM5dqO94lbUveOiJBI+xZEbGRsMNbXmMREUTgu+Oca7Y73MPWcslIx2VhkSKS
# XjDbD6rgg39H5Mh7QfieAIjWagkJNt68Yfim6cjEzVSiLSeZfdkr5dtFPTW6jATl
# WJdYeeDRGCyatf8R1hSjzSvdN8yWQPT9gzGCBkcwggZDAgEBMGswVzELMAkGA1UE
# BhMCR0IxGDAWBgNVBAoTD1NlY3RpZ28gTGltaXRlZDEuMCwGA1UEAxMlU2VjdGln
# byBQdWJsaWMgQ29kZSBTaWduaW5nIENBIEVWIFIzNgIQBmp+HumDwNBvIWlKxs/D
# ljANBglghkgBZQMEAgEFAKCBhDAYBgorBgEEAYI3AgEMMQowCKACgAChAoAAMBkG
# CSqGSIb3DQEJAzEMBgorBgEEAYI3AgEEMBwGCisGAQQBgjcCAQsxDjAMBgorBgEE
# AYI3AgEVMC8GCSqGSIb3DQEJBDEiBCD4sMMQVXqkSN3y9KxBofsqD1SMw95RDeFa
# QeqxegDRSTANBgkqhkiG9w0BAQEFAASCAgDFgVDXsb0PErX4A9UB5c9A4PI4EbWY
# vlIchblw/eX1xxEVbnf+lhCzkVyYNUEwoFPWlYgRKnP2Qaw/AtE3HmXdBqU4BLUQ
# yoo+OjsI9PXXiHwlZ1peyALmjov8ODnF22Zgg1ICV4O2p8pFtmwPnijuICKmiI05
# RQoR83tfrjibkawfUcUQdl2D+Gxc/sjySx6oQb2dCI+w8OB4c9qlYAGaW29q/xOQ
# Jj4ffa3DrJ1itc9Wgm8Uhl39d6g+LAn+eLEOtH0uXcULd6H+BncrlbXfaYXcVQ4q
# rczHGpAUlRG4EskIQoDbXETBo6MwaoZUzHFLD+WZd+96pImGIfZJ+9cvQrSZsDD7
# fPhdBHA2pEKY1+k3ZJQ9tvM1vhGsRmLiH64+kssCuD9OaPOz8PCWEO5tdgFirmkl
# mrJceho1/vC7ImcwC0ijAcLOy2xB5H82VAsLIogUhRNqbij+UCT/NDfF5ESn1QWD
# EOVrTo0xvlv+yc1hxalULsR0dN0j3yjRRM3zIW+Y4b3/RF6lzCbsC4jseuBZJIht
# XnjWRJ1fjOFp8PaSCR5x9nv2WI9//swmqo389XFewjjCW81PO99B/vg1GCD+Gx+L
# cjTmf+FLdlOQhtqBMIdVrqRNUPs0pMZ7vXf4TzFHOgGaHLSez3zebeGR+KwOxDQj
# yBuH84MhOGBuRqGCAyYwggMiBgkqhkiG9w0BCQYxggMTMIIDDwIBATB9MGkxCzAJ
# BgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwgSW5jLjFBMD8GA1UEAxM4RGln
# aUNlcnQgVHJ1c3RlZCBHNCBUaW1lU3RhbXBpbmcgUlNBNDA5NiBTSEEyNTYgMjAy
# NSBDQTECEAhP3DNPfkVO28MPj/mSGDUwDQYJYIZIAWUDBAIBBQCgaTAYBgkqhkiG
# 9w0BCQMxCwYJKoZIhvcNAQcBMBwGCSqGSIb3DQEJBTEPFw0yNjA5MTQyMjQwNDRa
# MC8GCSqGSIb3DQEJBDEiBCBeTDPIzD49lvslgyVyc1a1kvcjulHQfJJ0Kto/h6a7
# ZjANBgkqhkiG9w0BAQEFAASCAgBLioWuLRmibvkzrSjzIgOx6KBjq2BMu8W+RMj6
# JOXYXWJ5mZJFrCDO0S7KJhCxcGh5VT5VXLUtHnYXIMwfZRkus1WBRHmYvYvR7cCN
# oEvumYoBoQS62uXFFaL+EvaT48i/vGexM3uAkC6xToPgzBnje1SnCDxDGyZF60Tl
# nfPUIYAuK1mS/H4yimojzB0S75lcOpvq9g6AtT5XYjJ59PCo61urQigTKrtIzPWU
# qtDT4AuTFz4f9l8Mc8KCrnydSEub2MdD3Bl/MRwZv7OSPfbWN09UFALA7xZNOfdb
# PcnEmqLbWkVWLfyKI28LgGlTj+o/oWsZma53Hkls8eROlpTfosekJtU/tGTPYFCz
# NR4KALR1V6ktJ2uG/gA0EQFZTOJka8BpBFP9uJ3HxM8oy/uNJqPhf+MOWuIFZ80f
# lBkc1zf/uoB8d1oqnKFm3W0iEDfbaTyCTJn1A4e4o6ptXe1oaRvUcSMsuBSSRTNR
# 4VxJlteebDIzZTcbZe++ABW57NpHrZEJL7OcxkhjBqBR3Fqdy6KKk/9qCbL8ojPb
# nmvAi6xgFkHG77HGEXfAiJBpwu3OrGojlxYw3ilj7rHDTUjwYYVnDrlsoRQPgoZQ
# yzeljpft87k6Z9Tf8pelIixijtXjsEVhWGDmeReRudnenuaazumUR5bhDlSvUat3
# IQJGDg==
# SIG # End signature block
