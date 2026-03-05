<#
.SYNOPSIS
    Audits Entra ID Global Administrators (active and PIM-eligible) and all active
    Entra ID Member users, then uploads the resulting CSV files to a SharePoint folder.

.DESCRIPTION
    Run-EntraUserAudit uses the Microsoft Graph REST API with client-credential
    (application) authentication — no interactive sign-in required.

    It produces two CSV files and uploads them to a specified SharePoint Online folder:

        AuditEntraAdministrators_<yyyyMMdd_HHmmss>.csv
            Columns: Id, DisplayName, UserPrincipalName, CreatedDateTime,
                     AccountEnabled, AssignmentType

        AuditEntraUsers_<yyyyMMdd_HHmmss>.csv
            Columns: Id, DisplayName, UserPrincipalName, CreatedDateTime,
                     AccountEnabled, Roles

    User role resolution is performed via the Graph JSON Batch endpoint (20 users per
    request) to minimise execution time in large tenants.

.REQUIRED MODULES
    None — all interactions use Invoke-RestMethod against the Microsoft Graph REST API.
    No PowerShell SDK modules need to be installed.

.REQUIRED API PERMISSIONS (Application — on the App Registration)
    Microsoft Graph:
        User.Read.All              — Read all user profiles
        RoleManagement.Read.All    — Read directory role memberships and PIM schedules
        Directory.Read.All         — Read directory roles
        Sites.ReadWrite.All        — Upload files to SharePoint
            (Alternatively use Sites.Selected for least-privilege access limited
             to the specific SharePoint site.)

.PARAMETER TenantId
    Azure AD / Entra ID Tenant ID (GUID).

.PARAMETER ClientId
    Application (Client) ID of the App Registration.

.PARAMETER ClientSecret
    Client secret value for the App Registration.

.PARAMETER GlobalAdminRoleId
    The OBJECT ID of the Global Administrator directory role in your tenant.
    This value is used to enumerate ACTIVE Global Administrators via
    GET /directoryRoles/{id}/members.
    Defaults to 68f97962-6168-438e-82ca-ee2fa01a40c3.
    Note: Unlike role definition IDs, directory role object IDs can vary per tenant.
    Verify this value via: GET https://graph.microsoft.com/v1.0/directoryRoles

.PARAMETER PimRoleDefinitionId
    The ROLE DEFINITION ID for the Global Administrator role used to query
    PIM-eligible assignments via GET /roleManagement/directory/roleEligibilitySchedules.
    This ID is consistent across all tenants for the Global Administrator role.
    Defaults to 62e90394-69f5-4237-9190-012177145e10.

.PARAMETER SharePointSiteUrl
    Full URL of the SharePoint site where CSV files will be uploaded.
    Example: https://contoso.sharepoint.com/sites/IT

.PARAMETER SharePointFolderPath
    Path to the target folder within the site's default document library.
    Example: Shared Documents/Audits
    Leading and trailing slashes are handled automatically.

.EXAMPLE
    # Dot-source the file to load the function into the current session
    . .\Run-EntraUserAudit.ps1

    # Run the audit
    Run-EntraUserAudit `
        -TenantId       "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" `
        -ClientId       "yyyyyyyy-yyyy-yyyy-yyyy-yyyyyyyyyyyy" `
        -ClientSecret   "your-client-secret-value" `
        -SharePointSiteUrl    "https://contoso.sharepoint.com/sites/IT" `
        -SharePointFolderPath "Shared Documents/Audits"

.EXAMPLE
    # Override both role IDs if your tenant uses different values
    Run-EntraUserAudit `
        -TenantId             "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" `
        -ClientId             "yyyyyyyy-yyyy-yyyy-yyyy-yyyyyyyyyyyy" `
        -ClientSecret         "your-client-secret-value" `
        -GlobalAdminRoleId    "68f97962-6168-438e-82ca-ee2fa01a40c3" `
        -PimRoleDefinitionId  "62e90394-69f5-4237-9190-012177145e10" `
        -SharePointSiteUrl    "https://contoso.sharepoint.com/sites/IT" `
        -SharePointFolderPath "Shared Documents/Audits"

.NOTES
    Author  : TechOps
    Version : 1.0.0
    Created : 2026-03-05

    To confirm your tenant's Global Administrator directory role object ID, run:
        Invoke-RestMethod `
            -Uri     "https://graph.microsoft.com/v1.0/directoryRoles" `
            -Headers @{ Authorization = "Bearer <token>" } |
        Select-Object -ExpandProperty value |
        Where-Object { $_.displayName -eq 'Global Administrator' } |
        Select-Object id, displayName
#>

function Run-EntraUserAudit {
    [CmdletBinding()]
    param (
        # ── Authentication ──────────────────────────────────────────────────────
        [Parameter(Mandatory = $true, HelpMessage = "Entra ID Tenant ID (GUID)")]
        [ValidateNotNullOrEmpty()]
        [string]$TenantId,

        [Parameter(Mandatory = $true, HelpMessage = "App Registration Client ID (GUID)")]
        [ValidateNotNullOrEmpty()]
        [string]$ClientId,

        [Parameter(Mandatory = $true, HelpMessage = "App Registration Client Secret")]
        [ValidateNotNullOrEmpty()]
        [string]$ClientSecret,

        # ── Role IDs ────────────────────────────────────────────────────────────
        [Parameter(HelpMessage = "Object ID of the Global Administrator directory role in your tenant")]
        [string]$GlobalAdminRoleId = "68f97962-6168-438e-82ca-ee2fa01a40c3",

        [Parameter(HelpMessage = "Role Definition ID used to query PIM-eligible Global Administrator assignments")]
        [string]$PimRoleDefinitionId = "62e90394-69f5-4237-9190-012177145e10",

        # ── SharePoint destination ───────────────────────────────────────────────
        [Parameter(Mandatory = $true, HelpMessage = "Full SharePoint site URL, e.g. https://contoso.sharepoint.com/sites/IT")]
        [ValidateNotNullOrEmpty()]
        [string]$SharePointSiteUrl,

        [Parameter(Mandatory = $true, HelpMessage = "Folder path within the site's default document library, e.g. Shared Documents/Audits")]
        [ValidateNotNullOrEmpty()]
        [string]$SharePointFolderPath
    )

    #region ── Internal helper functions ──────────────────────────────────────────

    <#
    .SYNOPSIS
        Acquires an OAuth 2.0 client-credentials access token from Microsoft identity platform.
    #>
    function Get-GraphAccessToken {
        param (
            [string]$TenantId,
            [string]$ClientId,
            [string]$ClientSecret,
            [string]$Scope = "https://graph.microsoft.com/.default"
        )

        $tokenUri = "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token"
        $body = @{
            grant_type    = "client_credentials"
            client_id     = $ClientId
            client_secret = $ClientSecret
            scope         = $Scope
        }

        try {
            $response = Invoke-RestMethod `
                -Uri         $tokenUri `
                -Method      Post `
                -Body        $body `
                -ContentType "application/x-www-form-urlencoded" `
                -ErrorAction Stop
            return $response.access_token
        }
        catch {
            throw "Failed to acquire access token from $tokenUri.`n$_"
        }
    }

    <#
    .SYNOPSIS
        Calls a Graph API endpoint and automatically follows @odata.nextLink
        pagination, returning all results as a flat array.
    #>
    function Invoke-GraphPagedRequest {
        param (
            [string]$AccessToken,
            [string]$Uri
        )

        $headers = @{ Authorization = "Bearer $AccessToken" }
        $results  = [System.Collections.Generic.List[object]]::new()
        $nextLink = $Uri

        do {
            try {
                $response = Invoke-RestMethod `
                    -Uri     $nextLink `
                    -Headers $headers `
                    -Method  Get `
                    -ErrorAction Stop
            }
            catch {
                throw "Graph API request failed.`n  URI : $nextLink`n  Error : $_"
            }

            if ($null -ne $response.value) {
                foreach ($item in $response.value) { $results.Add($item) }
            }

            $nextLink = $response.'@odata.nextLink'
        } while ($nextLink)

        return $results.ToArray()
    }

    <#
    .SYNOPSIS
        Uploads a string (CSV content) to a SharePoint Online folder via the
        Graph Files API, creating the upload path if it does not exist.
    #>
    function Upload-CsvToSharePoint {
        param (
            [string]$AccessToken,
            [string]$SiteUrl,
            [string]$FolderPath,
            [string]$FileName,
            [string]$CsvContent
        )

        # ── Resolve the SharePoint site ID ──────────────────────────────────────
        $uri      = [System.Uri]$SiteUrl
        $hostname = $uri.Host

        # AbsolutePath for https://tenant.sharepoint.com/sites/IT  →  /sites/IT
        $sitePath = $uri.AbsolutePath.Trim('/')

        $siteApiUrl = "https://graph.microsoft.com/v1.0/sites/${hostname}:/${sitePath}"
        $authHeader = @{ Authorization = "Bearer $AccessToken" }

        try {
            $siteObj = Invoke-RestMethod -Uri $siteApiUrl -Headers $authHeader -Method Get -ErrorAction Stop
            $siteId  = $siteObj.id
        }
        catch {
            throw "Could not resolve SharePoint site '$SiteUrl'.`nEnsure the App Registration has Sites.ReadWrite.All (or Sites.Selected) permission.`n  Error : $_"
        }

        # ── Build the upload URL ─────────────────────────────────────────────────
        # Graph drive upload path: /sites/{id}/drive/root:/{folder}/{file}:/content
        $cleanFolder = $FolderPath.Trim('/')
        $uploadUri   = "https://graph.microsoft.com/v1.0/sites/$siteId/drive/root:/$cleanFolder/$FileName`:/content"

        $uploadHeaders = @{
            Authorization  = "Bearer $AccessToken"
            "Content-Type" = "text/csv; charset=utf-8"
        }

        # Convert string to UTF-8 bytes (preserves special characters in UPNs, names)
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($CsvContent)

        try {
            Invoke-RestMethod `
                -Uri     $uploadUri `
                -Method  Put `
                -Headers $uploadHeaders `
                -Body    $bytes `
                -ErrorAction Stop | Out-Null
        }
        catch {
            throw "Upload failed for '$FileName'.`n  URI : $uploadUri`n  Error : $_"
        }
    }

    #endregion

    #region ── Authentication ──────────────────────────────────────────────────────

    Write-Host "[1/5] Acquiring Graph API access token..." -ForegroundColor Cyan

    $token     = Get-GraphAccessToken -TenantId $TenantId -ClientId $ClientId -ClientSecret $ClientSecret
    $graphBase = "https://graph.microsoft.com/v1.0"
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"

    Write-Host "      Token acquired successfully." -ForegroundColor Green

    #endregion

    #region ── Admin Audit ─────────────────────────────────────────────────────────

    Write-Host "[2/5] Querying Global Administrators..." -ForegroundColor Cyan

    # ── Active Global Administrators ─────────────────────────────────────────────
    # Endpoint: GET /directoryRoles/{objectId}/members
    # Returns all users, groups, and service principals currently assigned the role.
    $activeMembers = Invoke-GraphPagedRequest `
        -AccessToken $token `
        -Uri         "$graphBase/directoryRoles/$GlobalAdminRoleId/members"

    $activeAdmins = foreach ($member in $activeMembers) {
        # Limit to user objects only (skip groups, service principals, etc.)
        if ($member.userPrincipalName -or $member.'@odata.type' -eq '#microsoft.graph.user') {
            [PSCustomObject]@{
                Id                = $member.id
                DisplayName       = $member.displayName
                UserPrincipalName = $member.userPrincipalName
                CreatedDateTime   = $member.createdDateTime
                AccountEnabled    = $member.accountEnabled
                AssignmentType    = "Active"
            }
        }
    }

    Write-Host "      Active Global Administrators   : $(@($activeAdmins).Count)" -ForegroundColor Gray

    # ── PIM-Eligible Global Administrators ───────────────────────────────────────
    # Endpoint: GET /roleManagement/directory/roleEligibilitySchedules
    # $expand=principal avoids a second round-trip per eligible assignment.
    $encodedPimFilter = [System.Uri]::EscapeDataString("roleDefinitionId eq '$PimRoleDefinitionId'")
    $eligibleSchedules = Invoke-GraphPagedRequest `
        -AccessToken $token `
        -Uri         "$graphBase/roleManagement/directory/roleEligibilitySchedules?`$filter=$encodedPimFilter&`$expand=principal"

    $eligibleAdmins = foreach ($schedule in $eligibleSchedules) {
        $p = $schedule.principal
        if ($p -and ($p.userPrincipalName -or $p.'@odata.type' -eq '#microsoft.graph.user')) {
            [PSCustomObject]@{
                Id                = $p.id
                DisplayName       = $p.displayName
                UserPrincipalName = $p.userPrincipalName
                CreatedDateTime   = $p.createdDateTime
                AccountEnabled    = $p.accountEnabled
                AssignmentType    = "Eligible (PIM)"
            }
        }
    }

    Write-Host "      PIM-Eligible Global Admins     : $(@($eligibleAdmins).Count)" -ForegroundColor Gray

    # ── Deduplicate — a user may appear in both lists ─────────────────────────────
    $combinedAdmins = (@($activeAdmins) + @($eligibleAdmins)) |
        Group-Object -Property Id |
        ForEach-Object {
            if ($_.Count -gt 1) {
                # Present in both lists; merge the AssignmentType value
                $base = $_.Group[0]
                [PSCustomObject]@{
                    Id                = $base.Id
                    DisplayName       = $base.DisplayName
                    UserPrincipalName = $base.UserPrincipalName
                    CreatedDateTime   = $base.CreatedDateTime
                    AccountEnabled    = $base.AccountEnabled
                    AssignmentType    = "Active; Eligible (PIM)"
                }
            }
            else {
                $_.Group[0]
            }
        }

    Write-Host "      Total unique admin accounts    : $(@($combinedAdmins).Count)" -ForegroundColor Green

    # Build CSV content in memory (no temp file required)
    $adminCsvName    = "AuditEntraAdministrators_$timestamp.csv"
    $adminCsvContent = $combinedAdmins |
        Select-Object Id, DisplayName, UserPrincipalName, CreatedDateTime, AccountEnabled, AssignmentType |
        ConvertTo-Csv -NoTypeInformation |
        Out-String

    #endregion

    #region ── User Audit ──────────────────────────────────────────────────────────

    Write-Host "[3/5] Querying active Entra ID Member users..." -ForegroundColor Cyan

    # Retrieve all active, non-guest accounts
    # $select limits the payload; $filter excludes disabled and guest accounts
    $userFilter = [System.Uri]::EscapeDataString("accountEnabled eq true and userType eq 'Member'")
    $userSelect = "id,displayName,userPrincipalName,createdDateTime,accountEnabled"

    $activeUsers = Invoke-GraphPagedRequest `
        -AccessToken $token `
        -Uri         "$graphBase/users?`$filter=$userFilter&`$select=$userSelect"

    Write-Host "      Active member users found      : $(@($activeUsers).Count)" -ForegroundColor Gray
    Write-Host "[4/5] Resolving role assignments (Graph batch, 20 users/request)..." -ForegroundColor Cyan
    Write-Host "      This may take several minutes for large tenants." -ForegroundColor Yellow

    $userDetailsWithRoles = [System.Collections.Generic.List[object]]::new()
    $batchSize            = 20

    for ($i = 0; $i -lt $activeUsers.Count; $i += $batchSize) {
        $end   = [Math]::Min($i + $batchSize - 1, $activeUsers.Count - 1)
        $chunk = $activeUsers[$i..$end]

        # Build a JSON Batch request — one sub-request per user, asking for their
        # directory role memberships only (microsoft.graph.directoryRole cast).
        $batchRequests = foreach ($user in $chunk) {
            @{
                id     = $user.id
                method = "GET"
                url    = "/users/$($user.id)/memberOf/microsoft.graph.directoryRole?`$select=displayName"
            }
        }

        $batchPayload = @{ requests = $batchRequests } | ConvertTo-Json -Depth 10
        $batchHeaders = @{
            Authorization  = "Bearer $token"
            "Content-Type" = "application/json"
        }

        try {
            $batchResult = Invoke-RestMethod `
                -Uri         "$graphBase/`$batch" `
                -Method      Post `
                -Headers     $batchHeaders `
                -Body        $batchPayload `
                -ErrorAction Stop
        }
        catch {
            Write-Warning "Batch request failed for users at index $i — skipping chunk. Error: $_"
            continue
        }

        # Index responses by their ID (which equals the user's GUID)
        $responseMap = @{}
        foreach ($resp in $batchResult.responses) {
            $responseMap[$resp.id] = $resp
        }

        foreach ($user in $chunk) {
            $resp  = $responseMap[$user.id]
            $roles = @()

            if ($resp -and $resp.status -eq 200 -and $resp.body.value) {
                $roles = $resp.body.value | ForEach-Object { $_.displayName }
            }

            $userDetailsWithRoles.Add([PSCustomObject]@{
                Id                = $user.id
                DisplayName       = $user.displayName
                UserPrincipalName = $user.userPrincipalName
                CreatedDateTime   = $user.createdDateTime
                AccountEnabled    = $user.accountEnabled
                Roles             = ($roles -join "; ")
            })
        }

        $processed = $end + 1
        Write-Progress `
            -Activity        "Resolving user role assignments" `
            -Status          "$processed of $($activeUsers.Count) users processed" `
            -PercentComplete ([Math]::Round(($processed / $activeUsers.Count) * 100))
    }

    Write-Progress -Activity "Resolving user role assignments" -Completed
    Write-Host "      Role resolution complete       : $($userDetailsWithRoles.Count) users" -ForegroundColor Green

    $userCsvName    = "AuditEntraUsers_$timestamp.csv"
    $userCsvContent = $userDetailsWithRoles |
        Select-Object Id, DisplayName, UserPrincipalName, CreatedDateTime, AccountEnabled, Roles |
        ConvertTo-Csv -NoTypeInformation |
        Out-String

    #endregion

    #region ── SharePoint Upload ───────────────────────────────────────────────────

    Write-Host "[5/5] Uploading CSV files to SharePoint..." -ForegroundColor Cyan
    Write-Host "      Site   : $SharePointSiteUrl" -ForegroundColor Gray
    Write-Host "      Folder : $SharePointFolderPath" -ForegroundColor Gray

    Upload-CsvToSharePoint `
        -AccessToken $token `
        -SiteUrl     $SharePointSiteUrl `
        -FolderPath  $SharePointFolderPath `
        -FileName    $adminCsvName `
        -CsvContent  $adminCsvContent

    Write-Host "      Uploaded : $adminCsvName" -ForegroundColor Green

    Upload-CsvToSharePoint `
        -AccessToken $token `
        -SiteUrl     $SharePointSiteUrl `
        -FolderPath  $SharePointFolderPath `
        -FileName    $userCsvName `
        -CsvContent  $userCsvContent

    Write-Host "      Uploaded : $userCsvName" -ForegroundColor Green

    #endregion

    Write-Host ""
    Write-Host "Audit complete." -ForegroundColor Green
    Write-Host "  $adminCsvName  →  $SharePointSiteUrl/$SharePointFolderPath" -ForegroundColor Green
    Write-Host "  $userCsvName   →  $SharePointSiteUrl/$SharePointFolderPath" -ForegroundColor Green
}

# SIG # Begin signature block
# MIIsoAYJKoZIhvcNAQcCoIIskTCCLI0CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCC6lQFOPQLn3yxx
# IG9fCjJv/6haxDL0t32zPdCQrDop7aCCJa8wggVvMIIEV6ADAgECAhBI/JO0YFWU
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
# vRmVTN9mOpSydgucjsl5xkCJCeCbYQqeMIIG7TCCBNWgAwIBAgIQCoDvGEuN8QWC
# 0cR2p5V0aDANBgkqhkiG9w0BAQsFADBpMQswCQYDVQQGEwJVUzEXMBUGA1UEChMO
# RGlnaUNlcnQsIEluYy4xQTA/BgNVBAMTOERpZ2lDZXJ0IFRydXN0ZWQgRzQgVGlt
# ZVN0YW1waW5nIFJTQTQwOTYgU0hBMjU2IDIwMjUgQ0ExMB4XDTI1MDYwNDAwMDAw
# MFoXDTM2MDkwMzIzNTk1OVowYzELMAkGA1UEBhMCVVMxFzAVBgNVBAoTDkRpZ2lD
# ZXJ0LCBJbmMuMTswOQYDVQQDEzJEaWdpQ2VydCBTSEEyNTYgUlNBNDA5NiBUaW1l
# c3RhbXAgUmVzcG9uZGVyIDIwMjUgMTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCC
# AgoCggIBANBGrC0Sxp7Q6q5gVrMrV7pvUf+GcAoB38o3zBlCMGMyqJnfFNZx+wvA
# 69HFTBdwbHwBSOeLpvPnZ8ZN+vo8dE2/pPvOx/Vj8TchTySA2R4QKpVD7dvNZh6w
# W2R6kSu9RJt/4QhguSssp3qome7MrxVyfQO9sMx6ZAWjFDYOzDi8SOhPUWlLnh00
# Cll8pjrUcCV3K3E0zz09ldQ//nBZZREr4h/GI6Dxb2UoyrN0ijtUDVHRXdmncOOM
# A3CoB/iUSROUINDT98oksouTMYFOnHoRh6+86Ltc5zjPKHW5KqCvpSduSwhwUmot
# uQhcg9tw2YD3w6ySSSu+3qU8DD+nigNJFmt6LAHvH3KSuNLoZLc1Hf2JNMVL4Q1O
# pbybpMe46YceNA0LfNsnqcnpJeItK/DhKbPxTTuGoX7wJNdoRORVbPR1VVnDuSeH
# VZlc4seAO+6d2sC26/PQPdP51ho1zBp+xUIZkpSFA8vWdoUoHLWnqWU3dCCyFG1r
# oSrgHjSHlq8xymLnjCbSLZ49kPmk8iyyizNDIXj//cOgrY7rlRyTlaCCfw7aSURO
# wnu7zER6EaJ+AliL7ojTdS5PWPsWeupWs7NpChUk555K096V1hE0yZIXe+giAwW0
# 0aHzrDchIc2bQhpp0IoKRR7YufAkprxMiXAJQ1XCmnCfgPf8+3mnAgMBAAGjggGV
# MIIBkTAMBgNVHRMBAf8EAjAAMB0GA1UdDgQWBBTkO/zyMe39/dfzkXFjGVBDz2GM
# 6DAfBgNVHSMEGDAWgBTvb1NK6eQGfHrK4pBW9i/USezLTjAOBgNVHQ8BAf8EBAMC
# B4AwFgYDVR0lAQH/BAwwCgYIKwYBBQUHAwgwgZUGCCsGAQUFBwEBBIGIMIGFMCQG
# CCsGAQUFBzABhhhodHRwOi8vb2NzcC5kaWdpY2VydC5jb20wXQYIKwYBBQUHMAKG
# UWh0dHA6Ly9jYWNlcnRzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydFRydXN0ZWRHNFRp
# bWVTdGFtcGluZ1JTQTQwOTZTSEEyNTYyMDI1Q0ExLmNydDBfBgNVHR8EWDBWMFSg
# UqBQhk5odHRwOi8vY3JsMy5kaWdpY2VydC5jb20vRGlnaUNlcnRUcnVzdGVkRzRU
# aW1lU3RhbXBpbmdSU0E0MDk2U0hBMjU2MjAyNUNBMS5jcmwwIAYDVR0gBBkwFzAI
# BgZngQwBBAIwCwYJYIZIAYb9bAcBMA0GCSqGSIb3DQEBCwUAA4ICAQBlKq3xHCcE
# ua5gQezRCESeY0ByIfjk9iJP2zWLpQq1b4URGnwWBdEZD9gBq9fNaNmFj6Eh8/Ym
# RDfxT7C0k8FUFqNh+tshgb4O6Lgjg8K8elC4+oWCqnU/ML9lFfim8/9yJmZSe2F8
# AQ/UdKFOtj7YMTmqPO9mzskgiC3QYIUP2S3HQvHG1FDu+WUqW4daIqToXFE/JQ/E
# ABgfZXLWU0ziTN6R3ygQBHMUBaB5bdrPbF6MRYs03h4obEMnxYOX8VBRKe1uNnzQ
# VTeLni2nHkX/QqvXnNb+YkDFkxUGtMTaiLR9wjxUxu2hECZpqyU1d0IbX6Wq8/gV
# utDojBIFeRlqAcuEVT0cKsb+zJNEsuEB7O7/cuvTQasnM9AWcIQfVjnzrvwiCZ85
# EE8LUkqRhoS3Y50OHgaY7T/lwd6UArb+BOVAkg2oOvol/DJgddJ35XTxfUlQ+8Hg
# gt8l2Yv7roancJIFcbojBcxlRcGG0LIhp6GvReQGgMgYxQbV1S3CrWqZzBt1R9xJ
# gKf47CdxVRd/ndUlQ05oxYy2zRWVFjF7mcr4C34Mj3ocCVccAvlKV9jEnstrniLv
# UxxVZE/rptb7IRE2lskKPIJgbaP5t2nGj/ULLi49xTcBZU8atufk+EMF/cWuiC7P
# OGT75qaL6vdCvHlshtjdNXOCIUjsarfNZzGCBkcwggZDAgEBMGswVzELMAkGA1UE
# BhMCR0IxGDAWBgNVBAoTD1NlY3RpZ28gTGltaXRlZDEuMCwGA1UEAxMlU2VjdGln
# byBQdWJsaWMgQ29kZSBTaWduaW5nIENBIEVWIFIzNgIQBmp+HumDwNBvIWlKxs/D
# ljANBglghkgBZQMEAgEFAKCBhDAYBgorBgEEAYI3AgEMMQowCKACgAChAoAAMBkG
# CSqGSIb3DQEJAzEMBgorBgEEAYI3AgEEMBwGCisGAQQBgjcCAQsxDjAMBgorBgEE
# AYI3AgEVMC8GCSqGSIb3DQEJBDEiBCCLdBtMu8dJuYPfbQwLVzthPgw7AdgWYlRR
# tULkZ/97wzANBgkqhkiG9w0BAQEFAASCAgB8+VFI30QEHNoNzTCuBROAH7AhilPb
# OqfL7BZWNHKWSWgeYTqZeC+Hi+MSmQ6ClbFhq/8Ew+XQnSOW4hIVpVkPH0vb7hMJ
# hkFYIj8o42VpCfHNFYBAZJ1zU6FuuBges+D+rhcv5n4ek8MxxUN8r9mefJ+DSCtP
# fYYI/MUFu8EAr3cftXet/z3Y/NLd9otisWut1favv7FQIS8zZAnzgB9y9sUIr7Yf
# Gl7aQZOVM3mCqNGzHj8zuSkLVxd+V5p/RzRxjqdo5Iyq1lz6VhcXFSPvKXzkg9yp
# SrIsB44/R4mPCuKR9FmhRvtoR+bU+QvBghyq3YucXfLRPnjQ6jvD+WxX+RvqrQHV
# WZFLz54DwZjKRqPjeiZRqUmDbun+FGQ1uTRvB0foxSKbupygu6+aqW5Lt8uUV2Ho
# PPGFcBCWXFiV21nTuNV5D8zgdXR2Ae+RCA6gFxcxyZfVdUq0izhJh8HOyV2+QIMU
# zmzM0m/9npyKsg48MUZ9i5ZLAkheUONOMeDniRA9yWi0+GBneGJBhYCt0eFt2aaB
# c+b76Pz9birLcQhVde24uaPCxLOZWSuMbCSxW11b07bP72ChGSre1sVSCU6WWz8+
# rSk6jlsSaldCz3jVi5SINPvl7oNYRcwQGFcTY8s/niCycLOvIj7oDPHRvDtKljHE
# jCLrc0MNNlYcV6GCAyYwggMiBgkqhkiG9w0BCQYxggMTMIIDDwIBATB9MGkxCzAJ
# BgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwgSW5jLjFBMD8GA1UEAxM4RGln
# aUNlcnQgVHJ1c3RlZCBHNCBUaW1lU3RhbXBpbmcgUlNBNDA5NiBTSEEyNTYgMjAy
# NSBDQTECEAqA7xhLjfEFgtHEdqeVdGgwDQYJYIZIAWUDBAIBBQCgaTAYBgkqhkiG
# 9w0BCQMxCwYJKoZIhvcNAQcBMBwGCSqGSIb3DQEJBTEPFw0yNjAzMDUyMDAxNTla
# MC8GCSqGSIb3DQEJBDEiBCCrqFbiAG2k8Lxw7/mlZORm1CkuFLg9i1FcK1JEUREh
# WDANBgkqhkiG9w0BAQEFAASCAgCkqr7LYq2GrKIiJ7W50cr6U64bHr+85na+l2xG
# IzAxWTm3xebiaRs2br0gqcDaRfekK5jRJs2RuXSN3ssuFcAJRXIkwNOzuNoLJYoz
# amufQsIT1X7Lf4TBsTA1rBbAFbCNfIT8NVyL+0CrXUyZHVvWAAOGrEqhT2PiZM0l
# hAtdlrPcf944JxhHnsfbgA5Di+f/7w5WNu4uPB6Ga71OHd1UY1IEUwaPu9Ak8eOg
# gf0ASgYsBYYmmyDquEVKfhbsTd9esJIU+lX9gfzBxpK9WlDPw76J01vreHiZX27N
# Fw79g34xPIghhWGcg9FPUnSA3dduSdI4tNAEZaPAMWeH+rFV701+HXrTvzRV7o+F
# v02aAV+r4dD7Jly8TycGKPoYNDIuYG2zNog5lSa6Ds9M1rzCR8BP3lojirIJkv9o
# YwAlvRdVl7MWZv0DjcitDyuPm5vyve1j44E4Rklz6LEwe4TL8857cTxm3MUJ53yX
# e5hRH837Btu8IKUZEnHblijqo88RB1/qPFgNOfDTWNCIM+ASDP484iFXEdguL0If
# JZ8jtR4sumnl6g1Kl7i8Ph6aSakUDl9u+I+IF1s/zcngNpePgP/TFpMhqoL6b6DS
# 47DNW1qWUimMHwGneIODVsI5GVJyxIZOY677MulVXK3sno/exWorzKyGQK27RLZ8
# SFmOkA==
# SIG # End signature block
