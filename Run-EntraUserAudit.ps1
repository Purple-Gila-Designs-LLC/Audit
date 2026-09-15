<#
.SYNOPSIS
    Audits Entra ID directory role assignments (ALL roles, active + PIM-eligible, with
    group-based assignments expanded down to member users), all active Entra ID Member users
    (with their group memberships and enterprise-app role assignments), and the tenant's
    service principal inventory — then uploads the resulting CSV files to a SharePoint folder.

.DESCRIPTION
    Run-EntraUserAudit uses the Microsoft Graph REST API with client-credential
    (application) authentication — no interactive sign-in required.

    It produces three CSV files and uploads them to a specified SharePoint Online folder:

        AuditEntraRoleAssignments_<yyyyMMdd_HHmmss>.csv
            Every directory role assignment in the tenant (not just Global Administrator),
            both currently active and PIM-eligible. A role held by a security group is
            expanded to one row per member user (tagged "via group: <name>") in addition to a
            row for the group itself, so this file answers "who effectively holds this role"
            directly, not just "which principal object was assigned it."
            Columns: RoleName, AssignmentType, PrincipalType, PrincipalId,
                     PrincipalDisplayName, UserPrincipalName

        AuditEntraUsers_<yyyyMMdd_HHmmss>.csv
            Columns: Id, DisplayName, UserPrincipalName, CreatedDateTime, AccountEnabled,
                     DirectoryRoles, Groups, RoleAssignableGroups, EnterpriseAppAccess
            DirectoryRoles here is the user's *direct* role membership only (Graph's
            memberOf/directoryRole does not reflect roles held via a role-assignable group) —
            cross-reference AuditEntraRoleAssignments.csv for the complete picture including
            group-derived roles. EnterpriseAppAccess lists which enterprise apps
            (service principals) the user has been granted an app role on directly; it does
            not resolve the specific role name within each app, nor access granted via group
            (both noted as future enhancements — see .NOTES).

        AuditEntraServicePrincipals_<yyyyMMdd_HHmmss>.csv
            Every service principal in the tenant with its credential expiry window —
            forgotten/expiring service-principal secrets are a common privilege-hygiene gap.
            Columns: Id, AppId, DisplayName, AccountEnabled, ServicePrincipalType,
                     CredentialCount, EarliestCredentialExpiry, LatestCredentialExpiry
            Owners are not included (would need a per-SP call — noted as a future enhancement).

.REQUIRED MODULES
    None — all interactions use Invoke-RestMethod against the Microsoft Graph REST API.
    No PowerShell SDK modules need to be installed.

.REQUIRED API PERMISSIONS (Application — on the App Registration)
    Microsoft Graph (see docs\Entra-AppRegistration-Setup.md for the authoritative list):
        Directory.Read.All         — Users, groups, memberships, directory roles/objects
                                      (covers group-based role expansion and role-assignable
                                      group detection too - Group.Read.All is not additionally
                                      needed)
        RoleManagement.Read.Directory — Directory role definitions and active/eligible
                                      assignment schedules, for ALL roles (RoleManagement.Read.All
                                      also works if that's what's already granted)
        Application.Read.All       — Service principals, app role assignments, credential expiry
        Sites.ReadWrite.All        — Upload files to SharePoint
            (Alternatively use Sites.Selected for least-privilege access limited
             to the specific SharePoint site.)

.PARAMETER TenantId
    Azure AD / Entra ID Tenant ID (GUID). Optional if the 'Entra-TenantId' secret exists in
    SecretManagement (see -TenantIdSecretName) — matches the credential-storage pattern used
    by Get-NinjaOneServerRightsInventory.ps1.

.PARAMETER ClientId
    Application (Client) ID of the App Registration. Optional — see -ClientIdSecretName.

.PARAMETER ClientSecret
    Client secret value for the App Registration. Optional — see -ClientSecretSecretName.

.PARAMETER TenantIdSecretName
    SecretManagement secret name to resolve -TenantId from when not supplied directly.
    Defaults to 'Entra-TenantId'.

.PARAMETER ClientIdSecretName
    SecretManagement secret name to resolve -ClientId from when not supplied directly.
    Defaults to 'Entra-ClientId'.

.PARAMETER ClientSecretSecretName
    SecretManagement secret name to resolve -ClientSecret from when not supplied directly.
    Defaults to 'Entra-ClientSecret'.

.PARAMETER SharePointSiteUrl
    Full URL of the SharePoint site where CSV files will be uploaded.
    Defaults to this project's established target: https://harddollarcorp.sharepoint.com/sites/SCCM

.PARAMETER SharePointFolderPath
    Path to the target folder within the site's default document library.
    Defaults to 'Shared Documents/Audit'. Leading/trailing slashes are handled automatically.

.EXAMPLE
    # One-time: store credentials so future runs need no parameters at all
    Set-Secret -Name 'Entra-TenantId' -Secret 'xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx'
    Set-Secret -Name 'Entra-ClientId' -Secret 'yyyyyyyy-yyyy-yyyy-yyyy-yyyyyyyyyyyy'
    Set-Secret -Name 'Entra-ClientSecret' -Secret 'your-client-secret-value'

    # Then every run is just:
    . .\Run-EntraUserAudit.ps1
    Run-EntraUserAudit

.EXAMPLE
    # Explicit credentials, e.g. for a one-off test against a different app registration
    . .\Run-EntraUserAudit.ps1
    Run-EntraUserAudit `
        -TenantId       "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" `
        -ClientId       "yyyyyyyy-yyyy-yyyy-yyyy-yyyyyyyyyyyy" `
        -ClientSecret   "your-client-secret-value" `
        -SharePointSiteUrl    "https://harddollarcorp.sharepoint.com/sites/SCCM" `
        -SharePointFolderPath "Shared Documents/Audit"

.NOTES
    Author  : RTillmon - InEight Technology Operations (with Claude Code)
    Version : 2.1.0
    Created : 2026-03-05
    Updated : 2026-09-14 — v2.0.0 expanded from Global-Admin-only to all directory roles (with
              group-expansion), added per-user group membership + direct enterprise-app
              access, added a service principal inventory. Removed -GlobalAdminRoleId /
              -PimRoleDefinitionId (no longer needed — every role is covered, not one).
              This is a breaking change to the function's parameter set and to the
              AuditEntraAdministrators_*.csv filename (replaced by
              AuditEntraRoleAssignments_*.csv, which is a superset) — update anything
              downstream that depends on the old file/parameters.
              v2.1.0 same day — TenantId/ClientId/ClientSecret are now optional with a
              SecretManagement vault fallback (Entra-TenantId/Entra-ClientId/
              Entra-ClientSecret), matching Get-NinjaOneServerRightsInventory.ps1's pattern;
              SharePointSiteUrl/SharePointFolderPath now default to this project's
              established target instead of being required every call.

    Known limitations (candidates for a future pass, kept out of this one to bound scope):
      - Graph's $expand on a collection (used to pull each activated directory role's active
        members in one call) can silently truncate a very large nested member list. Spot-check
        any role with an unusually large membership against a direct
        /directoryRoles/{id}/members call if the count looks suspicious.
      - EnterpriseAppAccess (in AuditEntraUsers.csv) reflects only *direct* app role
        assignments on the user, not access granted via group membership, and lists the app
        name rather than resolving the specific role assigned within it.
      - AuditEntraServicePrincipals.csv does not include owners (would need one extra Graph
        call per service principal).
#>

function Run-EntraUserAudit {
    [CmdletBinding()]
    param (
        # ── Authentication ──────────────────────────────────────────────────────
        # All three are optional if the matching secret exists in SecretManagement
        # (see -*SecretName below) - mirrors Get-NinjaOneServerRightsInventory.ps1's pattern,
        # so credentials never need to be typed/pasted for a routine re-run.
        [Parameter(HelpMessage = "Entra ID Tenant ID (GUID)")]
        [string]$TenantId,

        [Parameter(HelpMessage = "App Registration Client ID (GUID)")]
        [string]$ClientId,

        [Parameter(HelpMessage = "App Registration Client Secret")]
        [string]$ClientSecret,

        [string]$TenantIdSecretName = 'Entra-TenantId',
        [string]$ClientIdSecretName = 'Entra-ClientId',
        [string]$ClientSecretSecretName = 'Entra-ClientSecret',

        # ── SharePoint destination ───────────────────────────────────────────────
        # Defaulted to this project's established target (docs\*.md, prior runs) - override
        # if uploading somewhere else.
        [string]$SharePointSiteUrl = 'https://harddollarcorp.sharepoint.com/sites/SCCM',
        [string]$SharePointFolderPath = 'Shared Documents/Audit'
    )

    # --- Resolve credentials -----------------------------------------------------------
    # Prefer SecretManagement (local SecretStore today; swaps to Keeper's SecretManagement.Keeper
    # vault later with no script changes - same convention as the NinjaOne orchestrator) over
    # explicit parameters, which exist mainly for one-off/manual testing.
    if (-not $TenantId -or -not $ClientId -or -not $ClientSecret) {
        if (-not (Get-Module -ListAvailable -Name Microsoft.PowerShell.SecretManagement)) {
            throw 'No -TenantId/-ClientId/-ClientSecret supplied and Microsoft.PowerShell.SecretManagement is not available to resolve them. Either pass credentials explicitly or store them as secrets - see docs\Entra-AppRegistration-Setup.md.'
        }
        Import-Module Microsoft.PowerShell.SecretManagement -ErrorAction Stop

        if (-not $TenantId) {
            $TenantId = Get-Secret -Name $TenantIdSecretName -AsPlainText -ErrorAction Stop
        }
        if (-not $ClientId) {
            $ClientId = Get-Secret -Name $ClientIdSecretName -AsPlainText -ErrorAction Stop
        }
        if (-not $ClientSecret) {
            $ClientSecret = Get-Secret -Name $ClientSecretSecretName -AsPlainText -ErrorAction Stop
        }
    }

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
        Maps a Graph principal object's @odata.type to a short, readable type name.
    #>
    function Get-PrincipalTypeName {
        param($Principal)
        if (-not $Principal) { return 'Unknown' }
        switch ($Principal.'@odata.type') {
            '#microsoft.graph.user'             { 'User' }
            '#microsoft.graph.group'            { 'Group' }
            '#microsoft.graph.servicePrincipal' { 'ServicePrincipal' }
            default                             { 'Unknown' }
        }
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

        # AbsolutePath for https://tenant.sharepoint.com/sites/SCCM  →  /sites/SCCM
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

    Write-Host "[1/7] Acquiring Graph API access token..." -ForegroundColor Cyan

    $token     = Get-GraphAccessToken -TenantId $TenantId -ClientId $ClientId -ClientSecret $ClientSecret
    $graphBase = "https://graph.microsoft.com/v1.0"
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"

    Write-Host "      Token acquired successfully." -ForegroundColor Green

    #endregion

    #region ── Directory role assignments (ALL roles, active + eligible) ──────────

    Write-Host "[2/7] Fetching role definitions..." -ForegroundColor Cyan
    $roleDefs = Invoke-GraphPagedRequest -AccessToken $token `
        -Uri "$graphBase/roleManagement/directory/roleDefinitions?`$select=id,displayName"
    $roleDefMap = @{}
    foreach ($rd in $roleDefs) { $roleDefMap[$rd.id] = $rd.displayName }
    Write-Host "      Role definitions            : $($roleDefMap.Count)" -ForegroundColor Gray

    Write-Host "[3/7] Fetching ACTIVE role assignments (all roles)..." -ForegroundColor Cyan
    # /directoryRoles only lists roles that are "activated" (have at least one member) - that's
    # fine, a role nobody holds has nothing to report. $expand=members returns each role's
    # current members inline in the same call - see .NOTES for the large-membership caveat.
    $activeRoles = Invoke-GraphPagedRequest -AccessToken $token `
        -Uri "$graphBase/directoryRoles?`$expand=members"
    Write-Host "      Activated roles              : $($activeRoles.Count)" -ForegroundColor Gray

    Write-Host "[4/7] Fetching PIM-ELIGIBLE role assignments (all roles)..." -ForegroundColor Cyan
    $eligibleSchedules = Invoke-GraphPagedRequest -AccessToken $token `
        -Uri "$graphBase/roleManagement/directory/roleEligibilitySchedules?`$expand=principal"
    Write-Host "      Eligible schedules            : $($eligibleSchedules.Count)" -ForegroundColor Gray

    # Cache group membership expansions - the same group may hold multiple roles, or be
    # encountered again as an eligible principal after already being seen as an active one.
    $groupMemberCache = @{}
    function Get-CachedGroupUserMembers {
        param([string]$GroupId, [string]$AccessToken, [string]$GraphBase)
        if ($groupMemberCache.ContainsKey($GroupId)) { return $groupMemberCache[$GroupId] }
        $members = Invoke-GraphPagedRequest -AccessToken $AccessToken `
            -Uri "$GraphBase/groups/$GroupId/members?`$select=id,displayName,userPrincipalName"
        $userMembers = @($members | Where-Object { $_.'@odata.type' -eq '#microsoft.graph.user' })
        $groupMemberCache[$GroupId] = $userMembers
        return $userMembers
    }

    $roleAssignmentRows = [System.Collections.Generic.List[object]]::new()

    function Add-RoleAssignmentRows {
        param(
            [string]$RoleName,
            [string]$AssignmentTypeLabel,
            $Principal,
            [System.Collections.Generic.List[object]]$Sink,
            [string]$AccessToken,
            [string]$GraphBase
        )
        $ptype = Get-PrincipalTypeName $Principal
        if ($ptype -eq 'Group') {
            $memberUsers = Get-CachedGroupUserMembers -GroupId $Principal.id -AccessToken $AccessToken -GraphBase $GraphBase
            foreach ($mu in $memberUsers) {
                $Sink.Add([PSCustomObject]@{
                    RoleName              = $RoleName
                    AssignmentType        = "$AssignmentTypeLabel (via group: $($Principal.displayName))"
                    PrincipalType         = 'User'
                    PrincipalId           = $mu.id
                    PrincipalDisplayName  = $mu.displayName
                    UserPrincipalName     = $mu.userPrincipalName
                })
            }
            # Also record the group itself, for traceability of which group is granting access.
            $Sink.Add([PSCustomObject]@{
                RoleName              = $RoleName
                AssignmentType        = $AssignmentTypeLabel
                PrincipalType         = 'Group'
                PrincipalId           = $Principal.id
                PrincipalDisplayName  = $Principal.displayName
                UserPrincipalName     = $null
            })
        } else {
            $Sink.Add([PSCustomObject]@{
                RoleName              = $RoleName
                AssignmentType        = $AssignmentTypeLabel
                PrincipalType         = $ptype
                PrincipalId           = $Principal.id
                PrincipalDisplayName  = $Principal.displayName
                UserPrincipalName     = $Principal.userPrincipalName
            })
        }
    }

    foreach ($role in $activeRoles) {
        foreach ($member in $role.members) {
            Add-RoleAssignmentRows -RoleName $role.displayName -AssignmentTypeLabel 'Active' `
                -Principal $member -Sink $roleAssignmentRows -AccessToken $token -GraphBase $graphBase
        }
    }
    foreach ($schedule in $eligibleSchedules) {
        if (-not $schedule.principal) { continue }
        $roleName = $roleDefMap[$schedule.roleDefinitionId]
        if (-not $roleName) { $roleName = $schedule.roleDefinitionId }
        Add-RoleAssignmentRows -RoleName $roleName -AssignmentTypeLabel 'Eligible (PIM)' `
            -Principal $schedule.principal -Sink $roleAssignmentRows -AccessToken $token -GraphBase $graphBase
    }

    Write-Host "      Total role-assignment rows    : $($roleAssignmentRows.Count) (group-expanded)" -ForegroundColor Green

    $roleAssignmentCsvName    = "AuditEntraRoleAssignments_$timestamp.csv"
    $roleAssignmentCsvContent = $roleAssignmentRows |
        Select-Object RoleName, AssignmentType, PrincipalType, PrincipalId, PrincipalDisplayName, UserPrincipalName |
        ConvertTo-Csv -NoTypeInformation |
        Out-String

    #endregion

    #region ── User audit (roles, groups, enterprise-app access) ──────────────────

    Write-Host "[5/7] Querying active Entra ID Member users..." -ForegroundColor Cyan

    # Retrieve all active, non-guest accounts
    # $select limits the payload; $filter excludes disabled and guest accounts
    $userFilter = [System.Uri]::EscapeDataString("accountEnabled eq true and userType eq 'Member'")
    $userSelect = "id,displayName,userPrincipalName,createdDateTime,accountEnabled"

    $activeUsers = Invoke-GraphPagedRequest `
        -AccessToken $token `
        -Uri         "$graphBase/users?`$filter=$userFilter&`$select=$userSelect"

    Write-Host "      Active member users found      : $(@($activeUsers).Count)" -ForegroundColor Gray
    Write-Host "[6/7] Resolving roles, groups, and app access (Graph batch)..." -ForegroundColor Cyan
    Write-Host "      This may take several minutes for large tenants." -ForegroundColor Yellow

    $userDetailsWithRoles = [System.Collections.Generic.List[object]]::new()
    # The Graph $batch endpoint hard-caps at 20 sub-requests per call. Each user here generates
    # 3 sub-requests (roles, groups, app role assignments), so 6 users/batch keeps every call
    # at 18 sub-requests - comfortably under the limit while still batching.
    $batchSize = 6

    for ($i = 0; $i -lt $activeUsers.Count; $i += $batchSize) {
        $end   = [Math]::Min($i + $batchSize - 1, $activeUsers.Count - 1)
        $chunk = $activeUsers[$i..$end]

        $batchRequests = foreach ($user in $chunk) {
            @{
                id     = "$($user.id)_roles"
                method = "GET"
                url    = "/users/$($user.id)/memberOf/microsoft.graph.directoryRole?`$select=displayName"
            }
            @{
                id     = "$($user.id)_groups"
                method = "GET"
                url    = "/users/$($user.id)/memberOf/microsoft.graph.group?`$select=displayName,isAssignableToRole"
            }
            @{
                id     = "$($user.id)_approles"
                method = "GET"
                url    = "/users/$($user.id)/appRoleAssignments?`$select=resourceDisplayName"
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

        # Index responses by their composite ID (userId_roles / userId_groups / userId_approles)
        $responseMap = @{}
        foreach ($resp in $batchResult.responses) {
            $responseMap[$resp.id] = $resp
        }

        foreach ($user in $chunk) {
            $rolesResp    = $responseMap["$($user.id)_roles"]
            $groupsResp   = $responseMap["$($user.id)_groups"]
            $approlesResp = $responseMap["$($user.id)_approles"]

            $roles = @()
            if ($rolesResp -and $rolesResp.status -eq 200 -and $rolesResp.body.value) {
                $roles = $rolesResp.body.value | ForEach-Object { $_.displayName }
            }

            $allGroups          = @()
            $roleAssignableGroups = @()
            if ($groupsResp -and $groupsResp.status -eq 200 -and $groupsResp.body.value) {
                $allGroups = $groupsResp.body.value | ForEach-Object { $_.displayName }
                $roleAssignableGroups = $groupsResp.body.value |
                    Where-Object { $_.isAssignableToRole } |
                    ForEach-Object { $_.displayName }
            }

            $enterpriseAppAccess = @()
            if ($approlesResp -and $approlesResp.status -eq 200 -and $approlesResp.body.value) {
                $enterpriseAppAccess = $approlesResp.body.value |
                    ForEach-Object { $_.resourceDisplayName } |
                    Select-Object -Unique
            }

            $userDetailsWithRoles.Add([PSCustomObject]@{
                Id                    = $user.id
                DisplayName           = $user.displayName
                UserPrincipalName     = $user.userPrincipalName
                CreatedDateTime       = $user.createdDateTime
                AccountEnabled        = $user.accountEnabled
                DirectoryRoles        = ($roles -join "; ")
                Groups                = ($allGroups -join "; ")
                RoleAssignableGroups  = ($roleAssignableGroups -join "; ")
                EnterpriseAppAccess   = ($enterpriseAppAccess -join "; ")
            })
        }

        $processed = $end + 1
        Write-Progress `
            -Activity        "Resolving user roles/groups/app access" `
            -Status          "$processed of $($activeUsers.Count) users processed" `
            -PercentComplete ([Math]::Round(($processed / $activeUsers.Count) * 100))
    }

    Write-Progress -Activity "Resolving user roles/groups/app access" -Completed
    Write-Host "      Resolution complete            : $($userDetailsWithRoles.Count) users" -ForegroundColor Green

    $userCsvName    = "AuditEntraUsers_$timestamp.csv"
    $userCsvContent = $userDetailsWithRoles |
        Select-Object Id, DisplayName, UserPrincipalName, CreatedDateTime, AccountEnabled,
                       DirectoryRoles, Groups, RoleAssignableGroups, EnterpriseAppAccess |
        ConvertTo-Csv -NoTypeInformation |
        Out-String

    #endregion

    #region ── Service principal inventory ─────────────────────────────────────────

    Write-Host "[7/7] Fetching service principal inventory..." -ForegroundColor Cyan
    $spSelect = "id,appId,displayName,accountEnabled,servicePrincipalType,passwordCredentials,keyCredentials"
    $servicePrincipals = Invoke-GraphPagedRequest -AccessToken $token `
        -Uri "$graphBase/servicePrincipals?`$select=$spSelect"

    $spRows = foreach ($sp in $servicePrincipals) {
        $expiries = @(
            @($sp.passwordCredentials | ForEach-Object { $_.endDateTime })
            @($sp.keyCredentials | ForEach-Object { $_.endDateTime })
        ) | Where-Object { $_ } | Sort-Object

        [PSCustomObject]@{
            Id                       = $sp.id
            AppId                    = $sp.appId
            DisplayName              = $sp.displayName
            AccountEnabled           = $sp.accountEnabled
            ServicePrincipalType     = $sp.servicePrincipalType
            CredentialCount          = @($sp.passwordCredentials).Count + @($sp.keyCredentials).Count
            EarliestCredentialExpiry = if ($expiries) { $expiries[0] } else { $null }
            LatestCredentialExpiry   = if ($expiries) { $expiries[-1] } else { $null }
        }
    }

    Write-Host "      Service principals             : $(@($spRows).Count)" -ForegroundColor Green

    $spCsvName    = "AuditEntraServicePrincipals_$timestamp.csv"
    $spCsvContent = $spRows |
        Select-Object Id, AppId, DisplayName, AccountEnabled, ServicePrincipalType,
                       CredentialCount, EarliestCredentialExpiry, LatestCredentialExpiry |
        ConvertTo-Csv -NoTypeInformation |
        Out-String

    #endregion

    #region ── SharePoint Upload ───────────────────────────────────────────────────

    Write-Host "Uploading CSV files to SharePoint..." -ForegroundColor Cyan
    Write-Host "  Site   : $SharePointSiteUrl" -ForegroundColor Gray
    Write-Host "  Folder : $SharePointFolderPath" -ForegroundColor Gray

    foreach ($file in @(
        @{ Name = $roleAssignmentCsvName; Content = $roleAssignmentCsvContent }
        @{ Name = $userCsvName;           Content = $userCsvContent }
        @{ Name = $spCsvName;             Content = $spCsvContent }
    )) {
        Upload-CsvToSharePoint `
            -AccessToken $token `
            -SiteUrl     $SharePointSiteUrl `
            -FolderPath  $SharePointFolderPath `
            -FileName    $file.Name `
            -CsvContent  $file.Content
        Write-Host "  Uploaded : $($file.Name)" -ForegroundColor Green
    }

    #endregion

    Write-Host ""
    Write-Host "Audit complete." -ForegroundColor Green
    Write-Host "  $roleAssignmentCsvName  →  $SharePointSiteUrl/$SharePointFolderPath" -ForegroundColor Green
    Write-Host "  $userCsvName            →  $SharePointSiteUrl/$SharePointFolderPath" -ForegroundColor Green
    Write-Host "  $spCsvName              →  $SharePointSiteUrl/$SharePointFolderPath" -ForegroundColor Green
}

# SIG # Begin signature block
# MIIsoAYJKoZIhvcNAQcCoIIskTCCLI0CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCA2W853HQzD6MA6
# /nFZt3zPOs9ek5WI2Vc5iln2VgK9IKCCJa8wggVvMIIEV6ADAgECAhBI/JO0YFWU
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
# AYI3AgEVMC8GCSqGSIb3DQEJBDEiBCABFz0Sd+jBXBuYhGlVWdNb5EEMtAAsy3Tq
# kV8KDLxZqTANBgkqhkiG9w0BAQEFAASCAgCKr+SLmZ4kPOCXrUEOz7OGcqvGCg7C
# 0yPiJ1KdryyO5k0G3HMlTp1V8aczL8VKPBEpsb237dg7UJxkJ8LH1xUUUexA74GK
# 9V2VLA7AdvU/dfVeuBNEbjlgmqv7l9mUnZhjyWdO97fLFzTqyHpOVf+XkfyLQwCZ
# zKnPfbXyp2wjwSuJvmkeORu2Mjb+vp4WgSqNu5CwJZ56jTRAKVU6RDQcIImOAYMf
# oA8EXFOSwcnttQzjka8+7JxVePr9H+/XQxvFn+mHI3q6QO04Jf70uiFgxDSneZ53
# 5PnYftUY6vAEh3NpTRtVURmns4wvLaZN7tUYemlzAP3CdwfD3yJLfXnXBL3fTc1G
# eeQrgC2hR/RyLLIUDeAQ8JcDDOE60U2Oh1VmnlG/mLUrORBKyO5pi33fd3QM5DMM
# PuY9URLlqLN7crfGIe4Zs1BKo7/XHa2+/vEFCbp2gC9SHw6u5yecZsB0VEht53oc
# dWg7NuwUzJtsVM6j5jB575Mc9XskhwPg3czIKLtma5fnfSQR3EacfWMg/lrNVbfc
# tuokVbdddcQ99TsocdNxN1tUi6PeN2R80J40DgZauJ/irOvesn8NNvafcvh77uJD
# piluVEzoGg2BCRNkg6sV1rnlYbjkfFvjGIpaue0IvK4AlybzGrYqvm8KRODYoS+w
# M3TwmJSFXf8ubqGCAyYwggMiBgkqhkiG9w0BCQYxggMTMIIDDwIBATB9MGkxCzAJ
# BgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwgSW5jLjFBMD8GA1UEAxM4RGln
# aUNlcnQgVHJ1c3RlZCBHNCBUaW1lU3RhbXBpbmcgUlNBNDA5NiBTSEEyNTYgMjAy
# NSBDQTECEAhP3DNPfkVO28MPj/mSGDUwDQYJYIZIAWUDBAIBBQCgaTAYBgkqhkiG
# 9w0BCQMxCwYJKoZIhvcNAQcBMBwGCSqGSIb3DQEJBTEPFw0yNjA5MTUwODUzMDBa
# MC8GCSqGSIb3DQEJBDEiBCA894G7YuImh+XEjM6eIRDpOTlC3MWm+FGK6ibsgLNC
# VTANBgkqhkiG9w0BAQEFAASCAgAJ18elhfO850FGkIHaB976kuR1II/CH8/Bmu7Y
# xUhtkJtnh0AiHEMD7Wai97IBlG/yYU2J1Z9ib/jr8Knzn/jDVQjze0VFZc7FWAvX
# zQNM2r0BRirdedMlHER1jLh4s3XFSF0PqLbSw/hVRQRvakFctc/Zavk69YuxjJ6S
# iwBfQHgHwfV/ajeOAKkSJV3NBZc1J2VmDiVQ16J/wSUfj9fewQprvlt/0JBJiUK7
# J6u8fd+QiI0TJB+HBqu/9Y29qhvNLnsGm5fexdmSAJTINx8vceMGA3G6GFj66NMQ
# 8UAZn7w3c4cDhfm9rbH8qMEVyqYmHBGtLu7xvweyeloFHe385MoyZaC8H07Kn6i5
# Tkh9TqtT2bIqUQkJQGC/0VFg9iR4okwaFX4gLjR/2y4rBO1m/65/lO46jWJzvdJh
# WUAx0yASIYBZOdNJ2ROrUuSKICUh7tTxdkidqiXmkyEaLvqVoOAmPM4+OasY3ZT9
# a7sRY24vIOM2MsjsGRdvG2kSXljyiq3zLAW6vZxbFDjVm5+P2umE/Bzb14zgJniE
# /3aKGd9k4azdfVD2I7z2ZAA8ZHg+wR4qmGVPSltKDziqe1s2iJaPBp6/5WSoIyjo
# uk74mlDpT03X+DCQujjgJhKCaA4XBIzHoaCIF4YlcXwqHO/1NsVe/qX81GY5y2KI
# AQxnng==
# SIG # End signature block
