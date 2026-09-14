<#
.SYNOPSIS
    Inventories Active Directory users, service accounts, group membership (recursive),
    and delegated OU/object rights across one or more domains, for the privilege audit /
    job-code comparison initiative.

.DESCRIPTION
    Get-ADRightsInventory complements Run-EntraUserAudit.ps1 (the Entra-side collector in
    this same folder). Where that script answers "what can this user do in Entra/Azure",
    this script answers "what can this user do in on-prem AD".

    For each configured domain it collects three things:

      1. USERS  - all enabled user accounts under the "Internal" (employee) OU tree,
                  including extensionAttribute2 (JobCode, per Copy-JobCodes2EA2.ps1) and
                  Description (JobCode's original source field).
      2. SERVICE ACCOUNTS - all accounts under the "Service" OU tree, flagged separately
                  since they are not employees and won't have a JobCode.
      3. GROUP MEMBERSHIP - recursive (nested-group-aware) membership for every account
                  found above, so a user who is only a member of Group A, which is itself
                  a member of privileged Group B, is correctly credited with Group B too.
      4. DELEGATED RIGHTS (optional, -IncludeACLDelegation) - non-inherited ACEs on every
                  OU in the domain, i.e. rights granted by delegation (Delegation of
                  Control wizard / dsacls) rather than by group membership. This is the
                  audit trail for things like "Helpdesk group can reset passwords in this
                  OU" that group membership alone will never show you.

    Built-in/default ACEs (SYSTEM, well-known admin groups, CREATOR OWNER, etc.) are
    excluded by default from the delegation report via -ExcludeWellKnownTrustees, since
    every OU carries these from creation and they drown out the interesting rows. Review
    the exclusion list before relying on the report and adjust it to your environment.

.PARAMETER Domain
    One or more domain DNS names to inventory. Defaults to both domains currently known
    to be in scope for this audit.

.PARAMETER EmployeeOU
    Distinguished-name suffix (relative to each domain's default naming context is NOT
    assumed - pass full DNs) identifying the employee/user OU tree to scan. Accepts one
    value per -Domain, matched by position. Defaults to the InEight OU layout already in
    use in harddollar.local; override per-domain as needed.

.PARAMETER ServiceAccountOU
    Same idea as -EmployeeOU, for the Service-account OU tree.

.PARAMETER IncludeACLDelegation
    Also walk every OU in the domain and report non-inherited (explicitly delegated) ACEs.
    This is the slowest part of the script on a large domain - expect it to dominate the
    runtime. Omit it for a quick group-membership-only pass.

.PARAMETER Credential
    Optional PSCredential to use for domains that need different auth than the account
    running the script (e.g. no trust between harddollar.local and IN8AZURE.local). Applies
    to every domain in this run - re-run separately per domain if credentials differ.

.PARAMETER OutputPath
    Folder to write the per-domain CSV reports to. Defaults to .\output next to this
    script. Created if it doesn't exist.

.EXAMPLE
    .\Get-ADRightsInventory.ps1

    Quick pass: users, service accounts, and recursive group membership for both
    harddollar.local and IN8AZURE.local, no ACL delegation walk.

.EXAMPLE
    .\Get-ADRightsInventory.ps1 -Domain 'harddollar.local' -IncludeACLDelegation -OutputPath 'C:\Audit\AD'

    Full pass (including OU delegation) against a single domain.

.NOTES
    Author  : RTillmon - InEight Technology Operations (with Claude Code)
    Version : 1.0.0
    Created : 2026-09-14

    Run as a dedicated, non-privileged, read-only-delegated service account - see
    docs\AD-Service-Account-Setup.md. This script only reads; it never modifies AD.

    IN8AZURE.local is confirmed in scope alongside harddollar.local as of 2026-09-14.
    If there is no two-way trust between the domains, run once per domain with the
    appropriate -Credential rather than relying on a single identity for both.
#>

#Requires -Module ActiveDirectory

[CmdletBinding()]
param(
    [string[]]$Domain = @('harddollar.local', 'IN8AZURE.local'),

    [string[]]$EmployeeOU = @(
        'OU=Internal,OU=InEight Users,DC=harddollar,DC=local'
    ),

    [string[]]$ServiceAccountOU = @(
        'OU=Service,OU=InEight Users,DC=harddollar,DC=local'
    ),

    [switch]$IncludeACLDelegation,

    [string[]]$ExcludeWellKnownTrustees = @(
        'NT AUTHORITY\SYSTEM', 'BUILTIN\Administrators', 'CREATOR OWNER',
        'NT AUTHORITY\SELF', 'Everyone', 'BUILTIN\Pre-Windows 2000 Compatible Access',
        'BUILTIN\Account Operators', 'BUILTIN\Print Operators', 'BUILTIN\Server Operators',
        'BUILTIN\Backup Operators'
    ),

    [System.Management.Automation.PSCredential]$Credential,

    [string]$OutputPath = (Join-Path $PSScriptRoot 'output')
)

Import-Module ActiveDirectory -ErrorAction Stop

if (-not (Test-Path $OutputPath)) {
    New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
}
$RunStamp = Get-Date -Format 'yyyyMMdd_HHmmss'

#region ── Helper functions ────────────────────────────────────────────────────

function Get-ADRecursiveGroupMembership {
    <#
        Walks an account's memberOf chain to full depth, following nested groups,
        with cycle protection. Returns one object per (account, group, depth) pair.
    #>
    param(
        [Parameter(Mandatory)][string]$DistinguishedName,
        [Parameter(Mandatory)][string]$Server,
        [System.Management.Automation.PSCredential]$Credential
    )

    $adParams = @{ Server = $Server; ErrorAction = 'SilentlyContinue' }
    if ($Credential) { $adParams['Credential'] = $Credential }

    $visited = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    $queue = [System.Collections.Generic.Queue[pscustomobject]]::new()
    $queue.Enqueue([pscustomobject]@{ DN = $DistinguishedName; Depth = 0 })
    $results = [System.Collections.Generic.List[pscustomobject]]::new()

    while ($queue.Count -gt 0) {
        $current = $queue.Dequeue()
        $obj = Get-ADObject -Identity $current.DN -Properties memberOf, objectClass @adParams
        if (-not $obj) { continue }

        foreach ($groupDN in $obj.memberOf) {
            if ($visited.Contains($groupDN)) { continue }
            [void]$visited.Add($groupDN)

            $group = Get-ADGroup -Identity $groupDN -Properties GroupCategory, GroupScope @adParams
            if (-not $group) { continue }

            $results.Add([pscustomobject]@{
                GroupDN       = $group.DistinguishedName
                GroupName     = $group.Name
                GroupCategory = $group.GroupCategory
                GroupScope    = $group.GroupScope
                NestedDepth   = $current.Depth + 1
                ViaGroup      = if ($current.Depth -eq 0) { $null } else {
                    (Get-ADObject -Identity $current.DN -Properties Name @adParams).Name
                }
            })

            $queue.Enqueue([pscustomobject]@{ DN = $groupDN; Depth = $current.Depth + 1 })
        }
    }

    return $results
}

function Get-ADSchemaGuidMap {
    <#
        Builds a GUID -> friendly-name lookup covering both schema attribute/class GUIDs
        (schemaIDGUID) and extended-rights GUIDs (rightsGuid), so ObjectType/
        InheritedObjectType values on delegated ACEs can be resolved to something readable
        instead of a bare GUID.
    #>
    param(
        [Parameter(Mandatory)][string]$Server,
        [System.Management.Automation.PSCredential]$Credential
    )

    $adParams = @{ Server = $Server; ErrorAction = 'SilentlyContinue' }
    if ($Credential) { $adParams['Credential'] = $Credential }

    $map = @{}
    $rootDSE = Get-ADRootDSE @adParams

    Get-ADObject -SearchBase $rootDSE.schemaNamingContext -LDAPFilter '(schemaIDGUID=*)' `
        -Properties schemaIDGUID, name @adParams | ForEach-Object {
            $guid = [GUID]$_.schemaIDGUID
            $map[$guid.ToString()] = $_.name
        }

    $extendedRightsDN = "CN=Extended-Rights,$($rootDSE.configurationNamingContext)"
    Get-ADObject -SearchBase $extendedRightsDN -LDAPFilter '(rightsGuid=*)' `
        -Properties rightsGuid, name @adParams | ForEach-Object {
            $map[$_.rightsGuid] = $_.name
        }

    return $map
}

function Get-ADDelegatedRights {
    <#
        Walks every OU under -SearchBase and returns explicitly-set (non-inherited) ACEs,
        i.e. rights granted by delegation rather than by default security descriptor
        inheritance. Well-known built-in trustees are excluded by default (see
        -ExcludeWellKnownTrustees on the main script) since they appear on every OU from
        creation and are not "delegation" in the interesting sense.
    #>
    param(
        [Parameter(Mandatory)][string]$SearchBase,
        [Parameter(Mandatory)][string]$Server,
        [Parameter(Mandatory)][hashtable]$SchemaGuidMap,
        [string[]]$ExcludeTrustees = @(),
        [System.Management.Automation.PSCredential]$Credential
    )

    $adParams = @{ Server = $Server; ErrorAction = 'SilentlyContinue' }
    if ($Credential) { $adParams['Credential'] = $Credential }

    $ous = @(Get-ADObject -SearchBase $SearchBase -SearchScope Subtree `
                -LDAPFilter '(objectClass=organizationalUnit)' @adParams)
    $ous += Get-ADObject -Identity $SearchBase @adParams   # include the root itself

    $results = [System.Collections.Generic.List[pscustomobject]]::new()

    foreach ($ou in $ous) {
        $path = "AD:\$($ou.DistinguishedName)"
        try {
            $acl = Get-Acl -Path $path -ErrorAction Stop
        } catch {
            Write-Warning "Could not read ACL for $($ou.DistinguishedName): $_"
            continue
        }

        foreach ($ace in $acl.Access) {
            if ($ace.IsInherited) { continue }
            if ($ExcludeTrustees -contains $ace.IdentityReference.Value) { continue }

            $objTypeName = if ($ace.ObjectType -and $ace.ObjectType -ne [guid]::Empty) {
                $SchemaGuidMap[$ace.ObjectType.ToString()]
            } else { $null }
            $inheritedObjTypeName = if ($ace.InheritedObjectType -and $ace.InheritedObjectType -ne [guid]::Empty) {
                $SchemaGuidMap[$ace.InheritedObjectType.ToString()]
            } else { $null }

            $results.Add([pscustomobject]@{
                OrganizationalUnit = $ou.DistinguishedName
                Trustee            = $ace.IdentityReference.Value
                AccessControlType  = $ace.AccessControlType
                ActiveDirectoryRights = $ace.ActiveDirectoryRights
                ObjectType         = $objTypeName
                InheritedObjectType = $inheritedObjTypeName
                InheritanceType    = $ace.InheritanceType
            })
        }
    }

    return $results
}

#endregion

#region ── Main ─────────────────────────────────────────────────────────────────

for ($i = 0; $i -lt $Domain.Count; $i++) {
    $dc = $Domain[$i]
    $employeeOU = if ($i -lt $EmployeeOU.Count) { $EmployeeOU[$i] } else { $EmployeeOU[0] }
    $svcOU      = if ($i -lt $ServiceAccountOU.Count) { $ServiceAccountOU[$i] } else { $ServiceAccountOU[0] }

    Write-Host "=== Domain: $dc ===" -ForegroundColor Cyan
    $adParams = @{ Server = $dc; ErrorAction = 'SilentlyContinue' }
    if ($Credential) { $adParams['Credential'] = $Credential }

    # --- Employees ---------------------------------------------------------
    Write-Host "  Collecting employee accounts under $employeeOU ..."
    $employees = @()
    try {
        $employees = Get-ADUser -Filter { Enabled -eq $true } -SearchBase $employeeOU `
            -Properties DisplayName, Description, extensionAttribute2, EmployeeID,
                        Title, Department, Manager, whenCreated, PasswordLastSet,
                        ServicePrincipalName @adParams |
            Select-Object SamAccountName, UserPrincipalName, DisplayName,
                @{N='JobCode';E={$_.extensionAttribute2}},
                Description, EmployeeID, Title, Department, Manager,
                whenCreated, PasswordLastSet, DistinguishedName,
                @{N='HasSPN';E={[bool]$_.ServicePrincipalName}}
    } catch {
        Write-Warning "  Failed to query $employeeOU on $dc : $_"
    }
    Write-Host "  -> $($employees.Count) employee accounts"

    # --- Service accounts ---------------------------------------------------
    Write-Host "  Collecting service accounts under $svcOU ..."
    $serviceAccounts = @()
    try {
        $serviceAccounts = Get-ADUser -Filter * -SearchBase $svcOU `
            -Properties Description, whenCreated, PasswordLastSet, PasswordNeverExpires,
                        ServicePrincipalName @adParams |
            Select-Object SamAccountName, UserPrincipalName, Enabled, Description,
                whenCreated, PasswordLastSet, PasswordNeverExpires, DistinguishedName,
                @{N='HasSPN';E={[bool]$_.ServicePrincipalName}}
    } catch {
        Write-Warning "  Failed to query $svcOU on $dc : $_"
    }
    Write-Host "  -> $($serviceAccounts.Count) service accounts"

    # --- Recursive group membership -----------------------------------------
    Write-Host "  Resolving recursive group membership for $($employees.Count + $serviceAccounts.Count) accounts ..."
    $membershipRows = [System.Collections.Generic.List[pscustomobject]]::new()
    foreach ($acct in @($employees) + @($serviceAccounts)) {
        $isSvc = $serviceAccounts.SamAccountName -contains $acct.SamAccountName
        $groups = Get-ADRecursiveGroupMembership -DistinguishedName $acct.DistinguishedName -Server $dc -Credential $Credential
        foreach ($g in $groups) {
            $membershipRows.Add([pscustomobject]@{
                Domain           = $dc
                SamAccountName   = $acct.SamAccountName
                IsServiceAccount = $isSvc
                JobCode          = $acct.JobCode
                GroupName        = $g.GroupName
                GroupCategory    = $g.GroupCategory
                GroupScope       = $g.GroupScope
                NestedDepth      = $g.NestedDepth
                ViaGroup         = $g.ViaGroup
            })
        }
    }
    Write-Host "  -> $($membershipRows.Count) (account, group) rows"

    # --- Export ---------------------------------------------------------------
    $employees        | Export-Csv -NoTypeInformation -Path (Join-Path $OutputPath "ADUsers_${dc}_$RunStamp.csv")
    $serviceAccounts  | Export-Csv -NoTypeInformation -Path (Join-Path $OutputPath "ADServiceAccounts_${dc}_$RunStamp.csv")
    $membershipRows   | Export-Csv -NoTypeInformation -Path (Join-Path $OutputPath "ADGroupMembership_${dc}_$RunStamp.csv")

    # --- Delegated rights (optional, slow) -------------------------------------
    if ($IncludeACLDelegation) {
        Write-Host "  Building schema/extended-rights GUID map ..."
        $guidMap = Get-ADSchemaGuidMap -Server $dc -Credential $Credential

        Write-Host "  Walking OU delegation for domain root (this is the slow part) ..."
        $domainParams = @{ Server = $dc }
        if ($Credential) { $domainParams['Credential'] = $Credential }
        $domainDN = (Get-ADDomain @domainParams).DistinguishedName
        $delegation = Get-ADDelegatedRights -SearchBase $domainDN -Server $dc `
            -SchemaGuidMap $guidMap -ExcludeTrustees $ExcludeWellKnownTrustees -Credential $Credential

        $delegation | Export-Csv -NoTypeInformation -Path (Join-Path $OutputPath "ADDelegatedRights_${dc}_$RunStamp.csv")
        Write-Host "  -> $($delegation.Count) delegated ACE rows (after exclusions)"
    }

    Write-Host "  Reports written to $OutputPath" -ForegroundColor Green
}

Write-Host "`nDone. Review ADDelegatedRights_*.csv exclusions against your environment before treating it as complete -" -ForegroundColor Yellow
Write-Host "the default -ExcludeWellKnownTrustees list is a starting point, not a guarantee every default ACE is filtered." -ForegroundColor Yellow

#endregion

# SIG # Begin signature block
# MIIsoAYJKoZIhvcNAQcCoIIskTCCLI0CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCDByrXaVDpdeaUm
# IrtdBZKJgxi/P+U9ucPkbN96Ip5Es6CCJa8wggVvMIIEV6ADAgECAhBI/JO0YFWU
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
# AYI3AgEVMC8GCSqGSIb3DQEJBDEiBCCvFjmHFg+oucwGNxLnq7kfqjg/cK1E6yqL
# PXR7qlST+DANBgkqhkiG9w0BAQEFAASCAgBD0lIBkQooE3gYsUVj8L95aXBGv6A4
# NaJGvzqXBWnLFyNQpqR0JVoxjDiE32+RAYBRIpkj8nOw++ea4UOguX4F8QP6BxwE
# E48jxt3wIUWWBg4iyyi3GyhNrLlW1/c5ySATO6edrH/hjzRBtxigSO/cR7D5oueS
# OWJS5ntLfjs+S7O3qiOakbzKPfBuvytH7drg8XETsOkEMrhZ70k+RRD/lCGW0o1P
# vG2CaH7l5v06YJo4V+pZm4uY/+FdIbF2zlCdtaT6e9/DGeNsxn9aCxFiUmlN68LK
# dgyGUs0G4YPP9+lq/SNSlmqxnM7SVrdB9oy9GIOqKo/LRGxFukMMHnGD10RWyvzk
# c7xmZPkmcP2jXVlF9dPceKPJfJHUiITcteVA5fOQMMpRnBUgwAP3aq4vTtMnDB9y
# ViFzZlCy6WjVzVxU6vSlkF6P+iLELX4ikZYsr7etxIOQmiy4pkqRHc1n4264TYbE
# of+QTTczDz/BiNYzrY9yVhnqmUgZcbkawzmevg3dD4KY08Np0tjsPs7x7RDoDrUy
# T25hkQzGeKOXHXUFnTD0YrvRRXv29CWC1aUVtYppVUzereACRba+EvQ2sJS973X3
# t8kLK+OxTc4hb995qjUwVX4TjpwEzy8u1IMXJwmMnlI2g3DYghE9S1Pv/8Ls7gMJ
# N8GLIBJmASjBb6GCAyYwggMiBgkqhkiG9w0BCQYxggMTMIIDDwIBATB9MGkxCzAJ
# BgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwgSW5jLjFBMD8GA1UEAxM4RGln
# aUNlcnQgVHJ1c3RlZCBHNCBUaW1lU3RhbXBpbmcgUlNBNDA5NiBTSEEyNTYgMjAy
# NSBDQTECEAhP3DNPfkVO28MPj/mSGDUwDQYJYIZIAWUDBAIBBQCgaTAYBgkqhkiG
# 9w0BCQMxCwYJKoZIhvcNAQcBMBwGCSqGSIb3DQEJBTEPFw0yNjA5MTQyMjQwNDFa
# MC8GCSqGSIb3DQEJBDEiBCCXECQSU+Z21mbw3J4/Bpdn2Hke7nNQN1pgIECL7+R/
# WzANBgkqhkiG9w0BAQEFAASCAgBoGvBEB7Ktvjxq60sdK8HlPPUM0SjrVGJXhrSu
# RggnorbWXRg8RRz772R6gkCgXRO7tLyRKz1+GYHFizn1aA3UCLRLVJcgx9YIwTxi
# Hnkt8jV5BDT5FwrS9k0TcTbIO411ETKXVeMyvGrl91wZTnNz5Rvf4BuY2XAVpNmD
# Xq/SrcPa/Xws+/Ec4DK5zDvHCG/BAuyC0Hv3XuRgaINR+0FR55bqgLh/8NibBhys
# VUeMstIK9Q37jOhc4zH5cUAXmhdQum+Y0k0buckrT5uuSwQeZMAFaMa6cXEMzTUK
# h9m+fBZ8gKYWk3uGXZvglKVo1LqF4IafpZY34kbjDMBYQTLqzE6PeVpMMU5UhawW
# F51UkBHA4eZdOocV2qbEpP1qyTXssPbuCOLeNUTp620cn5ILxcbtkKQR/c30BgDL
# IE43wEps/9YPaglFGnWASjgyNs3N4jE+pqMrBQ/PokxrXT3fZIL22kqJaFDGYqRM
# kMk1jK230WgRhDYV0BcphjLXYYaiyRh4A0RHIO/OLlAIvavKVG5K+HWal8pvMPpP
# 9eNisNwLvS+4L1L/ZGFnIsqlO93DyN5MAvXkdKCu96cyPLqbPU9J1KPSOmX/Ap/C
# ErBwddE+BEJwqyYHOT2JyRmIJdR7I9i/XVYxvNyhZI7n69OLKY9ZaUoDfhoeRoCg
# T98NJg==
# SIG # End signature block
