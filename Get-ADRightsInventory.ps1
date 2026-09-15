<#
.SYNOPSIS
    Inventories Active Directory users, service accounts, group membership (recursive),
    and delegated OU/object rights across one or more domains, for the privilege audit /
    job-code comparison initiative.

.DESCRIPTION
    Get-ADRightsInventory complements Run-EntraUserAudit.ps1 (the Entra-side collector in
    this same folder). Where that script answers "what can this user do in Entra/Azure",
    this script answers "what can this user do in on-prem AD".

    For each configured domain it collects three things across four account-type OU trees
    under "InEight Users" - Internal (employees), External (contractors/non-employee user
    types), Shared (shared/business-function logons used by multiple people), and Service
    (service accounts):

      1. ACCOUNTS - every account under each OU tree above, tagged with AccountType, plus
                  extensionAttribute2 (JobCode, per Copy-JobCodes2EA2.ps1) and Description
                  (JobCode's original source field). JobCode-based peer comparison is only
                  meaningful for the Internal/Employee type, but the field is captured for
                  all types since External accounts sometimes carry one too.
      2. GROUP MEMBERSHIP - recursive (nested-group-aware) membership for every account
                  found above, so a user who is only a member of Group A, which is itself
                  a member of privileged Group B, is correctly credited with Group B too.
      3. DELEGATED RIGHTS (optional, -IncludeACLDelegation) - non-inherited ACEs on every
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
    to be in scope for this audit. Used for labeling output/JobCode rows - actual queries
    target -DomainController, not this name directly (see below).

.PARAMETER DomainController
    Specific domain controller (FQDN) to query for each -Domain, matched by position.
    Required because the machine running this script is Entra-joined, not AD-joined
    (confirmed 2026-09-14) - there's no domain-joined DNS/Kerberos context to locate a DC
    from the bare domain name the way Get-ADUser normally would, so this has to be
    explicit. Defaults to 'PSADDS1.harddollar.local' for harddollar.local and
    'in8azuredc7.in8azure.local' for IN8AZURE.local (one of four confirmed DCs -
    in8azuredc7/8/9/10.in8azure.local - pick another with -DomainController if dc7 is
    ever unavailable).

.PARAMETER EmployeeOU
    Distinguished-name suffix (relative to each domain's default naming context is NOT
    assumed - pass full DNs) identifying the employee/user OU tree to scan. Accepts one
    value per -Domain, matched by position. Defaults to the InEight OU layout already in
    use in harddollar.local; override per-domain as needed.

.PARAMETER ExternalOU
    Same idea as -EmployeeOU, for the "External" OU tree (contractors and other
    non-employee interactive user types). Added 2026-09-14 at Roger's request - these
    accounts are essential to capture even though they typically fall outside JobCode
    peer comparison.

.PARAMETER SharedOU
    Same idea as -EmployeeOU, for the "Shared" OU tree (shared/business-function logons
    used by multiple people for a specific purpose). Added 2026-09-14 alongside -ExternalOU.

.PARAMETER ServiceAccountOU
    Same idea as -EmployeeOU, for the Service-account OU tree.

.PARAMETER IncludeACLDelegation
    Also walk every OU in the domain and report non-inherited (explicitly delegated) ACEs.
    This is the slowest part of the script on a large domain - expect it to dominate the
    runtime. Omit it for a quick group-membership-only pass.

.PARAMETER Credential
    Optional PSCredential to use instead of the identity running the script. If omitted,
    resolved automatically from SecretManagement via -CredentialSecretName (see below) -
    matches the pattern used by Run-EntraUserAudit.ps1 and the NinjaOne orchestrator, so
    credentials never need to be typed/pasted for a routine re-run. A two-way trust between
    harddollar.local and IN8AZURE.local is confirmed in place as of 2026-09-14, so a single
    credential is expected to work across both domains as long as the account has been
    granted read rights in both - see docs\AD-Service-Account-Setup.md.

.PARAMETER CredentialSecretName
    Name of the SecretManagement secret holding the PSCredential to use when -Credential
    isn't supplied. Store it with:
    Set-Secret -Name 'AD-ServiceAccount' -Secret (Get-Credential 'HARDDOLLAR\svc-priv-audit')
    Defaults to 'AD-ServiceAccount'. Vault: whatever SecretManagement resolves by default
    (PGDLocalVault today - see docs\AD-Service-Account-Setup.md).

.PARAMETER OutputPath
    Folder to write the per-domain CSV reports to. Defaults to .\output next to this
    script. Created if it doesn't exist.

.EXAMPLE
    .\Get-ADRightsInventory.ps1

    Quick pass: employee, external, shared, and service accounts, plus recursive group
    membership, for both harddollar.local and IN8AZURE.local, no ACL delegation walk.
    Credential resolves automatically from the 'AD-ServiceAccount' secret.

.EXAMPLE
    .\Get-ADRightsInventory.ps1 -Domain 'harddollar.local' -IncludeACLDelegation -OutputPath 'C:\Audit\AD'

    Full pass (including OU delegation) against a single domain.

.NOTES
    Author  : RTillmon - InEight Technology Operations (with Claude Code)
    Version : 1.1.0
    Created : 2026-09-14
    Updated : 2026-09-14 - added External/Shared OU scope, Windows Credential Manager +
              SecretManagement credential resolution (AD-ServiceAccount), confirmed trust
              note, required -DomainController (this machine is Entra-joined, not
              AD-joined - no DC locator available from a bare domain name).
    Updated : 2026-09-15 - fixed a real bug found on the first live run: the per-domain
              loop variables $employeeOU/$externalOU/$sharedOU collided (case-insensitive)
              with the like-named [string[]] parameters, so PowerShell kept re-coercing
              the scalar back into a 1-element array on every loop iteration, which then
              failed -SearchBase [string] binding ("Cannot convert value to type
              System.String") for Employee/External/Shared every time - Service accounts
              were unaffected since $svcOU doesn't collide with $ServiceAccountOU, which
              is why only that one query type ever succeeded. Renamed to
              $empOU/$extOU/$shrOU. Also added the default IN8AZURE.local DC
              (in8azuredc7.in8azure.local, confirmed by Roger - dc7/8/9/10 all valid).

    Run as a dedicated, non-privileged, read-only-delegated service account - see
    docs\AD-Service-Account-Setup.md. This script only reads; it never modifies AD.
    HARDDOLLAR\svc-priv-audit was created for this purpose 2026-09-14.

    IN8AZURE.local is confirmed in scope alongside harddollar.local as of 2026-09-14.
    A two-way trust between the two domains is also confirmed in place as of 2026-09-14,
    so a single -Credential (or the resolved AD-ServiceAccount secret) is expected to work
    for both, as long as it has been delegated read rights on both sides. If that ever
    stops being true, run once per domain with the appropriate -Credential instead.
#>

#Requires -Module ActiveDirectory

[CmdletBinding()]
param(
    [string[]]$Domain = @('harddollar.local', 'IN8AZURE.local'),

    [string[]]$DomainController = @('PSADDS1.harddollar.local', 'in8azuredc7.in8azure.local'),

    [string[]]$EmployeeOU = @(
        'OU=Internal,OU=InEight Users,DC=harddollar,DC=local'
    ),

    [string[]]$ExternalOU = @(
        'OU=External,OU=InEight Users,DC=harddollar,DC=local'
    ),

    [string[]]$SharedOU = @(
        'OU=Shared,OU=InEight Users,DC=harddollar,DC=local'
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

    [string]$CredentialManagerTarget = 'AD-ServiceAccount',

    [string]$CredentialSecretName = 'AD-ServiceAccount',

    [string]$OutputPath = (Join-Path $PSScriptRoot 'output')
)

Import-Module ActiveDirectory -ErrorAction Stop

#region ── Windows Credential Manager helper ───────────────────────────────────
function Get-CredManGenericCredential {
    <#
        Reads a *generic* credential (username + password) directly from the native
        Windows Credential Manager store via the Win32 CredRead API - no extra module
        dependency (the community `CredentialManager` PowerShell module isn't installed
        here). Returns $null (not a terminating error) if the target doesn't exist, so
        callers can fall through to another resolution method.
    #>
    param([Parameter(Mandatory)][string]$Target)

    if (-not ('CredMan.NativeMethods' -as [type])) {
        Add-Type -Namespace CredMan -Name NativeMethods -MemberDefinition @'
[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
public struct CREDENTIAL {
    public int    Flags;
    public int    Type;
    public string TargetName;
    public string Comment;
    public long   LastWritten;
    public int    CredentialBlobSize;
    public IntPtr CredentialBlob;
    public int    Persist;
    public int    AttributeCount;
    public IntPtr Attributes;
    public string TargetAlias;
    public string UserName;
}

[DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
public static extern bool CredRead(string target, int type, int reservedFlag, out IntPtr credentialPtr);

[DllImport("advapi32.dll", SetLastError = true)]
public static extern void CredFree(IntPtr cred);
'@
    }

    $credPtr = [IntPtr]::Zero
    # type 1 = CRED_TYPE_GENERIC
    $ok = [CredMan.NativeMethods]::CredRead($Target, 1, 0, [ref]$credPtr)
    if (-not $ok) { return $null }

    try {
        $cred = [System.Runtime.InteropServices.Marshal]::PtrToStructure($credPtr, [type]([CredMan.NativeMethods+CREDENTIAL]))
        if ($cred.CredentialBlobSize -eq 0 -or -not $cred.UserName) { return $null }

        $bytes = New-Object byte[] $cred.CredentialBlobSize
        [System.Runtime.InteropServices.Marshal]::Copy($cred.CredentialBlob, $bytes, 0, $cred.CredentialBlobSize)
        $password = [System.Text.Encoding]::Unicode.GetString($bytes)
        $secure = ConvertTo-SecureString -String $password -AsPlainText -Force
        return [System.Management.Automation.PSCredential]::new($cred.UserName, $secure)
    } finally {
        [CredMan.NativeMethods]::CredFree($credPtr)
    }
}
#endregion

# --- Resolve credential ---------------------------------------------------------------
# Order: explicit -Credential > native Windows Credential Manager (-CredentialManagerTarget,
# what Roger actually used for the AD service account, unlike NinjaOne/Entra which use the
# SecretManagement/SecretStore vault) > SecretManagement (-CredentialSecretName, kept as a
# fallback for consistency with the other two collectors) > the identity running the script.
#   Saved via: Control Panel > Credential Manager > Windows Credentials/Generic Credentials,
#   or:  cmdkey /generic:AD-ServiceAccount /user:HARDDOLLAR\svc-priv-audit /pass:<password>
if (-not $Credential) {
    $Credential = Get-CredManGenericCredential -Target $CredentialManagerTarget
    if ($Credential) {
        Write-Verbose "Resolved credential from Windows Credential Manager target '$CredentialManagerTarget' (user: $($Credential.UserName))."
    }
}
if (-not $Credential) {
    if (Get-Module -ListAvailable -Name Microsoft.PowerShell.SecretManagement) {
        Import-Module Microsoft.PowerShell.SecretManagement -ErrorAction Stop
        try {
            $Credential = Get-Secret -Name $CredentialSecretName -ErrorAction Stop
        } catch {
            Write-Warning "No -Credential supplied; Windows Credential Manager target '$CredentialManagerTarget' and SecretManagement secret '$CredentialSecretName' both failed to resolve ($_). Falling back to the identity running this script."
        }
    } else {
        Write-Warning "No -Credential supplied and Windows Credential Manager target '$CredentialManagerTarget' was not found. Falling back to the identity running this script."
    }
}

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

function Get-ADInteractiveAccounts {
    <#
        Shared query shape for the three "interactive human" OU trees (Internal/Employee,
        External, Shared) - same property set, just tagged with a different AccountType so
        they land in one combined membership report but stay distinguishable. Service
        accounts are queried separately (Get-ADUser -Filter * incl. disabled, different
        property set) since they're not people and PasswordNeverExpires matters more than
        JobCode/Title/Department for them.
    #>
    param(
        [Parameter(Mandatory)][string]$SearchBase,
        [Parameter(Mandatory)][string]$AccountType,
        [Parameter(Mandatory)][hashtable]$AdParams
    )

    Get-ADUser -Filter { Enabled -eq $true } -SearchBase $SearchBase `
        -Properties DisplayName, Description, extensionAttribute2, EmployeeID,
                    Title, Department, Manager, whenCreated, PasswordLastSet,
                    ServicePrincipalName @AdParams |
        Select-Object SamAccountName, UserPrincipalName, DisplayName,
            @{N='AccountType';E={$AccountType}},
            @{N='JobCode';E={$_.extensionAttribute2}},
            Description, EmployeeID, Title, Department, Manager,
            whenCreated, PasswordLastSet, DistinguishedName,
            @{N='HasSPN';E={[bool]$_.ServicePrincipalName}}
}

#endregion

#region ── Main ─────────────────────────────────────────────────────────────────

for ($i = 0; $i -lt $Domain.Count; $i++) {
    $dc = $Domain[$i]
    # NOTE: these must NOT be named $employeeOU/$externalOU/$sharedOU - PowerShell variable
    # names are case-insensitive, so a name differing from a [string[]] *parameter* only by
    # first-letter case (e.g. $employeeOU vs $EmployeeOU) is the SAME variable. Reassigning
    # it here would silently re-coerce the scalar string back into a 1-element string[] on
    # every write (the parameter's type constraint persists on the PSVariable), which then
    # fails -SearchBase [string] binding downstream ("Cannot convert value to type
    # System.String") even though the array only has one element. Root-caused 2026-09-14
    # against the real tenant - $svcOU below never had this bug since it doesn't collide
    # with $ServiceAccountOU, which is exactly why service accounts queried fine while
    # employee/external/shared did not.
    $empOU = if ($i -lt $EmployeeOU.Count) { $EmployeeOU[$i] } else { $EmployeeOU[0] }
    $extOU = if ($i -lt $ExternalOU.Count) { $ExternalOU[$i] } else { $ExternalOU[0] }
    $shrOU = if ($i -lt $SharedOU.Count) { $SharedOU[$i] } else { $SharedOU[0] }
    $svcOU = if ($i -lt $ServiceAccountOU.Count) { $ServiceAccountOU[$i] } else { $ServiceAccountOU[0] }

    # This machine is Entra-joined, not AD-joined (confirmed 2026-09-14), so there's no
    # domain-joined DC locator to fall back on - a -DomainController entry is required for
    # every -Domain, not optional. Skip (not guess) if one wasn't provided for this domain.
    if ($i -ge $DomainController.Count -or -not $DomainController[$i]) {
        Write-Warning "No -DomainController entry for domain '$dc' (index $i) - this machine is Entra-joined and can't locate a DC from the bare domain name. Skipping '$dc'; pass -DomainController explicitly for it."
        continue
    }
    $server = $DomainController[$i]

    Write-Host "=== Domain: $dc (server: $server) ===" -ForegroundColor Cyan
    $adParams = @{ Server = $server; ErrorAction = 'SilentlyContinue' }
    if ($Credential) { $adParams['Credential'] = $Credential }

    # --- Employees / External / Shared (interactive human accounts) ---------
    Write-Host "  Collecting employee accounts under $empOU ..."
    $employees = @()
    try {
        $employees = Get-ADInteractiveAccounts -SearchBase $empOU -AccountType 'Employee' -AdParams $adParams
    } catch {
        Write-Warning "  Failed to query $empOU on $dc : $_"
    }
    Write-Host "  -> $($employees.Count) employee accounts"

    Write-Host "  Collecting external/contractor accounts under $extOU ..."
    $external = @()
    try {
        $external = Get-ADInteractiveAccounts -SearchBase $extOU -AccountType 'External' -AdParams $adParams
    } catch {
        Write-Warning "  Failed to query $extOU on $dc : $_"
    }
    Write-Host "  -> $($external.Count) external accounts"

    Write-Host "  Collecting shared accounts under $shrOU ..."
    $shared = @()
    try {
        $shared = Get-ADInteractiveAccounts -SearchBase $shrOU -AccountType 'Shared' -AdParams $adParams
    } catch {
        Write-Warning "  Failed to query $shrOU on $dc : $_"
    }
    Write-Host "  -> $($shared.Count) shared accounts"

    # --- Service accounts ---------------------------------------------------
    Write-Host "  Collecting service accounts under $svcOU ..."
    $serviceAccounts = @()
    try {
        $serviceAccounts = Get-ADUser -Filter * -SearchBase $svcOU `
            -Properties Description, whenCreated, PasswordLastSet, PasswordNeverExpires,
                        ServicePrincipalName @adParams |
            Select-Object SamAccountName, UserPrincipalName, Enabled,
                @{N='AccountType';E={'ServiceAccount'}},
                Description, whenCreated, PasswordLastSet, PasswordNeverExpires,
                DistinguishedName, @{N='HasSPN';E={[bool]$_.ServicePrincipalName}}
    } catch {
        Write-Warning "  Failed to query $svcOU on $dc : $_"
    }
    Write-Host "  -> $($serviceAccounts.Count) service accounts"

    # --- Recursive group membership -----------------------------------------
    $allAccounts = @($employees) + @($external) + @($shared) + @($serviceAccounts)
    Write-Host "  Resolving recursive group membership for $($allAccounts.Count) accounts ..."
    $membershipRows = [System.Collections.Generic.List[pscustomobject]]::new()
    foreach ($acct in $allAccounts) {
        $groups = Get-ADRecursiveGroupMembership -DistinguishedName $acct.DistinguishedName -Server $server -Credential $Credential
        foreach ($g in $groups) {
            $membershipRows.Add([pscustomobject]@{
                Domain         = $dc
                SamAccountName = $acct.SamAccountName
                AccountType    = $acct.AccountType
                JobCode        = $acct.JobCode
                GroupName      = $g.GroupName
                GroupCategory  = $g.GroupCategory
                GroupScope     = $g.GroupScope
                NestedDepth    = $g.NestedDepth
                ViaGroup       = $g.ViaGroup
            })
        }
    }
    Write-Host "  -> $($membershipRows.Count) (account, group) rows"

    # --- Export ---------------------------------------------------------------
    $employees        | Export-Csv -NoTypeInformation -Path (Join-Path $OutputPath "ADUsers_${dc}_$RunStamp.csv")
    $external         | Export-Csv -NoTypeInformation -Path (Join-Path $OutputPath "ADExternalAccounts_${dc}_$RunStamp.csv")
    $shared           | Export-Csv -NoTypeInformation -Path (Join-Path $OutputPath "ADSharedAccounts_${dc}_$RunStamp.csv")
    $serviceAccounts  | Export-Csv -NoTypeInformation -Path (Join-Path $OutputPath "ADServiceAccounts_${dc}_$RunStamp.csv")
    $membershipRows   | Export-Csv -NoTypeInformation -Path (Join-Path $OutputPath "ADGroupMembership_${dc}_$RunStamp.csv")

    # --- Delegated rights (optional, slow) -------------------------------------
    if ($IncludeACLDelegation) {
        Write-Host "  Building schema/extended-rights GUID map ..."
        $guidMap = Get-ADSchemaGuidMap -Server $server -Credential $Credential

        Write-Host "  Walking OU delegation for domain root (this is the slow part) ..."
        $domainParams = @{ Server = $server }
        if ($Credential) { $domainParams['Credential'] = $Credential }
        $domainDN = (Get-ADDomain @domainParams).DistinguishedName
        $delegation = Get-ADDelegatedRights -SearchBase $domainDN -Server $server `
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
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCAzYmZoAL83WOkP
# j7H/ykpCqZtRFpn8+2ntYi6gXL1XF6CCJa8wggVvMIIEV6ADAgECAhBI/JO0YFWU
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
# AYI3AgEVMC8GCSqGSIb3DQEJBDEiBCDk2KeT0DAP4gDEIP4ryCUBX5xtvB6RUn4P
# EA6lYZ5ycjANBgkqhkiG9w0BAQEFAASCAgBOr6FQBMK5dVg1/QxnlP0Ks4eqbtL9
# 8THXGQrq81lu/ewtXQy6tq2dJEkOgzVxR1dDBhBLYyXMcw+CzxkDC63cpp+RTtL9
# IFC2gA0/d81v/vfPyaBdonSSUTqhuu8ps1EYHc4m2c0ofxJjHIs0j+6zBhMgdcWT
# jYmrO6nz28AIQbbwmlq15jLHcIuwYXbV5r+5nbKKe4hrgvKY5kWKscho05D5HV/4
# 4+cCrF4b9a9T8CQ3m+fK7yUjyNVP8Fq/ZFp2toIUZgREctvw5LJaeR9OSXMQJM5B
# yk2IMyf/kfXuy/+gW1St46GIES8owmKhtPEZHHU366poI2qf+hOGOdJKNPQznev5
# 9ewBwHy6mapX2UOm6CT3BKXX7LqBylxCvIjw8yZY9LQxKYN1N2j22tn5SYzmoyjS
# jVveVA+91Eb/BY8BHIfSsmvxP4FxNnfITELEefvtWJ3K/ljnOmmAGKoAiOkxSzH6
# mKwAsU0OAH4nBpHVcRQvOYDZpaKKE8DBykn19sbwjDdZhBrh9Cy6CFm4cXzCPVd2
# 3gZzKkaPLaMSfm90MHrxAV9WhNlKhcj4XeDITUtTN1djLdHAS3oczeEg+iiwgI3+
# rfz9Vg4936q36FszELEVEqA/hThsEfHA/iv+T1JKf7dhtuy+RZMlZ7HzUEKPwkza
# VBEO2IWHxLPuGqGCAyYwggMiBgkqhkiG9w0BCQYxggMTMIIDDwIBATB9MGkxCzAJ
# BgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwgSW5jLjFBMD8GA1UEAxM4RGln
# aUNlcnQgVHJ1c3RlZCBHNCBUaW1lU3RhbXBpbmcgUlNBNDA5NiBTSEEyNTYgMjAy
# NSBDQTECEAhP3DNPfkVO28MPj/mSGDUwDQYJYIZIAWUDBAIBBQCgaTAYBgkqhkiG
# 9w0BCQMxCwYJKoZIhvcNAQcBMBwGCSqGSIb3DQEJBTEPFw0yNjA5MTUwODUyNDla
# MC8GCSqGSIb3DQEJBDEiBCDYy5C6pdco4Dfb/kJ+dABOTRQaXku2xPFGPZtiamaV
# xzANBgkqhkiG9w0BAQEFAASCAgAjHJ7uH+S9ctTja34a58Rl5FelPhJSA6kWwMq8
# 2bPj0WQIeYUCK/cW/u6R8Kjp9OAGONixbbvG0i/35aU6Z0C0lgBvCP2npT0lLML5
# yyxtSdIgEfrp+oZwUeNuSk8J5rprzhwd0pnL012nFEOEvtL7qqoWGqTNaEBpEa7G
# Yrq8aertQKP4sjxHTPd4nRdH3Jk357+f8mT+MuE3QdNrVXX+vALZlkY1kwZS7lDc
# vTMrmVpVEtW64AMMZHy7gU+1EMzq5zazpCo5hKfSmfr22u4vDZDFzSYtfP+j1iHy
# S+nzeX9WjMgd6LiK+8GL1bQOjuAmAKUm49u34+Wb5jq0jozPtDLxHz/nkj6Ol7zv
# P9wavMHkw1xjkab9pXcfW9cyBRPbRxp4L2Rez0mDopF1wuDJd6oLCyHz5N8eDkQ+
# sM1uk23n2e0yKs1sQUO9BeQ/TW65JMBKHoP/M3MTRWIdTUdt+Q/Aa3wLTn7/s2yh
# ZbexgaI4ZLFeI3Dl+YonmgunUyxMUtmW/v3XmXYsv7F9GiHUaTDQVcRQeBpImfFU
# USCYaFmJB4pJ8bHK+fyB8tF4oQrKP1J+Z/67Frd2tZnz8aaNJOfBkw8FDyLyLxYh
# 4h9lb4+vqVh1Py+CdSjp0+X0mRL5WhYq5oQ5z5TkqE9Ox6k9Ntt+Plde3M3eBIqN
# aj4iAw==
# SIG # End signature block
