# AD Service Account — Privilege Audit

Read-only service account for `Get-ADRightsInventory.ps1`, used against both `harddollar.local`
and `IN8AZURE.local`. A two-way trust between the two domains is confirmed in place as of
2026-09-14, so a single account is expected to work for both as long as it's been delegated read
access on each side — no need for one account per domain.

**Status: done.** `HARDDOLLAR\svc-priv-audit` has been created, with rights/restrictions granted
per the guidance below.

## Create the account

1. Create in a dedicated service-account OU (this environment already keeps service accounts
   separate under `OU=Service,OU=InEight Users,DC=harddollar,DC=local` — use the equivalent
   location, or create one, in `IN8AZURE.local` too).
2. Naming suggestion: `svc-priv-audit`. → **used**: `HARDDOLLAR\svc-priv-audit`.
3. Password: set to never expire is the normal (if imperfect) tradeoff for a non-interactive
   account — mitigate by storing it only in Credential Manager/SecretManagement (never in a
   script) and rotating on a schedule.
4. **Do not add it to any privileged built-in group** (Domain Admins, Account Operators, Backup
   Operators, Server Operators, Print Operators, DNS Admins). An audit tool with standing
   privileged rights defeats its own purpose — it should need *nothing* beyond read.
5. Restrict logon rights via GPO: deny interactive/RDP logon, allow only "Log on as a batch job"
   (if run via Scheduled Task) or "Log on as a service" (if run as an Automation Account /
   scheduled agent later).

## Grant read access (delegation, not group membership)

Reading user/group objects, `memberOf`, and OU ACLs does **not** require any special AD right
beyond ordinary read access, which `Authenticated Users` normally already has in most
environments. If this environment has hardened default read access, delegate explicitly instead
of adding the account to a privileged group:

```powershell
# Run as a domain admin, once, against each domain's root
dsacls "DC=harddollar,DC=local" /I:S /G "HARDDOLLAR\svc-priv-audit:GR"
dsacls "DC=harddollar,DC=local" /I:S /G "HARDDOLLAR\svc-priv-audit:LC"
```

Or via the GUI: ADUC → right-click the domain (or the specific OUs) → **Delegate Control** →
add `svc-priv-audit` → **Read all properties**, **List contents**.

`Get-ADRightsInventory.ps1 -IncludeACLDelegation` reads DACLs (`Get-Acl AD:\...`) to report
delegation itself — this needs no extra right beyond the read access above; reading a DACL is
part of ordinary object read.

### OU scope (as of 2026-09-14)

Delegation needs to cover all four account-type OUs under `OU=InEight Users`, not just
`Internal`/`Service`:

| OU (relative to `OU=InEight Users,DC=harddollar,DC=local`) | Script parameter | Contents |
|---|---|---|
| `OU=Internal` | `-EmployeeOU` | Employees (JobCode-bearing) |
| `OU=External` | `-ExternalOU` | Contractors / other non-employee interactive user types |
| `OU=Shared` | `-SharedOU` | Shared/business-function logons used by multiple people |
| `OU=Service` | `-ServiceAccountOU` | Service accounts (incl. `svc-priv-audit` itself) |

If delegation was scoped narrowly to `Internal`/`Service` only, extend it to `External` and
`Shared` too — either re-run the `dsacls`/Delegate Control step above against
`OU=InEight Users,DC=harddollar,DC=local` (covers all four in one shot, since delegation is
inherited down the OU tree by default) or repeat it per-OU if you'd rather keep the grants
narrow.

## Verifying the account works

```powershell
$cred = Get-Credential   # HARDDOLLAR\svc-priv-audit
Get-ADUser -Filter * -SearchBase 'OU=Internal,OU=InEight Users,DC=harddollar,DC=local' `
    -Server 'harddollar.local' -Credential $cred -ResultSetSize 1

# Confirm the cross-domain trust works for this account too
Get-ADUser -Filter * -SearchBase 'OU=Internal,OU=InEight Users,DC=IN8AZURE,DC=local' `
    -Server 'IN8AZURE.local' -Credential $cred -ResultSetSize 1
```

If either returns a user, the account has sufficient read access on that domain. If it errors
with access denied, that domain has tightened default read permissions and the delegation step
above is required there.

## Storing the credential

`Get-ADRightsInventory.ps1` resolves its credential from
`Microsoft.PowerShell.SecretManagement` automatically (falls back to the identity running the
script if nothing is stored) — same pattern as `Run-EntraUserAudit.ps1`
(`Entra-TenantId`/`Entra-ClientId`/`Entra-ClientSecret`) and the NinjaOne orchestrator
(`NinjaOne-ClientId`/`NinjaOne-ClientSecret`), all against the local `PGDLocalVault`
(`Microsoft.PowerShell.SecretStore`) today — this is what swaps to Keeper Secrets Manager later
with zero script changes once/if that's confirmed available (still unconfirmed — see README
"Known open items").

Unlike the Entra/NinjaOne secrets (which are separate GUID/string values), an AD credential is a
`PSCredential` (username + password together), and `SecretManagement`/`SecretStore` store that
type natively — so it's a single secret, not a pair:

```powershell
Set-Secret -Name 'AD-ServiceAccount' -Secret (Get-Credential 'HARDDOLLAR\svc-priv-audit')
```

That's the one name to use — `Get-ADRightsInventory.ps1 -CredentialSecretName` defaults to it,
so a plain `.\Get-ADRightsInventory.ps1` run picks it up with no other setup. Override
`-CredentialSecretName` (or pass `-Credential` directly) only for one-off testing with a
different identity.
