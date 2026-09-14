# AD Service Account — Privilege Audit

Read-only service account for `Get-ADRightsInventory.ps1`, used against both `harddollar.local`
and `IN8AZURE.local`. If there is no trust between the two domains, create one account per
domain rather than trying to share a single identity across both.

## Create the account

1. Create in a dedicated service-account OU (this environment already keeps service accounts
   separate under `OU=Service,OU=InEight Users,DC=harddollar,DC=local` — use the equivalent
   location, or create one, in `IN8AZURE.local` too).
2. Naming suggestion: `svc-priv-audit`.
3. Password: set to never expire is the normal (if imperfect) tradeoff for a non-interactive
   account — mitigate by storing it only in Keeper/Credential Manager (never in a script) and
   rotating on a schedule.
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

Or via the GUI: ADUC → right-click the domain (or the specific employee/service OUs) →
**Delegate Control** → add `svc-priv-audit` → **Read all properties**, **List contents**.

`Get-ADRightsInventory.ps1 -IncludeACLDelegation` reads DACLs (`Get-Acl AD:\...`) to report
delegation itself — this needs no extra right beyond the read access above; reading a DACL is
part of ordinary object read.

## Verifying the account works

```powershell
$cred = Get-Credential   # svc-priv-audit
Get-ADUser -Filter * -SearchBase 'OU=Internal,OU=InEight Users,DC=harddollar,DC=local' `
    -Server 'harddollar.local' -Credential $cred -ResultSetSize 1
```

If this returns a user, the account has sufficient read access. If it errors with access denied,
the domain has tightened default read permissions and step 2 above (explicit delegation) is
required.

## Storing the credential

See the main `README.md` for the Keeper Secrets Manager / Windows Credential Manager pattern —
the same secret-retrieval approach used for the Entra app's Tenant ID / Client ID / Client
Secret should be used here, so `Get-ADRightsInventory.ps1` never has the account's password
written into a script or scheduled-task definition.
