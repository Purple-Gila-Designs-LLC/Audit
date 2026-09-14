# Privilege Audit — Hybrid AD / Entra

Full-scope audit of user and service-account rights across on-prem Active Directory
(`harddollar.local`, `IN8AZURE.local`) and Entra ID, correlated by JobCode
(`extensionAttribute2`, sourced from AD `Description` via `..\AD-Entra\Copy-JobCodes2EA2.ps1`)
to find privilege creep — rights a user has that peers in the same job code don't, and vice
versa. Goal: consolidate findings, then migrate the whole pipeline to an Azure-hosted agent the
rest of the team can run on demand.

## Status

| Piece | Status | Script |
|---|---|---|
| AD users, service accounts, recursive group membership, OU delegation | **Built**, not yet run against production | `Get-ADRightsInventory.ps1` |
| Entra Member users + directory roles (Global Admin only so far) + PIM | Existing, needs expanding to all roles + groups + app role assignments + service principals | `Run-EntraUserAudit.ps1` |
| NinjaOne server-level rights (local group membership, User Rights Assignment) | **Built**, not yet run against a live tenant — needs the one-time Automation Library/custom-field setup first | `Get-NinjaOneServerRightsInventory.ps1` + `NinjaOne\Local-RightsInventory.ps1` |
| JobCode peer-group correlation / creep report | **Not started** — needs the three collectors above producing data first | *(planned)* |
| Credential storage (Keeper Secrets Manager or Windows Credential Manager) | **Not started** — pending confirmation of Keeper Secrets Manager availability on your plan | *(planned)* |
| Azure-hosted team agent | **Not started** — target platform (Azure Automation / AI Foundry agent / hosted Claude Agent) still undecided | *(planned)* |

## Known open items

- **Rotate the client secret in `..\AD-Entra\get-AuditAllUserRoles.ps1`** — it's hardcoded in
  plaintext and that script is superseded by `Run-EntraUserAudit.ps1` (MSOnline, which it
  depends on, is retired by Microsoft). Flagged 2026-09-14, not yet actioned.
- Confirm whether `IN8AZURE.local` needs its own service account / trust considerations, or
  shares one with `harddollar.local` — `Get-ADRightsInventory.ps1` supports either via
  `-Credential`.
- NinjaOne base URL/region/scopes confirmed 2026-09-14 (`app.ninjarmm.com` = region `us`,
  Monitoring + Management + Control + offline_access). Custom fields + Automation Library
  script are done. **Blocking the test run**: script execution needs a one-time *interactive*
  login (client-credentials tokens are rejected with `user_context_required`) — see
  `docs\NinjaOne-API-Setup.md`, "Enabling script execution (user-context auth)".
- Confirm Keeper Secrets Manager (the machine-to-machine add-on, distinct from interactive
  Keeper Commander) is enabled on your Keeper plan.

## Running what's built today

```powershell
# On-prem AD inventory, both domains, group membership only (fast)
.\Get-ADRightsInventory.ps1

# Same, plus OU delegation (ACL) walk - slower, run against a lab/test OU first
.\Get-ADRightsInventory.ps1 -IncludeACLDelegation

# Entra: Global Admins + per-user directory roles, uploaded to SharePoint
. .\Run-EntraUserAudit.ps1
Run-EntraUserAudit -TenantId <tid> -ClientId <cid> -ClientSecret <secret> `
    -SharePointSiteUrl 'https://harddollarcorp.sharepoint.com/sites/SCCM' `
    -SharePointFolderPath 'Shared Documents/Audit'

# NinjaOne: server-level local rights, one test device first (see docs\NinjaOne-API-Setup.md
# for the required one-time custom-field + Automation Library setup)
.\Get-NinjaOneServerRightsInventory.ps1 -ClientId <cid> -ClientSecret <secret> `
    -TargetSystemNames 'ONE-TEST-SERVER'
```

See `docs\Entra-AppRegistration-Setup.md`, `docs\AD-Service-Account-Setup.md`, and
`docs\NinjaOne-API-Setup.md` for the credentials/one-time setup each script needs.

## Next steps, in order

1. Rotate the exposed secret and confirm `Run-EntraUserAudit.ps1`'s app registration has the
   full permission set in `docs\Entra-AppRegistration-Setup.md`.
2. Expand `Run-EntraUserAudit.ps1` (or a new script alongside it) to cover all directory roles
   (not just Global Admin), group-based access, app role assignments, and service principals.
3. Do the NinjaOne one-time setup (`docs\NinjaOne-API-Setup.md`) and run the single-device test
   before a full rollout.
4. Wire credential retrieval through Keeper Secrets Manager (or Credential Manager as fallback)
   instead of parameters/plaintext, once KSM availability is confirmed.
5. Build the JobCode correlation report once all three collectors are producing data.
6. Decide the Azure-hosted agent target and port the collectors to it.
