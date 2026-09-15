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
| AD users (Employee/External/Shared/Service), recursive group membership, OU delegation | **Built** — `svc-priv-audit` service account created + secret stored, not yet run against production | `Get-ADRightsInventory.ps1` |
| Entra Member users + all directory roles (active+PIM, group-expanded) + groups + enterprise-app access + service principal inventory | **Live run complete** 2026-09-14 — 569 role-assignment rows (69 active roles + 64 PIM-eligible), 1,589 active Member users, 14,506 service principals; all uploaded to SharePoint | `Run-EntraUserAudit.ps1` |
| NinjaOne server-level rights (local group membership, User Rights Assignment) | **Full-fleet run complete** 2026-09-14 — 51/56 `WINDOWS_SERVER` devices (5 failures, all long-offline machines, not a pipeline issue): 278 local group rows, 3,691 user rights rows | `Get-NinjaOneServerRightsInventory.ps1` + `NinjaOne\Local-RightsInventory.ps1` |
| JobCode peer-group correlation / creep report | **Not started** — needs the three collectors above producing data first | *(planned)* |
| Credential storage (Keeper Secrets Manager or Windows Credential Manager) | **Not started** — pending confirmation of Keeper Secrets Manager availability on your plan | *(planned)* |
| Azure-hosted team agent | **Not started** — target platform (Azure Automation / AI Foundry agent / hosted Claude Agent) still undecided | *(planned)* |

## Known open items

- **Rotate the client secret in `..\AD-Entra\get-AuditAllUserRoles.ps1`** — it's hardcoded in
  plaintext and that script is superseded by `Run-EntraUserAudit.ps1` (MSOnline, which it
  depends on, is retired by Microsoft). Flagged 2026-09-14, not yet actioned.
- `HARDDOLLAR\svc-priv-audit` created 2026-09-14 — dedicated, read-only-delegated, no privileged
  group membership. Trust between `harddollar.local` and `IN8AZURE.local` is confirmed in place,
  so this single account covers both domains (credential resolves from the `AD-ServiceAccount`
  SecretManagement secret automatically — see `docs\AD-Service-Account-Setup.md`).
- Scope expanded 2026-09-14 at Roger's request: `Get-ADRightsInventory.ps1` now also inventories
  `OU=External` (contractors/non-employee interactive types) and `OU=Shared` (shared/
  business-function logons) under `InEight Users`, alongside `Internal` and `Service` — each
  account tagged with `AccountType` in the CSVs.
- NinjaOne pipeline fully validated live 2026-09-14 — see `docs\NinjaOne-API-Setup.md`. Notable
  along the way: the original API app ("Client App ID" type) couldn't do the interactive login
  needed for script execution at all (`unauthorized_client: Invalid grant type for client`) —
  had to create a second app of the "Web" type (`Web-AutomationRunner`) specifically for that.
  Remaining decision: scope of the first full-fleet run (all 56 `WINDOWS_SERVER` devices, or a
  smaller batch first) and how often to re-run.
- Confirm Keeper Secrets Manager (the machine-to-machine add-on, distinct from interactive
  Keeper Commander) is enabled on your Keeper plan.
- **Deferred by explicit request (2026-09-14), not dropped**: `EnterpriseAppAccess` in
  `AuditEntraUsers.csv` only reflects direct app role assignments (not via group) and lists the
  app name rather than the specific role within it; `AuditEntraServicePrincipals.csv` doesn't
  include owners. Revisit both once the JobCode correlation work surfaces whether they're
  actually needed for that analysis. Also worth a filtered follow-up view of the 14,506 service
  principals (most are Microsoft first-party apps every tenant has by default) — e.g. only SPs
  with active credentials, or excluding known Microsoft app IDs — to find the ones that matter.

## Running what's built today

```powershell
# On-prem AD inventory, both domains, all 4 account types (Employee/External/Shared/Service),
# group membership only (fast). Credential resolves from the 'AD-ServiceAccount' secret automatically.
.\Get-ADRightsInventory.ps1

# Same, plus OU delegation (ACL) walk - slower, run against a lab/test OU first
.\Get-ADRightsInventory.ps1 -IncludeACLDelegation

# Entra: all directory roles (active+PIM, group-expanded), per-user groups/app access,
# service principal inventory - three CSVs uploaded to SharePoint. Credentials pull from
# SecretManagement automatically (Entra-TenantId/Entra-ClientId/Entra-ClientSecret).
. .\Run-EntraUserAudit.ps1
Run-EntraUserAudit

# NinjaOne: server-level local rights - validated against one test device 2026-09-14.
# Credentials pull from SecretManagement automatically; omit -TargetSystemNames for a full run.
.\Get-NinjaOneServerRightsInventory.ps1 -TargetSystemNames 'ONE-TEST-SERVER'
```

See `docs\Entra-AppRegistration-Setup.md`, `docs\AD-Service-Account-Setup.md`, and
`docs\NinjaOne-API-Setup.md` for the credentials/one-time setup each script needs.

## Next steps, in order

1. Run `Get-ADRightsInventory.ps1` against production, both domains — `svc-priv-audit` and its
   secret are ready; confirm delegation reaches `OU=External`/`OU=Shared` too (see
   `docs\AD-Service-Account-Setup.md`), then do the quick group-membership pass first.
2. Rotate the exposed secret in `..\AD-Entra\get-AuditAllUserRoles.ps1` (still not actioned).
3. Look into the 5 long-offline NinjaOne devices from an ops angle (separate from this audit) —
   `NinjaCollectionFailures_20260914_154820.csv` has the list; `CO1SWVSS01` hasn't checked in
   since February.
4. Wire credential retrieval through Keeper Secrets Manager (or Credential Manager as fallback)
   instead of parameters/plaintext, once KSM availability is confirmed.
5. Build the JobCode correlation report — Entra and NinjaOne now have live data; AD is the last
   piece once step 1 above is done.
6. Decide the Azure-hosted agent target and port the collectors to it.
7. Revisit `EnterpriseAppAccess` group-attribution/role-name resolution and service principal
   owners (deferred by request — see "Known open items").
