# Entra App Registration — Privilege Audit

App Registration used for unattended (client-credential) collection by `Run-EntraUserAudit.ps1`
and its planned expansion (see `..\README.md` for scope/status). Tenant: see `$TenantId` used
when the script is run — do not hardcode it in any file committed to this repo.

## Create the app

1. Entra admin center → **App registrations** → **New registration**.
   - Name: e.g. `PrivilegeAudit-Collector`
   - Supported account types: single tenant
   - No redirect URI needed (client-credential flow only)
2. **Certificates & secrets** → **New client secret**. Record the value immediately (shown once).
   Store it in Keeper/Credential Manager per `AD-Service-Account-Setup.md` — never in a script file.
3. Set an explicit **expiry reminder** for the secret (max 24 months) — an audit tool going dark
   silently because a secret expired defeats the purpose.

## Microsoft Graph — Application permissions

Grant these as **Application** permissions (not delegated), then have a Global Administrator or
Privileged Role Administrator click **Grant admin consent**:

| Permission | Why | Used by |
|---|---|---|
| `Directory.Read.All` | Users, groups, memberships, directory objects | current + expanded |
| `RoleManagement.Read.Directory` | Directory role assignments incl. PIM eligible/active schedules, for **all** roles (current script only checks Global Admin) | expansion |
| `Application.Read.All` | Service principals, app registrations, app role assignments, owners, credential expiry | expansion |
| `Sites.ReadWrite.All` (or `Sites.Selected` scoped to the target site) | Upload CSV reports to SharePoint | current |
| `AuditLog.Read.All` *(optional)* | Sign-in logs — lets the report distinguish "has this right" from "actually uses it," useful for the job-code creep analysis | expansion, optional |
| `Policy.Read.All` *(optional)* | Conditional Access policy assignments | expansion, optional |

`User.Read.All` / `Group.Read.All` are subsumed by `Directory.Read.All` and were left off.

If `Sites.ReadWrite.All` is broader than you want, switch to `Sites.Selected` and grant the app
access to only the target SharePoint site via `POST /sites/{site-id}/permissions` — see
[Microsoft Learn: Sites.Selected](https://learn.microsoft.com/graph/permissions-reference#sitesselected).

## Azure RBAC (only if Azure resource-level roles are added to scope)

Azure subscription/resource-group/resource role assignments are **not** a Graph permission —
they're a separate Azure RBAC grant. If/when that's added to scope:

```powershell
# Reader at Management Group root covers every subscription underneath in one grant
az role assignment create `
    --assignee <app-service-principal-object-id> `
    --role "Reader" `
    --scope "/providers/Microsoft.Management/managementGroups/<mg-root-id>"
```

## Verifying the app works

```powershell
$body = @{
    client_id     = $ClientId
    scope         = 'https://graph.microsoft.com/.default'
    client_secret = $ClientSecret
    grant_type    = 'client_credentials'
}
Invoke-RestMethod -Method Post -Uri "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token" -Body $body
# Should return an access_token. Then:
Invoke-RestMethod -Uri 'https://graph.microsoft.com/v1.0/users?$top=1' -Headers @{ Authorization = "Bearer $($token.access_token)" }
```

If the second call 403s, admin consent hasn't been granted yet (or was granted for the wrong permission set).
