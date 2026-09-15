# NinjaOne API — Server Rights Inventory

Confirmed 2026-09-14: US region, base URL `https://app.ninjarmm.com`, API app already exists
with scopes **Monitoring, Management, Control, offline_access** granted. The NinjaOne
PowerShell module (v2.0.4, [homotechsual/NinjaOne](https://github.com/homotechsual/NinjaOne)) is
already installed locally — `Get-NinjaOneServerRightsInventory.ps1` and
`NinjaOne\Local-RightsInventory.ps1` are built against its actual v2.0.4 source (confirmed by
reading the installed module, not guessed), including endpoints and response shapes.

## How the two pieces fit together

- **`NinjaOne\Local-RightsInventory.ps1`** — the payload. Gets pasted into NinjaOne's
  Automation Library (it does *not* run from a console) and executes on each target device via
  the NinjaOne agent, as SYSTEM. Collects local group membership + User Rights Assignment,
  writes the (compressed) result to two device custom fields.
- **`Get-NinjaOneServerRightsInventory.ps1`** — the orchestrator. Runs off-device (your
  workstation today; the Azure agent eventually), authenticates to the NinjaOne API with the
  Client ID/Secret, tells the Automation Library script to run on each targeted server, waits
  for it to report back, and exports the aggregate CSVs.

## One-time setup (must be done before the first run)

### 1. Create two Device-scoped custom fields

NinjaOne admin console → **Administration → Devices → Custom Fields → Add Field** (Device
scope), twice:

| Field name (technical name must match exactly) | Type | Purpose |
|---|---|---|
| `rightsInventoryPayload` | **WYSIWYG** (or the largest available text type in your NinjaOne edition) | Compressed (GZip+Base64) JSON result |
| `rightsInventoryTimestamp` | Text | UTC collection time — the orchestrator polls this to detect a completed run |

The script names are hardcoded as defaults in both scripts' parameters
(`-PayloadFieldName`, `-TimestampFieldName`) — override there if you name the fields
differently. **Text-type custom fields in NinjaOne have a length limit** (compression buys
real headroom, but a very "rights-heavy" server could still exceed it) — if you see truncation
warnings in the collector's output, switch the field to WYSIWYG if you haven't already, or
raise `$MaxFieldLength` in `Local-RightsInventory.ps1` only after confirming the field's actual
limit.

### 2. Add the collection script to the Automation Library

NinjaOne admin console → **Administration → Library → Automation → Add → New Script**:
- Name: `Local-RightsInventory` (must match `-ScriptName` on the orchestrator, or note the
  script's id and pass `-ScriptId` directly instead)
- Language: PowerShell
- Paste the full contents of `NinjaOne\Local-RightsInventory.ps1`
- Run as: leave default (SYSTEM) — the orchestrator passes `-runAs 'system'` explicitly anyway

### 3. Confirm the device filter matches your tenant

The orchestrator defaults to `-DeviceFilter 'class in (WINDOWS_SERVER)'`. Verify that's the
right enum value for your tenant before a full run:

```powershell
Import-Module NinjaOne
Connect-NinjaOne -Instance 'us' -ClientId $cid -ClientSecret $secret -UseClientAuth -Scopes monitoring,management,control,offline_access
Get-NinjaOneDevices -detailed | Select-Object systemName, nodeClass -Unique | Sort-Object nodeClass
```

## Enabling script execution (user-context auth)

**Confirmed 2026-09-14, the hard way**: every read-only call (`Get-NinjaOneDevices`,
`Get-NinjaOneCustomFields`, `Get-NinjaOneAutomationScripts`, ...) works fine with the
client-credentials (`-UseClientAuth`) token from the API app alone. Actually **running** a
script — `Invoke-NinjaOneDeviceScript`, i.e. `POST /v2/device/{id}/script/run` — does not:

```
Access key does not have user context which is required for this request
```

This is a NinjaOne platform restriction, not a scope problem — `control` scope is granted and
still isn't enough. Script execution requires a token that carries an actual user's identity,
which only comes from the interactive **Authorization Code** flow, not client-credentials.

### One-time fix: interactive login, once, by a real NinjaOne user

**Do not use `Connect-NinjaOne -UseWebAuth` directly** — confirmed by reading the installed
module's source, its built-in OAuth listener has a **hardcoded 15-second timeout**, nowhere
near enough time to actually complete a login with MFA. `NinjaOne\Initialize-NinjaOneUserContext.ps1`
in this repo re-implements the same flow with a real (default 5-minute) timeout and writes the
result to the same secret names, so the rest of this project doesn't need to know the
difference.

1. In the NinjaOne app's settings (Administration → Apps → API → this app), the registered
   **Redirect URI must be exactly `http://localhost:9090/`**. This is not optional or a
   preference — the listener (in this script, same as the module's) only ever binds to
   localhost, so a redirect URI pointing anywhere else (e.g. an external domain) means the
   callback is delivered somewhere this script can never see it, and it will time out no matter
   how long `-TimeoutSeconds` is. If `http://localhost:9090/` can't coexist with another
   redirect URI your NinjaOne app already needs for something else, set it to localhost
   temporarily for this one-time step and change it back afterward.
2. Someone with a NinjaOne account that's allowed to run scripts (this only needs to happen
   once — after this, the refresh token keeps it working unattended) runs, via `!` in the
   terminal so nothing token-related passes through chat:

   ```powershell
   cd 'G:\rt-PGD\Audit\NinjaOne'
   .\Initialize-NinjaOneUserContext.ps1
   ```

   This opens a browser for a normal NinjaOne login (MFA and all, up to 5 minutes), then writes
   the resulting access/refresh tokens into the local vault under `NinjaOneRefresh` etc.
   (module's own naming — no hyphen, distinct from the `NinjaOne-ClientId`/`NinjaOne-ClientSecret`
   names used elsewhere in this project, so there's no collision).
3. From then on, `Get-NinjaOneServerRightsInventory.ps1` detects `NinjaOneRefresh` in the vault
   automatically and connects with `-UseTokenAuth` instead of `-UseClientAuth` — no further
   interactive logins needed. The module rotates and re-saves the refresh token on every
   connect, so it keeps working indefinitely (until revoked or unused long enough to expire).
   If `NinjaOneRefresh` isn't present, the script falls back to client-credentials, which will
   run fine right up until it tries to actually invoke the script — you'll get the same
   `user_context_required` error above as the signal to come back and do this step.

## Validated 2026-09-14 against a live device (CO1SWDOCMTST01)

End-to-end run confirmed clean: 6 local group membership rows (including 2 orphaned/unresolvable
SIDs the ADSI fallback caught in Administrators — exactly the kind of finding this audit is for)
and 63 User Rights Assignment rows, 0 failures.

```powershell
.\Get-NinjaOneServerRightsInventory.ps1 -TargetSystemNames 'ONE-TEST-SERVER'
```

Confirmed along the way, in case any of it resurfaces on a different tenant/agent version:
- `Ninja-Property-Set -Name ... -Value ...` (named-parameter form) works as-is — no need for the
  piped fallback in `Local-RightsInventory.ps1` on this agent version.
- The polling loop's defaults (`-PollIntervalSeconds 20`, `-MaxWaitMinutes 10`) are generous —
  the actual run completed within about a minute.
- A WYSIWYG-type custom field's value comes back from the API as `{text, html}`, not a plain
  string — `Get-NinjaFieldText` in the orchestrator normalizes this; if you see decode errors on
  a different field type, check that function first.
- Compressed payload size (a few hundred bytes to a couple KB for a typical server) is nowhere
  near any field length limit in practice.

## Connecting (client-credential / unattended pattern)

```powershell
Import-Module NinjaOne
Connect-NinjaOne -Instance 'us' -ClientId $ClientId -ClientSecret $ClientSecret `
    -UseClientAuth -Scopes @('monitoring','management','control','offline_access')
```

`-UseClientAuth` is the non-interactive client-credentials grant — no browser/device-code
prompt, matching the same "re-runnable programmatically" requirement as the Entra app
registration.

## Credential storage

`Get-NinjaOneServerRightsInventory.ps1` resolves `$ClientId`/`$ClientSecret` from
**Microsoft.PowerShell.SecretManagement** (already installed on this machine, backed by the
local **SecretStore** vault) when `-ClientId`/`-ClientSecret` aren't passed explicitly. This is
the same abstraction the Entra and AD pieces should move to — SecretManagement supports
swappable backend vaults, and Keeper publishes a `SecretManagement.Keeper` extension vault, so
once Keeper Secrets Manager is confirmed the backend can be swapped to Keeper with **no script
changes** — only re-pointing `Register-SecretVault` at the Keeper vault instead of SecretStore.

### One-time vault setup + storing the NinjaOne credential

Run this yourself (via `!` in the terminal, not pasted into chat) so the secret value never
appears in the conversation:

```powershell
# Register the local vault once, and configure it for non-interactive (no master-password
# prompt) use - protection then comes from Windows DPAPI tied to your user profile, the same
# trust boundary as Windows Credential Manager.
if (-not (Get-SecretVault -Name PGDLocalVault -ErrorAction SilentlyContinue)) {
    Register-SecretVault -Name PGDLocalVault -ModuleName Microsoft.PowerShell.SecretStore -DefaultVault
}
Set-SecretStoreConfiguration -Authentication None -Interaction None -Confirm:$false

# Prompts mask the input - neither value is echoed or logged.
Set-Secret -Name 'NinjaOne-ClientId'     -Secret (Read-Host -Prompt 'NinjaOne Client ID' -AsSecureString)
Set-Secret -Name 'NinjaOne-ClientSecret' -Secret (Read-Host -Prompt 'NinjaOne Client Secret' -AsSecureString)
```

After this, `.\Get-NinjaOneServerRightsInventory.ps1` (no `-ClientId`/`-ClientSecret` needed)
pulls both automatically. Verify with `Get-SecretInfo` (lists secret **names** only, never
values).
