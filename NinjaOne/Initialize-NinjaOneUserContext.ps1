<#
.SYNOPSIS
    One-time bootstrap: performs the NinjaOne interactive (Authorization Code) login and
    stores the resulting refresh token, so Get-NinjaOneServerRightsInventory.ps1 can run
    script invocations unattended afterward.

.DESCRIPTION
    Connect-NinjaOne -UseWebAuth (the module's built-in interactive flow) has a hardcoded
    15-second timeout waiting for the OAuth callback - confirmed by reading the installed
    module's source (Start-OAuthHTTPListener, NinjaOne.psm1) - which is not enough time for a
    real human login (especially with MFA). This script re-implements the same flow with a
    much longer timeout (-TimeoutSeconds, default 300) and stores the result the same way the
    module would, so Get-NinjaOneServerRightsInventory.ps1's existing vault-read logic works
    unchanged.

    Requires: the NinjaOne API app's registered Redirect URI must be exactly
    'http://localhost:<Port>/' (default port 9090) - this script's listener, like the module's,
    only ever binds to localhost. A redirect URI pointing anywhere else (an external domain,
    for example) cannot be captured here - the OAuth provider will deliver the code to that
    other endpoint instead, not to this script, regardless of timeout.

.PARAMETER Port
    Local port to listen on for the OAuth callback. Must match the NinjaOne app's registered
    Redirect URI (http://localhost:<Port>/). Default 9090.

.PARAMETER TimeoutSeconds
    How long to wait for the browser login to complete. Default 300 (5 minutes) - override
    with -TimeoutSeconds if MFA in your environment typically takes longer.

.PARAMETER Instance
    NinjaOne region code (eu|oc|us|ca|us2). Default 'us'.

.PARAMETER Scopes
    OAuth scopes to request. Default matches the tenant's granted scopes.

.EXAMPLE
    .\Initialize-NinjaOneUserContext.ps1

    Run this once, interactively, by whichever NinjaOne user should be attributed as running
    the rights-inventory scripts going forward.

.NOTES
    Author  : RTillmon - InEight Technology Operations (with Claude Code)
    Version : 1.0.0
    Created : 2026-09-14

    Endpoints (ws/oauth/authorize, ws/oauth/token) and request bodies match the installed
    NinjaOne module's own implementation exactly (confirmed by reading NinjaOne.psm1), so the
    resulting tokens are stored under the same secret names (NinjaOne<Field>, no hyphen) the
    module itself uses - Connect-NinjaOne -ReadFromSecretVault reads them the same way either
    script wrote them.
#>

[CmdletBinding()]
param(
    [int]$Port = 9090,
    [int]$TimeoutSeconds = 300,
    [ValidateSet('eu', 'oc', 'us', 'ca', 'us2')]
    [string]$Instance = 'us',
    [string[]]$Scopes = @('monitoring', 'management', 'control', 'offline_access'),
    [string]$VaultName = 'PGDLocalVault',
    [string]$SecretPrefix = 'NinjaOne'
)

Import-Module Microsoft.PowerShell.SecretManagement -ErrorAction Stop

$InstanceUrls = @{
    eu = 'https://eu.ninjarmm.com'; oc = 'https://oc.ninjarmm.com'; us = 'https://app.ninjarmm.com'
    ca = 'https://ca.ninjarmm.com'; us2 = 'https://us2.ninjarmm.com'
}
$BaseUrl = $InstanceUrls[$Instance]

$ClientId = Get-Secret -Name "$SecretPrefix-ClientId" -AsPlainText -ErrorAction Stop
$ClientSecret = Get-Secret -Name "$SecretPrefix-ClientSecret" -AsPlainText -ErrorAction Stop

$RedirectUri = "http://localhost:$Port/"
$State = [guid]::NewGuid().ToString()
$ScopeString = $Scopes -join ' '

$AuthorizeUri = "$BaseUrl/ws/oauth/authorize" +
    "?response_type=code" +
    "&client_id=$([uri]::EscapeDataString($ClientId))" +
    "&client_secret=$([uri]::EscapeDataString($ClientSecret))" +
    "&redirect_uri=$([uri]::EscapeDataString($RedirectUri))" +
    "&state=$State" +
    "&scope=$([uri]::EscapeDataString($ScopeString))"

Write-Host "Redirect URI this script will listen on: $RedirectUri" -ForegroundColor Yellow
Write-Host "This MUST exactly match a Redirect URI registered on the NinjaOne API app, or the callback will never arrive here." -ForegroundColor Yellow
Write-Host "Starting local listener and opening browser (timeout: $TimeoutSeconds seconds) ..." -ForegroundColor Cyan

$Http = [System.Net.HttpListener]::new()
$Http.Prefixes.Add($RedirectUri)
$Http.Start()

try {
    Start-Process $AuthorizeUri

    $ContextTask = $Http.GetContextAsync()
    if (-not $ContextTask.AsyncWaitHandle.WaitOne([TimeSpan]::FromSeconds($TimeoutSeconds))) {
        throw "Timed out after $TimeoutSeconds seconds waiting for the OAuth callback. Either the browser never opened/completed login, or the Redirect URI registered on the NinjaOne app doesn't exactly match $RedirectUri."
    }

    $Context = $ContextTask.GetAwaiter().GetResult()
    $Query = $Context.Request.QueryString
    $Code = $Query['code']
    $ReturnedState = $Query['state']
    $ErrorParam = $Query['error']

    $Html = if ($Code -and $ReturnedState -eq $State) {
        '<h1>NinjaOne login received</h1><p>You can close this tab.</p>'
    } else {
        "<h1>NinjaOne login failed</h1><p>$ErrorParam</p><p>You can close this tab.</p>"
    }
    $ResponseBytes = [System.Text.Encoding]::UTF8.GetBytes($Html)
    $Context.Response.ContentLength64 = $ResponseBytes.Length
    $Context.Response.OutputStream.Write($ResponseBytes, 0, $ResponseBytes.Length)
    $Context.Response.OutputStream.Close()
} finally {
    if ($Http.IsListening) { $Http.Stop() }
    $Http.Dispose()
}

if (-not $Code) {
    throw "No authorization code received. NinjaOne reported: $ErrorParam"
}
if ($ReturnedState -ne $State) {
    throw 'State mismatch on OAuth callback - possible CSRF, aborting without exchanging the code.'
}
Write-Host "Authorization code received. Exchanging for tokens ..." -ForegroundColor Cyan

$TokenBody = @{
    grant_type    = 'authorization_code'
    client_id     = $ClientId
    client_secret = $ClientSecret
    code          = $Code
    redirect_uri  = $RedirectUri
    scope         = $ScopeString
}
$TokenResponse = Invoke-RestMethod -Method Post -Uri "$BaseUrl/ws/oauth/token" -Body $TokenBody -ContentType 'application/x-www-form-urlencoded'

if (-not $TokenResponse.refresh_token) {
    throw 'Token exchange succeeded but no refresh_token was returned - check the offline_access scope was requested and granted.'
}

# Store using the same (unprefixed-with-dash) secret names Connect-NinjaOne's own
# -WriteToSecretVault uses, so its -ReadFromSecretVault reads these back identically.
Set-Secret -Name "${SecretPrefix}Refresh" -Secret $TokenResponse.refresh_token -Vault $VaultName
Set-Secret -Name "${SecretPrefix}Access" -Secret $TokenResponse.access_token -Vault $VaultName
Set-Secret -Name "${SecretPrefix}Type" -Secret $TokenResponse.token_type -Vault $VaultName
$ExpiresAt = (Get-Date).AddSeconds([int]$TokenResponse.expires_in).ToString('o')
Set-Secret -Name "${SecretPrefix}Expires" -Secret $ExpiresAt -Vault $VaultName

Write-Host "Done. Refresh token stored in vault '$VaultName' as '${SecretPrefix}Refresh'." -ForegroundColor Green
Write-Host "Get-NinjaOneServerRightsInventory.ps1 will now use -UseTokenAuth automatically." -ForegroundColor Green

# SIG # Begin signature block
# MIIsoAYJKoZIhvcNAQcCoIIskTCCLI0CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCC4viTZFJCotGfV
# jmLb2TGkR7mn3alsWHfiU6aXdhHzAKCCJa8wggVvMIIEV6ADAgECAhBI/JO0YFWU
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
# AYI3AgEVMC8GCSqGSIb3DQEJBDEiBCAkzC6VuVlS1OgUPO2TRiABq/gFnMOlrqna
# g4HjmJLopTANBgkqhkiG9w0BAQEFAASCAgDHivK083nxv28NAYOu+eqAvNVUOAzV
# PEG+qo3S9Gd7r0qvPGGrmw2UGpe0dXmKYzD5EE4YPPti/MU6AuXu2cl5Sxmuyb6t
# 4ZVu7XEEZMMQNPW9ddbK4j21k69s79X+zYTYPuATrtaqjyFYPZnvt8SUc1RdHxjR
# dv58/XCQ7l5yJlVwBkjHd1zhaZF3JbG9uWacNJnmgQBtvBCJLO4GzV7mgUbOakpR
# 0iEQCobuPDz5eytO3P/LsfL/WonhD6jmTccTXmLU51m4vlRY2xVNNZmF+y6vYs4c
# Z638xQ22R+bX2G70UdGKieQgg4P/lWB7q+5vZKHDS9XczCxNQjzZiJcFcV+GY+BL
# EyFa2Hq1rSiSjOofZH6i0afcF6C7KNF5Qeh3UewDTroyiHhViZMgeJTFUBy33wF2
# NMcq6At1uYyU4A7C9KT67Bcl1R/wk6jmIB55Tc2jOJmUPQq308ms9UsefOWi1ypZ
# sRQ7pvCe8z/4lA2y5UxVfRRqo6mw/Pay0QHF/RJjOMNLLCgJJClwgGRcEzrk2pzr
# cmOSqAdOgVCj8t2GCaCORD0VMQX9PN9xZUVVVpo07ENQ6qEMA/zEsJVTUk4XjA/T
# xhDAHRQdJi3Wjorovf9bCOsQUh9mUQRmCWQaW7U7bxaPwyM0dCTU4pREVtnPshv5
# FKVhqFJljzQ+1KGCAyYwggMiBgkqhkiG9w0BCQYxggMTMIIDDwIBATB9MGkxCzAJ
# BgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwgSW5jLjFBMD8GA1UEAxM4RGln
# aUNlcnQgVHJ1c3RlZCBHNCBUaW1lU3RhbXBpbmcgUlNBNDA5NiBTSEEyNTYgMjAy
# NSBDQTECEAhP3DNPfkVO28MPj/mSGDUwDQYJYIZIAWUDBAIBBQCgaTAYBgkqhkiG
# 9w0BCQMxCwYJKoZIhvcNAQcBMBwGCSqGSIb3DQEJBTEPFw0yNjA5MTQyMjQxMTBa
# MC8GCSqGSIb3DQEJBDEiBCC0EjUhdw2JSPTU0q+pAgHo6qW/47YX+NcJXvxIYtx6
# RTANBgkqhkiG9w0BAQEFAASCAgCIZZrQ0HQ52H0y3k3n0anjcA9eP3fqD5yyrJqM
# yKCPKWY+DoGSf5N4bcqSIiIAYNhdinGOD9pGEKQ5MdvUh6vGBqLmUYrwCZImSdCp
# 5xG5hBc3qs0pJJivy2a5sloaIH65mSSTi1BAIU/V0NqGCmqG6ME9Zjt6yYZSWzrC
# Ub/b8RJaKNV3dSkkq2jCUZU5vZTRzcCudP/BuYDW4cDEyF/VUhQV8jtFZaErIH0l
# lnbeJFaR9qwKLBqhuReH2Fuw0LPxHKsukDUBbLf/EpxPmnLo5DCNPU0Qjtzxhq0d
# 7YIhDbB/NIV8rUEZ9gSSJlBDMu18c6TboWIdIPewvfL8RfKosWMuuFbT+0Drh6rX
# 6QB7gOrFYPq7b5WyXYc9iejB7H+yHFX8AwxjE1EMo7MQbvOuYuo9IyT/IfYIZL+9
# WWA0/IC30vtb+PJ3IlXubybSU0ZLrzdHeRbmtz0fVAXdZ+cg4LjidAKlfNdQbhpz
# Hgcf8tZSnTNiez6rK2ijYLccTHzr/H4TDbkXrwjnGsLA79Ln9thIi93YD6DG8iHN
# DADMzvObMn7RgiE9bYAMGJQAfVLDzo6JrdOKS+spF4Pi2VGRT8KcdeGtvRnHmfcU
# paHtWRqWT6sPc3yJlMylsB2pBC+fTDiDNNl15LKAeKP6qyjNHApJo39Bmy1xWoAY
# tl5OnQ==
# SIG # End signature block
