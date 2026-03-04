param(
  [string]$BaseUrl = "http://localhost:8080",
  [string]$TdrUrl = "http://localhost:8000",
  [string]$Username = "admin",
  [string]$Password = "pass12345678",
  [int]$Rounds = 10,
  [int]$DelayMs = 120
)

$ErrorActionPreference = "Stop"

function Invoke-Probe {
  param(
    [string]$Url
  )

  try {
    Invoke-WebRequest -UseBasicParsing -Uri $Url -Headers @{
      "User-Agent" = "tdr-sim/1.0"
    } | Out-Null
  } catch {
    # Non-2xx is expected for probes and honeypots.
  }
}

function Get-Summary {
  param(
    [string]$Url,
    [string]$AccessToken
  )

  try {
    return Invoke-RestMethod -Uri "$Url/summary" -Headers @{
      "Authorization" = "Bearer $AccessToken"
    }
  } catch {
    return $null
  }
}

function Get-AccessToken {
  param(
    [string]$AuthBaseUrl,
    [string]$AuthUser,
    [string]$AuthPass
  )

  try {
    $session = New-Object Microsoft.PowerShell.Commands.WebRequestSession
    $csrfPayload = Invoke-RestMethod -Uri "$AuthBaseUrl/api/csrf-token" -WebSession $session
    if (-not $csrfPayload.csrfToken) {
      return $null
    }

    $loginPayload = @{
      username = $AuthUser
      password = $AuthPass
    } | ConvertTo-Json

    $login = Invoke-RestMethod -Method Post -Uri "$AuthBaseUrl/api/auth/login" -WebSession $session -Headers @{
      "x-csrf-token" = $csrfPayload.csrfToken
      "content-type" = "application/json"
    } -Body $loginPayload

    return $login.accessToken
  } catch {
    return $null
  }
}

$accessToken = Get-AccessToken -AuthBaseUrl $BaseUrl -AuthUser $Username -AuthPass $Password
if (-not $accessToken) {
  Write-Host "Could not authenticate to web app at $BaseUrl (user=$Username)."
  exit 1
}

$before = Get-Summary -Url $TdrUrl -AccessToken $accessToken
if ($before) {
  Write-Host "Before: alerts=$($before.activeAlerts) blockedIps=$($before.blockedIps) honeypotTriggers=$($before.honeypotTriggers)"
}

for ($i = 1; $i -le $Rounds; $i++) {
  # Honeypot endpoints generate high-risk events.
  Invoke-Probe -Url "$BaseUrl/.env"
  Invoke-Probe -Url "$BaseUrl/admin-backup"
  Invoke-Probe -Url "$BaseUrl/internal-debug"

  # Unauthorized access attempt (creates auth failures in logs).
  Invoke-Probe -Url "$BaseUrl/api/admin/secure-report"

  # Suspicious path text to trigger signature checks in detection.
  Invoke-Probe -Url "$BaseUrl/api/union%20select"

  Start-Sleep -Milliseconds $DelayMs
}

Start-Sleep -Seconds 2
$after = Get-Summary -Url $TdrUrl -AccessToken $accessToken
if ($after) {
  Write-Host "After : alerts=$($after.activeAlerts) blockedIps=$($after.blockedIps) honeypotTriggers=$($after.honeypotTriggers)"
  Write-Host "Top patterns:"
  $after.topAttackPatterns | Select-Object -First 5 | ForEach-Object {
    Write-Host " - $($_.pattern): $($_.count)"
  }
} else {
  Write-Host "Could not read authenticated threat summary from $TdrUrl/summary"
}
