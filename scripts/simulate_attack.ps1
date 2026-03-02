param(
  [string]$BaseUrl = "http://localhost:3000",
  [string]$SocUrl = "http://localhost:8000",
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
      "User-Agent" = "soc-sim/1.0"
    } | Out-Null
  } catch {
    # Non-2xx is expected for probes and honeypots.
  }
}

function Get-Summary {
  param(
    [string]$Url
  )

  try {
    return Invoke-RestMethod -Uri "$Url/summary"
  } catch {
    return $null
  }
}

$before = Get-Summary -Url $SocUrl
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
$after = Get-Summary -Url $SocUrl
if ($after) {
  Write-Host "After : alerts=$($after.activeAlerts) blockedIps=$($after.blockedIps) honeypotTriggers=$($after.honeypotTriggers)"
  Write-Host "Top patterns:"
  $after.topAttackPatterns | Select-Object -First 5 | ForEach-Object {
    Write-Host " - $($_.pattern): $($_.count)"
  }
} else {
  Write-Host "Could not read SOC summary from $SocUrl/summary"
}

