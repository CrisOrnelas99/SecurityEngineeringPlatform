param(
  [string]$BaseUrl = "http://localhost:8080",
  [string]$TdrUrl = "http://localhost:8000",
  [string]$AdminUser = "admin",
  [string]$AdminPass = "pass12345678",
  [string]$LabAnalystUser = "analystlab"
)

$ErrorActionPreference = "Stop"

function Get-CsrfToken {
  param([Microsoft.PowerShell.Commands.WebRequestSession]$Session)
  (Invoke-RestMethod -Method Get -Uri "$BaseUrl/api/csrf-token" -WebSession $Session).csrfToken
}

function Login-User {
  param(
    [string]$Username,
    [string]$Password
  )

  $session = New-Object Microsoft.PowerShell.Commands.WebRequestSession
  for ($attempt = 1; $attempt -le 4; $attempt++) {
    try {
      $csrf = Get-CsrfToken -Session $session
      $body = @{ username = $Username; password = $Password } | ConvertTo-Json
      $login = Invoke-RestMethod -Method Post -Uri "$BaseUrl/api/auth/login" -WebSession $session -Headers @{
        "x-csrf-token" = $csrf
        "content-type" = "application/json"
      } -Body $body
      return @{
        Session = $session
        Csrf = $csrf
        Login = $login
      }
    } catch {
      if ($attempt -lt 4) {
        Start-Sleep -Seconds 70
      } else {
        throw
      }
    }
  }
}

function Safe-Invoke {
  param([scriptblock]$Action)
  try { & $Action | Out-Null } catch { }
}

$admin = Login-User -Username $AdminUser -Password $AdminPass
$adminToken = $admin.Login.accessToken
$adminSession = $admin.Session
$adminCsrf = $admin.Csrf

Invoke-RestMethod -Method Post -Uri "$TdrUrl/test-ips" -Headers @{
  authorization = "Bearer $adminToken"
  "content-type" = "application/json"
} -Body '{"ip":"172.18.0.1","source":"lab-script"}' | Out-Null

Invoke-RestMethod -Method Delete -Uri "$TdrUrl/alerts" -Headers @{ authorization = "Bearer $adminToken" } | Out-Null
Start-Sleep -Milliseconds 600

$tempPass = ""
try {
  $createBody = @{ username = $LabAnalystUser; role = "analyst" } | ConvertTo-Json
  $created = Invoke-RestMethod -Method Post -Uri "$BaseUrl/api/auth/register" -WebSession $adminSession -Headers @{
    authorization = "Bearer $adminToken"
    "x-csrf-token" = $adminCsrf
    "content-type" = "application/json"
  } -Body $createBody
  $tempPass = $created.temporaryPassword
} catch {
  $users = Invoke-RestMethod -Method Get -Uri "$BaseUrl/api/auth/users" -WebSession $adminSession -Headers @{ authorization = "Bearer $adminToken" }
  $target = $users | Where-Object { $_.username -eq $LabAnalystUser } | Select-Object -First 1
  if (-not $target) { throw }
  $reset = Invoke-RestMethod -Method Post -Uri "$BaseUrl/api/auth/users/$($target.id)/reset-password" -WebSession $adminSession -Headers @{
    authorization = "Bearer $adminToken"
    "x-csrf-token" = $adminCsrf
    "content-type" = "application/json"
  } -Body "{}"
  $tempPass = $reset.temporaryPassword
}

# PRIV_ESC_ATTEMPT
$analyst = Login-User -Username $LabAnalystUser -Password $tempPass
$analystToken = $analyst.Login.accessToken
Safe-Invoke { Invoke-RestMethod -Method Get -Uri "$BaseUrl/api/auth/users" -Headers @{ authorization = "Bearer $analystToken" } -ErrorAction Stop }

# ACCOUNT_ENUMERATION
@("enum001", "enum002", "enum003", "enum004", "enum005") | ForEach-Object {
  $u = $_
  Safe-Invoke {
    $body = @{ username = $u; password = "wrongpass12345" } | ConvertTo-Json
    Invoke-RestMethod -Method Post -Uri "$BaseUrl/api/auth/login" -WebSession $adminSession -Headers @{
      "x-csrf-token" = $adminCsrf
      "content-type" = "application/json"
    } -Body $body -ErrorAction Stop
  }
}

# Allow temporary IP login lock to expire, then re-login admin to clear IP failure counters.
Start-Sleep -Seconds 35
$admin = Login-User -Username $AdminUser -Password $AdminPass
$adminToken = $admin.Login.accessToken
$adminSession = $admin.Session
$adminCsrf = $admin.Csrf

# FAILED_LOGIN_BURST
1..5 | ForEach-Object {
  Safe-Invoke {
    Invoke-RestMethod -Method Post -Uri "$BaseUrl/api/auth/login" -WebSession $adminSession -Headers @{
      "x-csrf-token" = $adminCsrf
      "content-type" = "application/json"
    } -Body "{`"username`":`"$LabAnalystUser`",`"password`":`"wrongpass12345`"}" -ErrorAction Stop
  }
}

# HONEYPOT + PATH_TRAVERSAL
Safe-Invoke { Invoke-WebRequest -UseBasicParsing -Uri "$BaseUrl/internal-debug" }
Safe-Invoke { Invoke-WebRequest -UseBasicParsing -Uri "$BaseUrl/admin-backup?path=../etc/passwd" }

# EXCESSIVE_API_CALLS + ABNORMAL_REQUEST_FREQUENCY
1..170 | ForEach-Object { Safe-Invoke { Invoke-WebRequest -UseBasicParsing -Uri "$BaseUrl/api/health" } }

Start-Sleep -Seconds 4
$alerts = Invoke-RestMethod -Method Get -Uri "$TdrUrl/alerts/categorized" -Headers @{ authorization = "Bearer $adminToken" }
$types = $alerts.applicationAlerts | ForEach-Object { $_.type } | Sort-Object -Unique
Write-Host ("ALERT_TYPES=" + ($types -join ","))
Write-Host ("ALERT_COUNT=" + $alerts.applicationAlerts.Count)
