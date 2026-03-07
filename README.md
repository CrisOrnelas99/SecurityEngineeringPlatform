# Security Engineering Platform

Hands-on Threat Detection & Response + protected web app lab for practical cybersecurity engineering.

## Stack
- `webapp` (Node.js/Express)
- `waf-proxy` (Nginx + ModSecurity + OWASP CRS)
- `python_engine` (FastAPI + detection/correlation engine)
- `dashboard` (React TD&RD UI)
- `security_core` (C++ crypto helper binary)

## Why Docker In This Project
- Runs all services with consistent versions and networking on any machine.
- Prevents local dependency/version drift across Node, Python, and C++ tooling.
- Brings the full lab up with one command (`docker compose up -d --build`).
- Keeps service boundaries clear (`waf -> webapp`, `dashboard -> python_engine/webapp`).
- Makes demo/review easier: reviewers run the same stack and get the same behavior.

## Full Architecture

```text
Browser
  |\
  | \__ Dashboard UI (:5173)
  |      |- reads detections/risk/timeline from python_engine (:8000)
  |      \- performs app auth/admin actions via WAF (:8080)
  |
  \__ Protected App Entry (:8080) [waf-proxy]
         |- ModSecurity + OWASP CRS inspection
         |- route-specific lab override: /admin-backup in DetectionOnly
         \-> forwards to webapp internal (:3000)

webapp (:3000)
  |- auth, RBAC, CSRF, rate limit, honeypot routes
  |- writes structured audit logs -> webapp/logs/app.log
  \- persists app data -> webapp/data/* (SQLite + JSON)

python_engine (:8000)
  |- tails app.log
  |- correlates detections + scores risk
  |- auto-response (block/test IP handling)
  \- persists alerts/timeline/blocklist artifacts

security_core
  \- C++ helper used by app/engine for crypto workflows
```

## Security Architecture (Practical View)
- **Edge protection (WAF):** `waf-proxy` inspects inbound requests before they reach the app.
- **Application layer (webapp):** serves app/auth routes and emits security telemetry.
- **Detection and response (python_engine):** correlates detections, calculates risk, and tracks response actions.
- **Analyst visibility/control (dashboard):** reads alerts/risk/timeline and allows admin operations.

### Event/Data Flow
`Client request -> WAF -> Webapp middleware/endpoint -> app log event -> python_engine correlation -> dashboard telemetry`

## Lab-Only Web App Guide
- The web app guide is intentionally manual-test focused.
- It includes generalized sections for detections, security features/libraries, OWASP Top 10 mapping, and a high-level architecture view.
- Internal control mappings and implementation-location details are intentionally omitted from the UI.

## Detection Coverage (Application Alerts)
- `FAILED_LOGIN_BURST`
- `ACCOUNT_ENUMERATION`
- `HONEYPOT_TRIGGER`
- `PATH_TRAVERSAL_ATTEMPT`
- `PRIV_ESC_ATTEMPT`
- `EXCESSIVE_API_CALLS`
- `ABNORMAL_REQUEST_FREQUENCY`

## Manual-Only Testing
- This project intentionally uses manual, step-by-step detection validation commands.
- No automation trigger scripts are included.

### Notes
- `/api/health` lab bursts use lower thresholds so `seq 1 50` style tests trigger reliably.
- Admin user-management endpoints are excluded from request-frequency alerts to reduce false positives.

## Timeline-Only Operational Events
(Not shown as Active Alerts)
- `ADMIN_DELETE_USER`
- `ADMIN_RESET_USER_PASS`
- `AUTO_BLOCK_IP_ACCESS`
- `MANUAL_BLOCK_IP`
- `MANUAL_UNBLOCK_IP`
- `TEST_IP_ADDED`
- `TEST_IP_REMOVED`

## Test Mode and Access Rules
- Test dashboard is **admin-only** in UI.
- Test dashboard is opened from **Dashboard -> Admin Test Tools -> Open Test Dashboard**.
- Test IP APIs are **admin-only** in backend:
  - `GET /test-ips`
  - `POST /test-ips`
  - `DELETE /test-ips/{ip}`
- Test IP traffic:
  - creates alerts
  - does **not** auto-block
  - does **not** add IP risk score

## Dashboard UX Notes (Current)
- **Main Dashboard layout:**
  - Large `Active Alerts` panel on the left
  - Large `Incident Timeline` panel in the center
  - Right-side stacked panels: `Risk Scores By IP`, `Blocked IPs`, `Attack Patterns`
- **Test Dashboard layout:**
  - Large `Test Alerts` panel on the left
  - Right-side stacked panels: `Test Risk Scores By IP`, `Test IPs`, `Test Attack Patterns`
- Active/test grouped alert rows no longer show `occurrence(s)` text.
- `Show Blocklist Events` button was removed from timeline UI.

## Analytics Page (Current)
- Data source is **timeline events** (not just active alerts), ordered **newest -> oldest**.
- Views: `Hourly` and `Daily` with fixed windows (`24h/72h`, `7d/30d`).
- Event type filter defaults to **all selected**.
- Exports:
  - `Download CSV` includes detailed timeline rows.
  - `Print` is supported; print layout is optimized for multi-page output and hides the event-type filter panel.
- `Save PDF` button was removed (use browser Print -> Save as PDF instead).

## Data Persistence (Where Things Are Stored)
- Web app logs: `webapp/logs/app.log`
- Web app data/artifacts: `webapp/data/*` (SQLite + JSON)
- Engine artifacts (alerts/timeline/block/test lists): persisted by `python_engine` under its mounted data/log paths.
- Dashboard is a UI client; it does not act as the source of truth for detections.

## Run
```bash
cp .env.example .env
docker compose up -d --build
```

Services:
- Protected app (via WAF): `http://localhost:8080`
- Threat Detection API: `http://localhost:8000`
- Dashboard: `http://localhost:5173`

## Useful Endpoints

### Threat API (`:8000`)
- `GET /summary`
- `GET /alerts`
- `GET /alerts/categorized`
- `GET /risk`
- `GET /timeline`
- `GET /blocked-ips`
- `POST /blocked-ips`
- `DELETE /blocked-ips/{ip}`
- `GET /test-ips` (admin)
- `POST /test-ips` (admin)
- `DELETE /test-ips/{ip}` (admin)

### Web App (`:8080`)
- `GET /api/csrf-token`
- `POST /api/auth/login`
- `POST /api/auth/refresh`
- `POST /api/auth/logout`
- `GET /api/auth/me`
- `POST /api/auth/change-password`
- `GET /api/auth/users` (admin)
- `POST /api/auth/register` (admin)
- `POST /api/auth/users/:id/reset-password` (admin)
- `DELETE /api/auth/users/:id` (admin)

## Lab Commands

### Windows PowerShell
```powershell
# Shared setup
$base = "http://localhost:8080"
$s = New-Object Microsoft.PowerShell.Commands.WebRequestSession
$csrf = (Invoke-RestMethod -Method Get -Uri "$base/api/csrf-token" -WebSession $s).csrfToken

# Brute force burst (failed login burst)
1..5 | ForEach-Object {
  try {
    Invoke-RestMethod -Method Post -Uri "$base/api/auth/login" -WebSession $s `
      -Headers @{ "x-csrf-token" = $csrf; "content-type" = "application/json" } `
      -Body '{"username":"analystlab","password":"wrongpass12345"}' -ErrorAction Stop | Out-Null
  } catch {}
}

# Account enumeration (one IP, many usernames)
"enum001","enum002","enum003","enum004","enum005" | ForEach-Object {
  $u = $_
  try {
    Invoke-RestMethod -Method Post -Uri "$base/api/auth/login" -WebSession $s `
      -Headers @{ "x-csrf-token" = $csrf; "content-type" = "application/json" } `
      -Body (@{ username = $u; password = "wrongpass12345" } | ConvertTo-Json) -ErrorAction Stop | Out-Null
  } catch {}
}

# Honeypot
curl.exe -i "http://localhost:8080/internal-debug"

# Path traversal lab probe
curl.exe -i "http://localhost:8080/admin-backup?path=../etc/passwd"

# Privilege escalation detection (manual analyst flow)
$user = "goose2"
$pass = "pass12345678"
$loginBody = @{ username = $user; password = $pass } | ConvertTo-Json
$login = Invoke-RestMethod -Method Post -Uri "$base/api/auth/login" -WebSession $s `
  -Headers @{ "x-csrf-token" = $csrf; "content-type" = "application/json" } `
  -Body $loginBody
$token = $login.accessToken
curl.exe -i "$base/api/auth/users" -H ("Authorization: Bearer " + $token)

# API frequency detections
1..50 | ForEach-Object {
  try { Invoke-WebRequest -UseBasicParsing -Uri "$base/api/health" | Out-Null } catch {}
}
```

### Kali Linux / WSL
```bash
# Brute force burst (failed login burst)
BASE="http://localhost:8080"
CSRF=$(curl -s -c cookies.txt "$BASE/api/csrf-token" | jq -r '.csrfToken')
for i in $(seq 1 5); do
  curl -s -b cookies.txt -c cookies.txt -X POST "$BASE/api/auth/login" \
    -H "x-csrf-token: $CSRF" -H "content-type: application/json" \
    -d '{"username":"analystlab","password":"wrongpass12345"}' >/dev/null
done

# Account enumeration (one IP, many usernames)
for u in enum001 enum002 enum003 enum004 enum005; do
  curl -s -b cookies.txt -c cookies.txt -X POST "$BASE/api/auth/login" \
    -H "x-csrf-token: $CSRF" -H "content-type: application/json" \
    -d "{\"username\":\"$u\",\"password\":\"wrongpass12345\"}" >/dev/null
done

# Honeypot
curl -i "http://localhost:8080/internal-debug"

# Path traversal lab probe
curl -i "http://localhost:8080/admin-backup?path=../etc/passwd"

# Privilege escalation detection (manual analyst flow)
BASE="http://localhost:8080"; USER="goose2"; PASS="pass12345678"
CSRF=$(curl -s -c cookies.txt "$BASE/api/csrf-token" | jq -r '.csrfToken'); echo "CSRF=$CSRF"
TOKEN=$(curl -s -b cookies.txt -c cookies.txt -H "Content-Type: application/json" -H "X-CSRF-Token: $CSRF" -d "{\"username\":\"$USER\",\"password\":\"$PASS\"}" "$BASE/api/auth/login" | jq -r '.accessToken'); echo "TOKEN=$TOKEN"
curl -i -b cookies.txt -H "Authorization: Bearer $TOKEN" "$BASE/api/auth/users"

# API frequency detections
for i in $(seq 1 50); do curl -s "http://localhost:8080/api/health" >/dev/null; done
```

## Manual Detection Checklist
- `FAILED_LOGIN_BURST`: 5 failed login attempts from same IP in short window.
- `ACCOUNT_ENUMERATION`: 5+ distinct usernames with failed login attempts from one IP within 10 minutes.
- `HONEYPOT_TRIGGER`: `curl -i http://localhost:8080/internal-debug`
- `PATH_TRAVERSAL_ATTEMPT`: `curl -i "http://localhost:8080/admin-backup?path=../etc/passwd"`
- `PRIV_ESC_ATTEMPT`: analyst login, then `GET /api/auth/users` with analyst token (expect `403`).
- `EXCESSIVE_API_CALLS` / `ABNORMAL_REQUEST_FREQUENCY`: `for i in $(seq 1 50); do curl -s http://localhost:8080/api/health >/dev/null; done`

## Repository Layout
```text
.
|- dashboard/
|- python_engine/
|- security_core/
|- webapp/
|- waf/
|- docker-compose.yml
`- README.md
```

## CI
GitHub Actions validates:
- webapp checks
- python checks
- C++ build
- secret scanning (Gitleaks)
