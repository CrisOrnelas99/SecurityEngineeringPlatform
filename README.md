# Security Engineering Platform

Hands-on Threat Detection & Response + protected web app lab for practical cybersecurity engineering.

## Stack
- `webapp` (Node.js/Express)
- `waf-proxy` (Nginx + ModSecurity + OWASP CRS)
- `python_engine` (FastAPI + detection/correlation engine)
- `dashboard` (React TD&RD UI)
- `security_core` (C++ crypto helper binary)

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

## Current Security Controls

### Web App
- JWT access/refresh auth
- RBAC (`admin`, `analyst`)
- CSRF protection (`csurf`)
- CORS policy
- Helmet security headers
- Input validation (`zod`)
- Login abuse protection (rate limit + adaptive backoff)
- Honeypot routes:
  - `/internal-debug`
  - `/.env`
  - `/admin-backup`

### Edge/WAF
- ModSecurity + OWASP CRS in front of app at `:8080`
- Anomaly scoring in blocking mode
- Lab override file: [`waf/modsecurity-override.conf`](waf/modsecurity-override.conf)
  - `/admin-backup` is `DetectionOnly` for lab observability
  - `DELETE` allowed for admin user-management endpoints

## Detection Coverage (Application Alerts)
- `FAILED_LOGIN_BURST`
- `ACCOUNT_ENUMERATION`
- `HONEYPOT_TRIGGER`
- `PATH_TRAVERSAL_ATTEMPT`
- `PRIV_ESC_ATTEMPT`
- `EXCESSIVE_API_CALLS`
- `ABNORMAL_REQUEST_FREQUENCY`

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

## Engine/System Alerts (separate panel)
- `ENGINE_INGEST_LAG`
- `ENGINE_LOG_PARSE_ERRORS`

## Test Mode and Access Rules
- Test dashboard is **admin-only** in UI.
- Test IP APIs are **admin-only** in backend:
  - `GET /test-ips`
  - `POST /test-ips`
  - `DELETE /test-ips/{ip}`
- Test IP traffic:
  - creates alerts
  - does **not** auto-block
  - does **not** add IP risk score

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
# Full detector validation script (all implemented alert classes)
powershell -ExecutionPolicy Bypass -File scripts/trigger_all_alerts.ps1

# Simple frequency test (now expected to trigger)
1..50 | % { try { Invoke-WebRequest -UseBasicParsing -Uri "http://localhost:8080/api/health" | Out-Null } catch {} }

# Honeypot
curl.exe -i "http://localhost:8080/internal-debug"

# Path traversal lab probe
curl.exe -i "http://localhost:8080/admin-backup?path=../etc/passwd"
```

### Kali Linux / WSL
```bash
# Full detector validation script
bash scripts/trigger_all_alerts_kali.sh

# Simple frequency test (now expected to trigger)
for i in $(seq 1 50); do curl -s http://localhost:8080/api/health >/dev/null; done

# Honeypot
curl -i "http://localhost:8080/internal-debug"

# Path traversal lab probe
curl -i "http://localhost:8080/admin-backup?path=../etc/passwd"
```

## Repository Layout
```text
.
|- dashboard/
|- python_engine/
|- security_core/
|- webapp/
|- scripts/
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
