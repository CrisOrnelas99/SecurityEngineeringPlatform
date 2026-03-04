# Security Engineering Platform

Hands-on Threat Detection & Response + secure web application project for demonstrating practical cybersecurity engineering:

- Secure Node.js web app (`webapp`)
- Python detection + response engine (`python_engine`)
- C++ security core (`security_core`)
- React Threat Detection & Response dashboard (`dashboard`)

## Architecture

```text
Dashboard (React, :5173)
   |
   v
Threat Detection API + Detection Engine (FastAPI, :8000)
   |
   v
Secure Web App (Node/Express, :3000) <-> Security Core (C++ CLI)
```

## What It Implements

### Web App Security Controls
- JWT access/refresh auth
- RBAC (`admin`, `analyst`)
- CSRF protection
- Rate limiting
- Input validation (Zod)
- Security headers (Helmet)
- Honeypot routes:
  - `/internal-debug`
  - `/.env`
  - `/admin-backup`

### Threat Detections (Current)
- `FAILED_LOGIN_BURST` (5+ failed logins from same IP, deduped)
- `ACCOUNT_ENUMERATION` (5+ distinct usernames from same IP in 10 min)
- `HONEYPOT_TRIGGER`
- `PATH_TRAVERSAL_ATTEMPT`
- `PRIV_ESC_ATTEMPT` (authorization denied on protected routes)
- `EXCESSIVE_API_CALLS`
- `ABNORMAL_REQUEST_FREQUENCY`

### Automated Response
- Risk scoring per IP/user (`LOW`, `MEDIUM`, `HIGH`, `CRITICAL`)
- Auto-block source IP for incidents
- Auto-lock user accounts at high user risk
- Persist output artifacts:
  - `webapp/data/blocklist.json`
  - `webapp/data/locked_users.json`
  - `webapp/logs/alerts.json`
  - `webapp/logs/timeline.json`

## Identity and User Management

- Shared SQLite DB for web app + threat dashboard login context (`webapp/data/security.db`)
- Default admin (from compose env):
  - Username: `admin`
  - Password: `pass12345678`
- Admin can:
  - Create users
  - Assign role (`analyst`/`admin`)
  - Reset user password
  - Delete users
  - View locked users in dashboard Users panel

## Run with Docker

```bash
cp .env.example .env
docker compose up -d --build
```

Services:
- Web app: `http://localhost:3000`
- Threat Detection API: `http://localhost:8000`
- Dashboard: `http://localhost:5173`

Note: `docker compose up` without `-d` will stay attached to logs (this is expected).

## Testing Attack Scenarios

### 1) Brute Force
Attempt wrong password 5+ times for same user/IP.

### 2) Account Enumeration
Use one IP with many usernames and wrong passwords.

### 3) Honeypot
```bash
curl -i http://localhost:3000/internal-debug
```

### 4) Path Traversal
```bash
curl -i "http://localhost:3000/admin-backup?path=../etc/passwd"
```

### 5) Excessive API Calls
```bash
for i in $(seq 1 150); do curl -s http://localhost:3000/api/health >/dev/null; done
```

## Useful Endpoints

### Threat Detection API (`:8000`)
- `GET /summary`
- `GET /alerts`
- `GET /alerts/categorized`
- `GET /risk`
- `GET /timeline`
- `GET /blocked-ips`

### Web App Auth/Admin (`:3000`)
- `GET /api/csrf-token`
- `POST /api/auth/login`
- `POST /api/auth/refresh`
- `POST /api/auth/logout`
- `GET /api/auth/me`
- `POST /api/auth/change-password`
- `GET /api/auth/users` (admin)
- `POST /api/auth/register` (admin creates user)
- `POST /api/auth/users/:id/reset-password` (admin)
- `DELETE /api/auth/users/:id` (admin)

## Repository Layout

```text
.
|- dashboard/
|- python_engine/
|- security_core/
|- webapp/
|- scripts/
|- docker-compose.yml
`- README.md
```

## CI

GitHub Actions (`.github/workflows/ci.yml`) validates:
- Node/webapp checks
- Python engine checks
- C++ core configure/build
- Secret scanning (Gitleaks)
