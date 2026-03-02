# Security Engineering Platform (Multi-Service)

Production-style security platform that combines AppSec controls, SOC detection, C++ cryptographic primitives, honeypot monitoring, and automated response in a container-ready architecture.

## 1) Project Structure

```text
ResumeProject/
+- .github/workflows/ci.yml
+- .env.example
+- .gitignore
+- docker-compose.yml
+- README.md
+- dashboard/
ï¿½  +- Dockerfile
ï¿½  +- index.html
ï¿½  +- package.json
ï¿½  +- src/
ï¿½     +- App.jsx
ï¿½     +- main.jsx
ï¿½     +- styles.css
+- python_engine/
ï¿½  +- Dockerfile
ï¿½  +- requirements.txt
ï¿½  +- data/
ï¿½  ï¿½  +- alerts.json
ï¿½  ï¿½  +- blocklist.json
ï¿½  ï¿½  +- locked_users.json
ï¿½  ï¿½  +- timeline.json
ï¿½  +- src/
ï¿½     +- __init__.py
ï¿½     +- app.py
ï¿½     +- crypto_core_client.py
ï¿½     +- detection_engine.py
+- security_core/
ï¿½  +- CMakeLists.txt
ï¿½  +- Dockerfile
ï¿½  +- crypto_engine.cpp
ï¿½  +- crypto_engine.h
ï¿½  +- file_crypto.cpp
ï¿½  +- file_crypto.h
ï¿½  +- main.cpp
ï¿½  +- token_service.cpp
ï¿½  +- token_service.h
ï¿½  +- utils.cpp
ï¿½  +- utils.h
+- webapp/
   +- Dockerfile
   +- package.json
   +- data/
   ï¿½  +- refreshTokens.json
   ï¿½  +- users.json
   +- src/
      +- middleware/
      ï¿½  +- auth.js
      ï¿½  +- rbac.js
      ï¿½  +- threatControls.js
      ï¿½  +- validation.js
      +- routes/
      ï¿½  +- apiRoutes.js
      ï¿½  +- authRoutes.js
      +- services/
      ï¿½  +- cryptoCoreClient.js
      ï¿½  +- userStore.js
      +- utils/
      ï¿½  +- logger.js
      +- server.js
```

## 2) High-Level Architecture

1. React dashboard consumes SOC API data for operational visibility.
2. Node.js API enforces AppSec controls and emits machine-readable JSON logs.
3. C++ security core provides hardened cryptographic operations consumed by Node and Python.
4. Python detection engine streams Node logs, computes risk, and performs automated response.
5. Response artifacts (blocklist, locked users, alerts, timeline) are fed back into platform behavior.

Data flow:

```text
[React Dashboard]
      ?
[Python SOC API] ? reads/maintains alerts, risk, timeline, blocklist
      ?
[Node Secure API] ? structured JSON logs
      ?
[C++ Security Core] (password hashing, JWT crypto, AES-GCM, HMAC)
```

## 3) Service Implementation Summary

### Node.js Secure API (`webapp`)

Security controls implemented:
- JWT authentication (`/api/auth/login`, `/api/auth/refresh`, `/api/auth/logout`)
- RBAC with `authorize(...)`
- Password hashing verification delegated to C++ core
- Input validation via `zod`
- Rate limiting via `express-rate-limit`
- Secure headers via `helmet`
- CSRF protection via `csurf` (cookie mode)
- File upload endpoint with MIME + size restrictions
- Payment simulation endpoint
- Honeypot endpoints (`/admin-backup`, `/.env`, `/internal-debug`)
- Blocklist and locked-account enforcement from SOC outputs

Structured log format includes:
- `ip`
- `userId`
- `endpoint`
- `timestamp`
- `success`
- `metadata`
- `errorType`

### C++ Cryptographic Core (`security_core`)

Modules:
- Password hashing: Argon2id (libsodium)
- Password verification
- JWT signing/verification: HS256, tamper detection, exp validation
- File encryption/decryption: AES-256-GCM (OpenSSL)
- HMAC integrity: HMAC-SHA256 + constant-time compare
- JSON CLI operations:
  - `hash-password`, `verify-password`
  - `sign-jwt`, `verify-jwt`
  - `encrypt-file`, `decrypt-file`
  - `hmac`, `verify-hmac`

Implementation principles:
- RAII usage for OpenSSL contexts
- Defensive input validation
- Structured JSON outputs for machine integration
- No secret material written to logs

### Python SOC / Detection Engine (`python_engine`)

Detection coverage:
- `FAILED_LOGIN_BURST` (5+ failed logins from one source in 5 minutes)
- `ACCOUNT_ENUMERATION` (many distinct failed usernames from one source)
- `SUSPICIOUS_JWT_REUSE` (per-user multi-IP and token-fingerprint reuse)
- `PRIV_ESC_ATTEMPT` (authorization denial on privileged routes)
- `INJECTION_ATTEMPT` (signature-based request payload/path indicators)
- `PATH_TRAVERSAL_ATTEMPT` (../ and encoded traversal signals)
- `EXCESSIVE_API_CALLS` and `ABNORMAL_REQUEST_FREQUENCY`
- `HONEYPOT_TRIGGER` (deduplicated against request-audit overlap)
- `BLACKLISTED_IP_ACCESS` (`BLOCKED_IP_REQUEST` in UI labels)

Risk engine:
- Weighted event scoring
- Aggregation by IP and user
- Risk levels: `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`

Automated response:
- IP blocking (`blocklist.json`)
- Account locking (`locked_users.json`)
- Alert generation (`alerts.json`)
- Incident timeline updates (`timeline.json`)

Baseline/anomaly logic:
- Maintains rolling login history per user
- Flags deviations above dynamic threshold

### React SOC Dashboard (`dashboard`)

Dashboard surfaces:
- Active alerts
- Risk scores by IP
- Incident timeline
- Blocked IPs
- Honeypot trigger counts
- Attack pattern distribution

## 4) CMake Config (C++ Core)

Main build file: `security_core/CMakeLists.txt`
- C++17
- `OpenSSL`
- `libsodium`
- `nlohmann_json`
- Executable target: `security_core`

## 5) Docker and Compose

Images/services:
- `webapp` (Node API)
- `python-engine` (SOC service)
- `security-core` (crypto build/runtime)
- `dashboard` (React frontend)

`docker-compose.yml` wires:
- service dependencies
- shared volumes for logs and response artifacts
- environment variables for integration
- published ports: `3000`, `8000`, `5173`

## 6) CI Pipeline (GitHub Actions)

Workflow: `.github/workflows/ci.yml`
- Node lint + dependency audit
- Python compile check + `pip-audit`
- C++ build verification (cmake)
- Secret scanning with `gitleaks`

## 7) Security Design Notes

Key design choices:
- Least privilege: RBAC and explicit deny behavior
- Defense in depth: API hardening + SOC monitoring + automated response
- Secure defaults: strict input validation, safe upload limits, secure headers
- Fail secure: invalid auth/CSRF/risk controls deny by default
- Structured observability: JSON logs enable deterministic detection
- Cryptographic hygiene: standard primitives from vetted libs only

## 8) Environment and Secret Handling

Use `.env.example` as template. Do not commit real secrets.

Guidelines:
1. Keep JWT secrets, CSRF secret, and key material in a secret manager.
2. Rotate secrets regularly and after incidents.
3. Use distinct secrets per environment (dev/stage/prod).
4. Set restrictive file permissions for runtime data volumes.
5. Avoid logging credentials, tokens, or encryption keys.

## 9) Quick Start

```bash
cp .env.example .env

docker compose build

docker compose up
```

Endpoints:
- Node API: `http://localhost:3000`
- Python SOC API: `http://localhost:8000`
- Dashboard: `http://localhost:5173`

SOC API examples:
- `GET /summary`
- `GET /alerts`
- `GET /risk`
- `GET /timeline`
- `GET /blocked-ips`

## 10) Generate Demo SOC Activity

Use the included simulation script to generate benign attack-like traffic (honeypot hits + suspicious probes) and populate the dashboard.

Run from project root:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\simulate_attack.ps1
```

Higher intensity example:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\simulate_attack.ps1 -Rounds 20 -DelayMs 50
```

What it updates:
- `alerts.json`
- `timeline.json`
- `blocklist.json`
- SOC dashboard metrics at `http://localhost:5173`

Verify directly:

```powershell
curl http://localhost:8000/summary
curl http://localhost:8000/alerts
```

Note:
- In the current compose config, `webapp` runs with `NODE_ENV=development` for local auth testing over `http://localhost`. The simulation script avoids that by using endpoints that still generate SOC-relevant events locally.

## 11) Current Implementation Status (March 2026)

This is what is currently implemented and working in the repository.

### Dashboard and UX

- Multi-tab dashboard UI with:
  - `Dashboard`
  - `Login / Register`
  - `Session Tools`
- Professional dark theme and cleaned card styling.
- Header nav tabs are aligned to the right of the live-visibility subtitle on desktop.
- IP display normalization in UI:
  - `::ffff:x.x.x.x` renders as `IPv4: x.x.x.x`
  - native v6 renders as `IPv6: ...`

### Authentication and Session Testing (Frontend)

- Frontend register/login forms are implemented.
- Session test actions are implemented:
  - payment simulation call
  - admin-report access check
- Local compose is configured for localhost auth testing with `webapp` on `NODE_ENV=development`.

### SOC Alert and Timeline Behavior

- Active Alerts card supports:
  - clear all alerts
  - per-alert `Details`
  - contiguous same-type grouping with `Show Group` / `Hide Group`
- Active Alerts excludes blocklist-noise alerts (`BLACKLISTED_IP_ACCESS`) by default.
- Incident Timeline supports per-event `Details` and localized timestamps.
- Incident Timeline includes a `Show Blocklist Events` toggle.
  - Default is hidden for blocked-repeat request events (`BLOCKED_IP_REQUEST` label in UI).
  - `AUTO_BLOCK_IP_ACCESS` remains visible as the enforcement action marker.
- Enforcement details include method/endpoint/error type where available.

### IP Block/Unblock Operations

- Manual block/unblock is implemented in API and dashboard.
- Dashboard `Blocked IPs` card supports add and unblock actions.
- SOC endpoints:
  - `POST /blocked-ips`
  - `DELETE /blocked-ips/{ip}`

### Detection and Response Updates

- Honeypot/request-audit overlap deduped so one probe produces one honeypot alert.
- Auto-response now blocks source IP on every detected incident event.
- Auto-block action is recorded as `AUTO_BLOCK_IP_ACCESS` in timeline.
- `BLACKLISTED_IP_ACCESS` is still produced for follow-up traffic from blocked sources, and is labeled `BLOCKED_IP_REQUEST` in UI.
- Web blocklist guard normalizes IPv4-mapped IPv6 (`::ffff:`) so blocked IP matching is consistent.

### Fresh-Start SOC Mode (Clean Startup)

Startup behavior is configured for a clean lab state by default:
- `SOC_LOAD_PERSISTED_STATE=false`
- `SOC_REPLAY_LOG_ON_START=false`

This means services start without historical alerts/risk unless new activity occurs after startup.

### Notes

- To keep SOC history across restarts, set:
  - `SOC_LOAD_PERSISTED_STATE=true`
  - `SOC_REPLAY_LOG_ON_START=true`
- Docker Compose v2 ignores the `version` key; it can be removed from `docker-compose.yml`.

