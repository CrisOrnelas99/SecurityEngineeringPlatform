# Security Engineering Platform

A multi-service cybersecurity platform that combines secure API engineering, C++ cryptography, SOC detection, and automated response.

## What This Project Demonstrates

- Secure API design with defense-in-depth controls
- Cryptographic operations implemented in C++ (libsodium + OpenSSL)
- SOC-style detection and risk scoring from structured application logs
- Automated response actions (IP block, account lock, timeline and alert generation)
- End-to-end observability through a React security dashboard

## Architecture

```text
React Dashboard (dashboard)
        |
        v
Python SOC API + Detection Engine (python_engine)
        |
        v
Node Secure API (webapp) ----> C++ Security Core CLI (security_core)
```

### Data and Control Flow

1. `webapp` enforces application security controls and writes structured JSON logs.
2. `python_engine` ingests events, detects suspicious behavior, computes risk, and triggers response actions.
3. `security_core` provides cryptographic primitives for password, token, and file-security operations.
4. `dashboard` visualizes alerts, risk, blocklist state, and incident timeline.

## Cybersecurity Implementations

### 1) Secure API Controls (`webapp`)

- JWT auth flows: login, refresh, logout
- RBAC authorization middleware
- Input validation with `zod`
- Rate limiting (`express-rate-limit`)
- Secure headers (`helmet`)
- CSRF protection (`csurf`)
- Upload restrictions (type and size checks)
- Honeypot endpoints to detect malicious probing
- Runtime enforcement of SOC outputs (blocked IPs, locked users)

### 2) Cryptographic Core (`security_core`)

- Argon2id password hashing and verification (`libsodium`)
- JWT signing and verification (tamper + expiration checks)
- AES-256-GCM file encryption/decryption (`OpenSSL`)
- HMAC-SHA256 integrity checks with constant-time compare
- JSON-based CLI interface for service-to-service integration

### 3) SOC Detection and Response (`python_engine`)

Implemented detections include:

- Failed login bursts
- Account enumeration patterns
- Suspicious JWT reuse across IPs
- Privilege escalation attempts
- Injection and path traversal indicators
- Excessive request frequency
- Honeypot triggers
- Requests from blocked sources

Risk and response pipeline:

- Weighted risk scoring per IP/user
- Risk levels: `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`
- Automated actions:
  - update `blocklist.json`
  - update `locked_users.json`
  - emit `alerts.json`
  - append `timeline.json`

### 4) SOC Dashboard (`dashboard`)

- Active alerts with details view
- Risk summary by source
- Incident timeline
- Blocked IP visibility and operations
- Attack pattern distribution

## Repository Structure

```text
.
|- .github/workflows/ci.yml
|- dashboard/
|- python_engine/
|- security_core/
|- webapp/
|- scripts/
|- docker-compose.yml
|- .env.example
`- README.md
```

## Build and Run

### Prerequisites

- Docker + Docker Compose
- Or local toolchains: Node 20, Python 3.11+, CMake 3.16+, C++17 compiler

### Quick Start (Docker)

```bash
cp .env.example .env
docker compose build
docker compose up
```

### Service Endpoints

- Node API: `http://localhost:3000`
- Python SOC API: `http://localhost:8000`
- Dashboard: `http://localhost:5173`

Common SOC endpoints:

- `GET /summary`
- `GET /alerts`
- `GET /risk`
- `GET /timeline`
- `GET /blocked-ips`

## CI and Security Automation

GitHub Actions workflow (`.github/workflows/ci.yml`) runs:

- Node lint and dependency checks
- Python compile checks and dependency audit
- C++ configure/build verification
- Secret scanning with Gitleaks

## Demo Activity Simulation

Generate SOC activity with the included script:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\simulate_attack.ps1
```

Higher volume example:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\simulate_attack.ps1 -Rounds 20 -DelayMs 50
```

## Secure Configuration Notes

- Use `.env.example` as a template only.
- Do not commit real secrets.
- Use separate secrets per environment.
- Rotate secrets after incidents and on schedule.
- Avoid logging sensitive material.
