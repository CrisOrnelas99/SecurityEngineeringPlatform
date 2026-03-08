# Standard logging and environment helpers used across the API.
import logging
import os

# FastAPI framework imports for routes, dependencies, headers, and CORS.
from fastapi import FastAPI
from fastapi import Depends
from fastapi import Header
from fastapi import HTTPException
from fastapi.middleware.cors import CORSMiddleware
# JWT library for validating access tokens from the dashboard/web app.
import jwt
# Pydantic models validate incoming JSON bodies.
from pydantic import BaseModel

# Core detection engine that ingests logs, correlates alerts, and manages response state.
from .detection_engine import DetectionEngine

# Configure simple process-level logging format.
logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")

# Create the API app and the in-memory detection engine instance.
app = FastAPI(title="Threat Detection and Response Engine", version="1.0.0")
engine = DetectionEngine()

# Allow browser clients (dashboard) to call this API.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


# Request body model for manual blocklist operations.
class BlockIpRequest(BaseModel):
    ip: str
    source: str = "dashboard"

# Request body model for test-IP operations.
class TestIpRequest(BaseModel):
    ip: str
    source: str = "dashboard"


# Read allowed telemetry roles from env (default: admin and analyst).
def _get_allowed_roles() -> set[str]:
    raw = os.getenv("TDR_ALLOWED_ROLES", "admin,analyst")
    return {role.strip() for role in raw.split(",") if role.strip()}


# Shared auth dependency:
# 1) require Bearer token
# 2) verify JWT signature
# 3) enforce allowed role list
def require_tdr_user(authorization: str | None = Header(default=None)) -> dict:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing bearer token")

    token = authorization.split(" ", 1)[1].strip()
    secret = os.getenv("JWT_ACCESS_SECRET", "")
    if not secret:
        raise HTTPException(status_code=500, detail="Threat telemetry auth secret not configured")

    try:
        claims = jwt.decode(token, secret, algorithms=["HS256"])
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="Invalid access token")

    role = str(claims.get("role") or "")
    if role not in _get_allowed_roles():
        raise HTTPException(status_code=403, detail="Insufficient role")

    return claims


# Admin-only dependency layered on top of authenticated user claims.
def require_tdr_admin(claims: dict = Depends(require_tdr_user)) -> dict:
    role = str(claims.get("role") or "")
    if role != "admin":
        raise HTTPException(status_code=403, detail="Admin role required")
    return claims


# Start background log-ingestion thread when the API boots.
@app.on_event("startup")
def startup_event() -> None:
    engine.start_background()


# Health check endpoint for liveness verification.
@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


# Return current active alerts for authorized users.
@app.get("/alerts")
def get_alerts(_claims: dict = Depends(require_tdr_user)) -> list[dict]:
    snapshot = engine.snapshot()
    return snapshot["alerts"]


# Return categorized alert payload for dashboard compatibility.
@app.get("/alerts/categorized")
def get_alerts_categorized(_claims: dict = Depends(require_tdr_user)) -> dict:
    snapshot = engine.snapshot()
    return {
        "applicationAlerts": snapshot["alerts"],
    }


# Admin endpoint to clear all active alerts and reset alert timeline view.
@app.delete("/alerts")
def clear_alerts(claims: dict = Depends(require_tdr_admin)) -> dict:
    cleared = engine.clear_alerts(
        actor_user_id=str(claims.get("sub") or "anonymous"),
        actor_username=str(claims.get("username") or "") or None,
        actor_role=str(claims.get("role") or "") or None,
    )
    return {"success": True, "cleared": cleared}


# Delete a single alert by ID while preserving other state.
@app.delete("/alerts/{alert_id}")
def delete_alert(alert_id: str, claims: dict = Depends(require_tdr_user)) -> dict:
    deleted = engine.delete_alert(
        alert_id,
        actor_user_id=str(claims.get("sub") or "anonymous"),
        actor_username=str(claims.get("username") or "") or None,
        actor_role=str(claims.get("role") or "") or None,
    )
    if not deleted:
        raise HTTPException(status_code=404, detail="Alert not found")
    return {"success": True, "deletedId": alert_id}


# Return aggregated risk scores by IP and by user.
@app.get("/risk")
def get_risk(_claims: dict = Depends(require_tdr_user)) -> dict:
    snapshot = engine.snapshot()
    return {"riskByIp": snapshot["riskByIp"], "riskByUser": snapshot["riskByUser"]}


# Return the recent incident timeline entries.
@app.get("/timeline")
def get_timeline(_claims: dict = Depends(require_tdr_user)) -> list[dict]:
    return engine.snapshot()["timeline"]


# Return currently blocked source IP addresses.
@app.get("/blocked-ips")
def get_blocked_ips(_claims: dict = Depends(require_tdr_user)) -> list[str]:
    return engine.snapshot()["blockedIps"]


# Manually add an IP to blocklist.
@app.post("/blocked-ips")
def add_blocked_ip(payload: BlockIpRequest, _claims: dict = Depends(require_tdr_user)) -> dict:
    try:
        added = engine.block_ip(payload.ip, payload.source)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid IP address format or test IP cannot be blocked")
    return {"success": True, "ip": payload.ip, "added": added}


# Manually remove an IP from blocklist.
@app.delete("/blocked-ips/{ip}")
def remove_blocked_ip(ip: str, _claims: dict = Depends(require_tdr_user)) -> dict:
    try:
        removed = engine.unblock_ip(ip, "dashboard")
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid IP address format")
    if not removed:
        raise HTTPException(status_code=404, detail="IP not in blocklist")
    return {"success": True, "ip": ip, "removed": removed}


# Admin endpoint to list test IPs (IPs used for safe lab traffic).
@app.get("/test-ips")
def get_test_ips(_claims: dict = Depends(require_tdr_admin)) -> list[str]:
    return engine.snapshot()["testIps"]


# Admin endpoint to add a test IP.
@app.post("/test-ips")
def add_test_ip(payload: TestIpRequest, _claims: dict = Depends(require_tdr_admin)) -> dict:
    try:
        added = engine.add_test_ip(payload.ip, payload.source)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid IP address format")
    return {"success": True, "ip": payload.ip, "added": added}


# Admin endpoint to remove a test IP.
@app.delete("/test-ips/{ip}")
def remove_test_ip(ip: str, _claims: dict = Depends(require_tdr_admin)) -> dict:
    try:
        removed = engine.remove_test_ip(ip, "dashboard")
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid IP address format")
    if not removed:
        raise HTTPException(status_code=404, detail="IP not in test list")
    return {"success": True, "ip": ip, "removed": removed}


# Return dashboard summary metrics (counts + top attack patterns).
@app.get("/summary")
def get_summary(_claims: dict = Depends(require_tdr_user)) -> dict:
    snapshot = engine.snapshot()
    honeypot_count = len([a for a in snapshot["alerts"] if a.get("type") == "HONEYPOT_TRIGGER"])
    return {
        "activeAlerts": len(snapshot["alerts"]),
        "applicationAlerts": len(snapshot["alerts"]),
        "blockedIps": len(snapshot["blockedIps"]),
        "lockedUsers": len(snapshot["lockedUsers"]),
        "honeypotTriggers": honeypot_count,
        "topAttackPatterns": _top_attack_patterns(snapshot["alerts"]),
    }


# Helper to rank alert types by frequency for summary cards/charts.
def _top_attack_patterns(alerts: list[dict]) -> list[dict]:
    counts: dict[str, int] = {}
    for alert in alerts:
        alert_type = alert.get("type", "UNKNOWN")
        counts[alert_type] = counts.get(alert_type, 0) + 1
    ranked = sorted(counts.items(), key=lambda item: item[1], reverse=True)
    return [{"pattern": key, "count": value} for key, value in ranked[:10]]
