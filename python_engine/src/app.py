import logging
import os

from fastapi import FastAPI
from fastapi import Depends
from fastapi import Header
from fastapi import HTTPException
from fastapi.middleware.cors import CORSMiddleware
import jwt
from pydantic import BaseModel

from .detection_engine import DetectionEngine

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")

app = FastAPI(title="Threat Detection and Response Engine", version="1.0.0")
engine = DetectionEngine()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


class BlockIpRequest(BaseModel):
    ip: str
    source: str = "dashboard"

class TestIpRequest(BaseModel):
    ip: str
    source: str = "dashboard"


def _get_allowed_roles() -> set[str]:
    raw = os.getenv("TDR_ALLOWED_ROLES", "admin,analyst")
    return {role.strip() for role in raw.split(",") if role.strip()}


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


def require_tdr_admin(claims: dict = Depends(require_tdr_user)) -> dict:
    role = str(claims.get("role") or "")
    if role != "admin":
        raise HTTPException(status_code=403, detail="Admin role required")
    return claims


@app.on_event("startup")
def startup_event() -> None:
    engine.start_background()


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/alerts")
def get_alerts(_claims: dict = Depends(require_tdr_user)) -> list[dict]:
    snapshot = engine.snapshot()
    return snapshot["alerts"]


@app.get("/alerts/categorized")
def get_alerts_categorized(_claims: dict = Depends(require_tdr_user)) -> dict:
    snapshot = engine.snapshot()
    return {
        "applicationAlerts": snapshot["alerts"],
    }


@app.delete("/alerts")
def clear_alerts(_claims: dict = Depends(require_tdr_user)) -> dict:
    cleared = engine.clear_alerts()
    return {"success": True, "cleared": cleared}


@app.delete("/alerts/{alert_id}")
def delete_alert(alert_id: str, _claims: dict = Depends(require_tdr_user)) -> dict:
    deleted = engine.delete_alert(alert_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Alert not found")
    return {"success": True, "deletedId": alert_id}


@app.get("/risk")
def get_risk(_claims: dict = Depends(require_tdr_user)) -> dict:
    snapshot = engine.snapshot()
    return {"riskByIp": snapshot["riskByIp"], "riskByUser": snapshot["riskByUser"]}


@app.get("/timeline")
def get_timeline(_claims: dict = Depends(require_tdr_user)) -> list[dict]:
    return engine.snapshot()["timeline"]


@app.get("/blocked-ips")
def get_blocked_ips(_claims: dict = Depends(require_tdr_user)) -> list[str]:
    return engine.snapshot()["blockedIps"]


@app.post("/blocked-ips")
def add_blocked_ip(payload: BlockIpRequest, _claims: dict = Depends(require_tdr_user)) -> dict:
    try:
        added = engine.block_ip(payload.ip, payload.source)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid IP address format or test IP cannot be blocked")
    return {"success": True, "ip": payload.ip, "added": added}


@app.delete("/blocked-ips/{ip}")
def remove_blocked_ip(ip: str, _claims: dict = Depends(require_tdr_user)) -> dict:
    try:
        removed = engine.unblock_ip(ip, "dashboard")
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid IP address format")
    if not removed:
        raise HTTPException(status_code=404, detail="IP not in blocklist")
    return {"success": True, "ip": ip, "removed": removed}


@app.get("/test-ips")
def get_test_ips(_claims: dict = Depends(require_tdr_admin)) -> list[str]:
    return engine.snapshot()["testIps"]


@app.post("/test-ips")
def add_test_ip(payload: TestIpRequest, _claims: dict = Depends(require_tdr_admin)) -> dict:
    try:
        added = engine.add_test_ip(payload.ip, payload.source)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid IP address format")
    return {"success": True, "ip": payload.ip, "added": added}


@app.delete("/test-ips/{ip}")
def remove_test_ip(ip: str, _claims: dict = Depends(require_tdr_admin)) -> dict:
    try:
        removed = engine.remove_test_ip(ip, "dashboard")
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid IP address format")
    if not removed:
        raise HTTPException(status_code=404, detail="IP not in test list")
    return {"success": True, "ip": ip, "removed": removed}


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


def _top_attack_patterns(alerts: list[dict]) -> list[dict]:
    counts: dict[str, int] = {}
    for alert in alerts:
        alert_type = alert.get("type", "UNKNOWN")
        counts[alert_type] = counts.get(alert_type, 0) + 1
    ranked = sorted(counts.items(), key=lambda item: item[1], reverse=True)
    return [{"pattern": key, "count": value} for key, value in ranked[:10]]
