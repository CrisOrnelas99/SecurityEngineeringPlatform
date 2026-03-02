import logging

from fastapi import FastAPI
from fastapi import HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from .detection_engine import DetectionEngine

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")

app = FastAPI(title="SOC Detection Engine", version="1.0.0")
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


@app.on_event("startup")
def startup_event() -> None:
    engine.start_background()


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/alerts")
def get_alerts() -> list[dict]:
    return engine.snapshot()["alerts"]


@app.delete("/alerts")
def clear_alerts() -> dict:
    cleared = engine.clear_alerts()
    return {"success": True, "cleared": cleared}


@app.delete("/alerts/{alert_id}")
def delete_alert(alert_id: str) -> dict:
    deleted = engine.delete_alert(alert_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Alert not found")
    return {"success": True, "deletedId": alert_id}


@app.get("/risk")
def get_risk() -> dict:
    snapshot = engine.snapshot()
    return {"riskByIp": snapshot["riskByIp"], "riskByUser": snapshot["riskByUser"]}


@app.get("/timeline")
def get_timeline() -> list[dict]:
    return engine.snapshot()["timeline"]


@app.get("/blocked-ips")
def get_blocked_ips() -> list[str]:
    return engine.snapshot()["blockedIps"]


@app.post("/blocked-ips")
def add_blocked_ip(payload: BlockIpRequest) -> dict:
    try:
        added = engine.block_ip(payload.ip, payload.source)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid IP address format")
    return {"success": True, "ip": payload.ip, "added": added}


@app.delete("/blocked-ips/{ip}")
def remove_blocked_ip(ip: str) -> dict:
    try:
        removed = engine.unblock_ip(ip, "dashboard")
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid IP address format")
    if not removed:
        raise HTTPException(status_code=404, detail="IP not in blocklist")
    return {"success": True, "ip": ip, "removed": removed}


@app.get("/summary")
def get_summary() -> dict:
    snapshot = engine.snapshot()
    active_alerts = [a for a in snapshot["alerts"] if a.get("type") != "BLACKLISTED_IP_ACCESS"]
    honeypot_count = len([a for a in snapshot["alerts"] if a.get("type") == "HONEYPOT_TRIGGER"])
    return {
        "activeAlerts": len(active_alerts),
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
