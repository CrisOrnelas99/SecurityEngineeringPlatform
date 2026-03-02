import hashlib
import ipaddress
import json
import logging
import os
import threading
import time
from collections import defaultdict, deque
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .crypto_core_client import CryptoCoreClient

logger = logging.getLogger("soc.engine")


class DetectionEngine:
    def __init__(self) -> None:
        self.log_path = Path(os.getenv("WEB_LOG_PATH", "/data/app.log"))
        self.blocklist_path = Path(os.getenv("BLOCKLIST_PATH", "/data/blocklist.json"))
        self.locked_users_path = Path(os.getenv("LOCKED_USERS_PATH", "/data/locked_users.json"))
        self.alerts_path = Path(os.getenv("ALERTS_PATH", "/data/alerts.json"))
        self.timeline_path = Path(os.getenv("TIMELINE_PATH", "/data/timeline.json"))
        self.load_persisted_state = self._env_bool("SOC_LOAD_PERSISTED_STATE", False)
        self.replay_log_on_start = self._env_bool("SOC_REPLAY_LOG_ON_START", False)

        self._risk_by_ip: dict[str, int] = defaultdict(int)
        self._risk_by_user: dict[str, int] = defaultdict(int)
        self._alerts: list[dict[str, Any]] = []
        self._timeline: list[dict[str, Any]] = []
        self._blocked_ips: set[str] = set()
        self._locked_users: set[str] = set()

        self._failed_logins: dict[str, deque[float]] = defaultdict(deque)
        self._failed_login_usernames: dict[str, deque[tuple[float, str]]] = defaultdict(deque)
        self._last_account_enum_alert_at: dict[str, float] = defaultdict(float)
        self._request_times: dict[str, deque[float]] = defaultdict(deque)
        self._user_token_ips: dict[str, set[str]] = defaultdict(set)
        self._baseline_logins: dict[str, deque[float]] = defaultdict(deque)
        self._token_fingerprint_ips: dict[str, set[str]] = defaultdict(set)
        self._recent_honeypot_events: dict[tuple[str, str, str], float] = {}

        self._file_position = 0
        self._lock = threading.Lock()
        self._crypto = CryptoCoreClient()

        self.weights = {
            "FAILED_LOGIN_BURST": 35,
            "ACCOUNT_ENUMERATION": 30,
            "SUSPICIOUS_JWT_REUSE": 30,
            "PRIV_ESC_ATTEMPT": 25,
            "INJECTION_ATTEMPT": 40,
            "PATH_TRAVERSAL_ATTEMPT": 45,
            "EXCESSIVE_API_CALLS": 20,
            "HONEYPOT_TRIGGER": 90,
            "ABNORMAL_REQUEST_FREQUENCY": 30,
            "BLACKLISTED_IP_ACCESS": 100,
        }

    @staticmethod
    def _now() -> datetime:
        return datetime.now(tz=timezone.utc)

    @staticmethod
    def _env_bool(name: str, default: bool) -> bool:
        value = os.getenv(name)
        if value is None:
            return default
        return value.strip().lower() in {"1", "true", "yes", "on"}

    def _load_json_list(self, path: Path) -> list[Any]:
        if not path.exists():
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("[]", encoding="utf-8")
            return []
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            return []

    def _save_json_list(self, path: Path, data: list[Any]) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(data, indent=2), encoding="utf-8")

    def _persist_state(self) -> None:
        self._save_json_list(self.blocklist_path, sorted(self._blocked_ips))
        self._save_json_list(self.locked_users_path, sorted(self._locked_users))
        self._save_json_list(self.alerts_path, self._alerts[-1000:])
        self._save_json_list(self.timeline_path, self._timeline[-2000:])

    def bootstrap_state(self) -> None:
        if self.load_persisted_state:
            self._blocked_ips = set(self._load_json_list(self.blocklist_path))
            self._locked_users = set(self._load_json_list(self.locked_users_path))
            self._alerts = self._load_json_list(self.alerts_path)
            self._timeline = self._load_json_list(self.timeline_path)
        else:
            # Fresh start mode: clear historical artifacts so dashboard starts clean.
            self._blocked_ips = set()
            self._locked_users = set()
            self._alerts = []
            self._timeline = []
            self._save_json_list(self.blocklist_path, [])
            self._save_json_list(self.locked_users_path, [])
            self._save_json_list(self.alerts_path, [])
            self._save_json_list(self.timeline_path, [])

        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        self.log_path.touch(exist_ok=True)
        self._file_position = 0 if self.replay_log_on_start else self.log_path.stat().st_size
        self._rebuild_risk_from_timeline()

    def _rebuild_risk_from_timeline(self) -> None:
        self._risk_by_ip = defaultdict(int)
        self._risk_by_user = defaultdict(int)
        for entry in self._timeline:
            ip = entry.get("ip", "unknown")
            user_id = entry.get("userId") or "anonymous"
            score_impact = int(entry.get("scoreImpact", 0))
            self._risk_by_ip[ip] += score_impact
            self._risk_by_user[user_id] += score_impact

    def _risk_level(self, score: int) -> str:
        if score >= 120:
            return "CRITICAL"
        if score >= 70:
            return "HIGH"
        if score >= 35:
            return "MEDIUM"
        return "LOW"

    def _record_incident(self, event_type: str, event: dict[str, Any], score: int, details: dict[str, Any]) -> None:
        ip = event.get("ip", "unknown")
        user_id = event.get("userId") or "anonymous"

        self._risk_by_ip[ip] += score
        self._risk_by_user[user_id] += score

        alert = {
            "id": hashlib.sha256(f"{event.get('timestamp')}-{event_type}-{ip}-{user_id}".encode()).hexdigest()[:16],
            "timestamp": self._now().isoformat(),
            "type": event_type,
            "ip": ip,
            "userId": user_id,
            "score": score,
            "riskLevel": self._risk_level(self._risk_by_ip[ip]),
            "endpoint": event.get("endpoint"),
            "method": event.get("method"),
            "errorType": event.get("errorType"),
            "details": details,
        }

        actions_taken = self._automated_response(alert)
        alert["actionsTaken"] = actions_taken
        self._alerts.append(alert)
        self._timeline.append(
            {
                "timestamp": alert["timestamp"],
                "event": event_type,
                "ip": ip,
                "userId": user_id,
                "scoreImpact": score,
                "cumulativeRisk": self._risk_by_ip[ip],
                "actionsTaken": actions_taken,
                "details": details,
            }
        )
        if "BLACKLISTED_IP_ACCESS" in actions_taken:
            self._timeline.append(
                {
                    "timestamp": self._now().isoformat(),
                    "event": "AUTO_BLOCK_IP_ACCESS",
                    "ip": ip,
                    "userId": user_id,
                    "scoreImpact": 0,
                    "cumulativeRisk": self._risk_by_ip[ip],
                    "actionsTaken": [],
                    "details": {"reasonEvent": event_type},
                }
            )
        self._persist_state()
        logger.info(
            "incident=%s ip=%s user=%s score=%s level=%s actions=%s endpoint=%s",
            event_type,
            ip,
            user_id,
            score,
            alert["riskLevel"],
            ",".join(actions_taken) if actions_taken else "NONE",
            alert.get("endpoint") or "n/a",
        )

    def _automated_response(self, alert: dict[str, Any]) -> list[str]:
        ip = alert["ip"]
        user_id = alert["userId"]
        actions: list[str] = []

        # Auto-block source IP for every detected incident event.
        if ip and ip != "unknown":
            if ip not in self._blocked_ips:
                actions.append("BLACKLISTED_IP_ACCESS")
            self._blocked_ips.add(ip)

        if self._risk_by_user[user_id] >= 90 and user_id != "anonymous":
            if user_id not in self._locked_users:
                actions.append("LOCKED_USER")
            self._locked_users.add(user_id)

        return actions

    def _mark_honeypot_event(self, ip: str, endpoint: str, method: str, seen_at: float) -> None:
        self._recent_honeypot_events[(ip, endpoint, method)] = seen_at

    def _is_honeypot_followup_audit(self, event: dict[str, Any], now: float) -> bool:
        if event.get("event") != "REQUEST_AUDIT":
            return False

        ip = event.get("ip", "unknown")
        endpoint = (event.get("endpoint") or "").lower()
        method = (event.get("method") or "").upper()
        key = (ip, endpoint, method)
        seen_at = self._recent_honeypot_events.get(key)
        if seen_at is None:
            return False

        # REQUEST_AUDIT is emitted after route handling for the same request.
        # A small window avoids a duplicate BLACKLISTED_IP_ACCESS for that one hit.
        return (now - seen_at) <= 2.0

    def _detect(self, event: dict[str, Any]) -> None:
        ip = event.get("ip", "unknown")
        user_id = event.get("userId") or "anonymous"
        endpoint = (event.get("endpoint") or "").lower()
        method = (event.get("method") or "").upper()
        error_type = (event.get("errorType") or "").lower()
        metadata = event.get("metadata") or {}
        now = time.time()

        # Keep honeypot correlation cache short-lived to avoid stale suppression.
        stale_keys = [key for key, ts in self._recent_honeypot_events.items() if (now - ts) > 10.0]
        for key in stale_keys:
            self._recent_honeypot_events.pop(key, None)

        if event.get("event") == "HONEYPOT_TRIGGER":
            self._mark_honeypot_event(ip, endpoint, method, now)

        # Avoid double-alerting on the same honeypot request:
        # `HONEYPOT_TRIGGER` and its immediate `REQUEST_AUDIT` should count once.
        if ip in self._blocked_ips and event.get("event") != "HONEYPOT_TRIGGER" and not self._is_honeypot_followup_audit(event, now):
            self._record_incident(
                "BLACKLISTED_IP_ACCESS",
                event,
                self.weights["BLACKLISTED_IP_ACCESS"],
                {
                    "ip": ip,
                    "method": event.get("method"),
                    "endpoint": event.get("endpoint"),
                    "errorType": event.get("errorType"),
                },
            )
            # If request was already denied by blocklist controls, do not run
            # additional detectors on the same denied traffic.
            if event.get("event") == "BLOCKLIST_DENY" or error_type == "blockedip":
                return

        if event.get("event") == "LOGIN_FAIL":
            dq = self._failed_logins[ip]
            dq.append(now)
            while dq and (now - dq[0]) > 300:
                dq.popleft()
            if len(dq) >= 5:
                self._record_incident("FAILED_LOGIN_BURST", event, self.weights["FAILED_LOGIN_BURST"], {"attempts5m": len(dq)})

            attempted_username = str((metadata.get("username") if isinstance(metadata, dict) else "") or "").strip().lower()
            if attempted_username:
                user_dq = self._failed_login_usernames[ip]
                user_dq.append((now, attempted_username))
                while user_dq and (now - user_dq[0][0]) > 600:
                    user_dq.popleft()
                distinct_usernames = {username for _, username in user_dq}
                last_alert_at = self._last_account_enum_alert_at[ip]
                if len(distinct_usernames) >= 5 and (now - last_alert_at) > 120:
                    self._record_incident(
                        "ACCOUNT_ENUMERATION",
                        event,
                        self.weights["ACCOUNT_ENUMERATION"],
                        {"distinctUsernames10m": len(distinct_usernames)},
                    )
                    self._last_account_enum_alert_at[ip] = now

        if event.get("event") == "AUTHZ_DENIED":
            self._record_incident("PRIV_ESC_ATTEMPT", event, self.weights["PRIV_ESC_ATTEMPT"], {"endpoint": endpoint})

        # Simple signature-based checks are useful as a first line before deeper parsing.
        # Skip immediate REQUEST_AUDIT for a just-seen honeypot hit to avoid duplicate
        # INJECTION_ATTEMPT alerts from the same HTTP request.
        is_honeypot_followup = self._is_honeypot_followup_audit(event, now)
        traversal_signals = ["../", "..\\", "%2e%2e", "%252e%252e", "..%2f", "..%5c"]
        injection_signals = ["$ne", "union select", " or 1=1", "<script", "drop table"]
        context_blob = json.dumps(metadata).lower() + " " + endpoint + " " + error_type
        if event.get("event") != "REQUEST_AUDIT" and not is_honeypot_followup and any(signal in context_blob for signal in traversal_signals):
            self._record_incident("PATH_TRAVERSAL_ATTEMPT", event, self.weights["PATH_TRAVERSAL_ATTEMPT"], {"endpoint": endpoint})
        if event.get("event") != "REQUEST_AUDIT" and not is_honeypot_followup and any(signal in context_blob for signal in injection_signals):
            self._record_incident("INJECTION_ATTEMPT", event, self.weights["INJECTION_ATTEMPT"], {"endpoint": endpoint})

        # Count honeypot probes once, based only on the dedicated honeypot event
        # emitted by the webapp route itself. REQUEST_AUDIT lines for the same
        # request should not generate duplicate honeypot alerts.
        if event.get("event") == "HONEYPOT_TRIGGER":
            self._record_incident("HONEYPOT_TRIGGER", event, self.weights["HONEYPOT_TRIGGER"], {"endpoint": endpoint})

        req_dq = self._request_times[ip]
        req_dq.append(now)
        while req_dq and (now - req_dq[0]) > 60:
            req_dq.popleft()
        if len(req_dq) > 80:
            self._record_incident("EXCESSIVE_API_CALLS", event, self.weights["EXCESSIVE_API_CALLS"], {"rpm": len(req_dq)})

        if len(req_dq) > 140:
            self._record_incident(
                "ABNORMAL_REQUEST_FREQUENCY", event, self.weights["ABNORMAL_REQUEST_FREQUENCY"], {"rpm": len(req_dq)}
            )

        if method == "POST" and endpoint.endswith("/refresh") and user_id != "anonymous":
            self._user_token_ips[user_id].add(ip)
            if len(self._user_token_ips[user_id]) >= 3:
                self._record_incident(
                    "SUSPICIOUS_JWT_REUSE",
                    event,
                    self.weights["SUSPICIOUS_JWT_REUSE"],
                    {"distinctIps": len(self._user_token_ips[user_id])},
                )
            token_fp = metadata.get("tokenFingerprint")
            if token_fp:
                self._token_fingerprint_ips[token_fp].add(ip)
                if len(self._token_fingerprint_ips[token_fp]) >= 2:
                    self._record_incident(
                        "SUSPICIOUS_JWT_REUSE",
                        event,
                        self.weights["SUSPICIOUS_JWT_REUSE"],
                        {"tokenFingerprint": token_fp, "distinctIps": len(self._token_fingerprint_ips[token_fp])},
                    )

        if "jwt" in metadata:
            # The Python SOC can delegate cryptographic verification to the C++ core when raw JWT is available.
            verification = self._crypto.verify_jwt(str(metadata["jwt"]))
            if not verification.get("valid", False):
                self._record_incident(
                    "SUSPICIOUS_JWT_REUSE",
                    event,
                    self.weights["SUSPICIOUS_JWT_REUSE"],
                    {"reason": verification.get("error")},
                )

        if event.get("event") == "LOGIN_SUCCESS" and user_id != "anonymous":
            history = self._baseline_logins[user_id]
            history.append(now)
            while history and (now - history[0]) > 86400 * 14:
                history.popleft()
            if len(history) >= 10:
                per_hour = len(history) / (14 * 24)
                last_hour = len([ts for ts in history if now - ts <= 3600])
                if last_hour > max(3, per_hour * 6):
                    self._record_incident(
                        "ABNORMAL_REQUEST_FREQUENCY",
                        event,
                        self.weights["ABNORMAL_REQUEST_FREQUENCY"],
                        {"baselineLoginsPerHour": round(per_hour, 2), "recentLogins1h": last_hour},
                    )

    def ingest_line(self, line: str) -> None:
        line = line.strip()
        if not line:
            return
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            return

        with self._lock:
            self._detect(event)

    def process_new_logs(self) -> None:
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        self.log_path.touch(exist_ok=True)

        with self.log_path.open("r", encoding="utf-8") as handle:
            handle.seek(self._file_position)
            for line in handle:
                self.ingest_line(line)
            self._file_position = handle.tell()

    def run_forever(self, poll_seconds: float = 1.0) -> None:
        self.bootstrap_state()
        while True:
            self.process_new_logs()
            time.sleep(poll_seconds)

    def start_background(self) -> None:
        thread = threading.Thread(target=self.run_forever, daemon=True)
        thread.start()

    def clear_alerts(self) -> int:
        with self._lock:
            cleared = len(self._alerts)
            self._alerts = []
            self._timeline = []
            self._rebuild_risk_from_timeline()
            self._persist_state()
            return cleared

    def block_ip(self, ip: str, source: str = "manual") -> bool:
        ipaddress.ip_address(ip)
        with self._lock:
            added = ip not in self._blocked_ips
            self._blocked_ips.add(ip)
            if added:
                self._timeline.append(
                    {
                        "timestamp": self._now().isoformat(),
                        "event": "MANUAL_BLOCK_IP",
                        "ip": ip,
                        "userId": "system",
                        "scoreImpact": 0,
                        "cumulativeRisk": self._risk_by_ip.get(ip, 0),
                        "source": source,
                    }
                )
            self._persist_state()
            logger.info("manual_block ip=%s source=%s added=%s", ip, source, added)
            return added

    def unblock_ip(self, ip: str, source: str = "manual") -> bool:
        ipaddress.ip_address(ip)
        with self._lock:
            if ip not in self._blocked_ips:
                return False
            self._blocked_ips.remove(ip)
            self._timeline.append(
                {
                    "timestamp": self._now().isoformat(),
                    "event": "MANUAL_UNBLOCK_IP",
                    "ip": ip,
                    "userId": "system",
                    "scoreImpact": 0,
                    "cumulativeRisk": self._risk_by_ip.get(ip, 0),
                    "source": source,
                }
            )
            self._persist_state()
            logger.info("manual_unblock ip=%s source=%s removed=true", ip, source)
            return True

    def delete_alert(self, alert_id: str) -> bool:
        with self._lock:
            target = next((a for a in self._alerts if a.get("id") == alert_id), None)
            if target is None:
                return False

            self._alerts = [a for a in self._alerts if a.get("id") != alert_id]
            self._timeline = [
                t for t in self._timeline
                if not (
                    t.get("timestamp") == target.get("timestamp")
                    and t.get("event") == target.get("type")
                    and t.get("ip") == target.get("ip")
                    and t.get("userId") == target.get("userId")
                    and int(t.get("scoreImpact", 0)) == int(target.get("score", 0))
                )
            ]
            self._rebuild_risk_from_timeline()
            self._persist_state()
            return True

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            return {
                "alerts": self._alerts[-200:],
                "riskByIp": [
                    {"ip": ip, "score": score, "riskLevel": self._risk_level(score)}
                    for ip, score in sorted(self._risk_by_ip.items(), key=lambda i: i[1], reverse=True)
                ],
                "riskByUser": [
                    {"userId": user, "score": score, "riskLevel": self._risk_level(score)}
                    for user, score in sorted(self._risk_by_user.items(), key=lambda i: i[1], reverse=True)
                ],
                "timeline": self._timeline[-300:],
                "blockedIps": sorted(self._blocked_ips),
                "lockedUsers": sorted(self._locked_users),
            }
