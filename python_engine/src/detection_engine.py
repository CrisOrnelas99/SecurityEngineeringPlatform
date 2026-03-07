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
from urllib.parse import unquote_plus

logger = logging.getLogger("tdr.engine")


class DetectionEngine:
    def __init__(self) -> None:
        self.log_path = Path(os.getenv("WEB_LOG_PATH", "/data/app.log"))
        self.blocklist_path = Path(os.getenv("BLOCKLIST_PATH", "/data/blocklist.json"))
        self.test_ips_path = Path(os.getenv("TEST_IPS_PATH", "/data/test_ips.json"))
        self.locked_users_path = Path(os.getenv("LOCKED_USERS_PATH", "/data/locked_users.json"))
        self.alerts_path = Path(os.getenv("ALERTS_PATH", "/data/alerts.json"))
        self.timeline_path = Path(os.getenv("TIMELINE_PATH", "/data/timeline.json"))
        self.load_persisted_state = self._env_bool("TDR_LOAD_PERSISTED_STATE", False)
        self.replay_log_on_start = self._env_bool("TDR_REPLAY_LOG_ON_START", False)
        self.auto_block_private_ips = self._env_bool("TDR_AUTO_BLOCK_PRIVATE_IPS", False)

        self._risk_by_ip: dict[str, int] = defaultdict(int)
        self._risk_by_user: dict[str, int] = defaultdict(int)
        self._alerts: list[dict[str, Any]] = []
        self._timeline: list[dict[str, Any]] = []
        self._blocked_ips: set[str] = set()
        self._test_ips: set[str] = set()
        self._locked_users: set[str] = set()

        self._failed_logins: dict[str, deque[float]] = defaultdict(deque)
        self._last_failed_login_burst_alert_at: dict[str, float] = defaultdict(float)
        self._failed_login_usernames: dict[str, deque[tuple[float, str]]] = defaultdict(deque)
        self._last_account_enum_alert_at: dict[str, float] = defaultdict(float)
        self._request_times: dict[str, deque[float]] = defaultdict(deque)
        self._excessive_rate_active_by_ip: dict[str, bool] = defaultdict(bool)
        self._abnormal_rate_active_by_ip: dict[str, bool] = defaultdict(bool)
        self._recent_honeypot_events: dict[tuple[str, str, str], float] = {}
        self._recent_signature_alerts: dict[tuple[str, str, str, str], float] = {}

        self._file_position = 0
        self._json_parse_errors = 0
        self._lock = threading.Lock()

        self.weights = {
            "FAILED_LOGIN_BURST": 35,
            "ACCOUNT_ENUMERATION": 30,
            "PRIV_ESC_ATTEMPT": 25,
            "PATH_TRAVERSAL_ATTEMPT": 45,
            "EXCESSIVE_API_CALLS": 20,
            "HONEYPOT_TRIGGER": 90,
            "ABNORMAL_REQUEST_FREQUENCY": 30,
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
        self._save_json_list(self.test_ips_path, sorted(self._test_ips))
        self._save_json_list(self.locked_users_path, sorted(self._locked_users))
        self._save_json_list(self.alerts_path, self._alerts[-1000:])
        self._save_json_list(self.timeline_path, self._timeline[-2000:])

    def bootstrap_state(self) -> None:
        if self.load_persisted_state:
            self._blocked_ips = set(self._load_json_list(self.blocklist_path))
            self._test_ips = set(self._load_json_list(self.test_ips_path))
            self._locked_users = set(self._load_json_list(self.locked_users_path))
            self._alerts = self._load_json_list(self.alerts_path)
            self._timeline = self._load_json_list(self.timeline_path)
        else:
            # Fresh start mode: clear historical artifacts so dashboard starts clean.
            self._blocked_ips = set()
            self._test_ips = set()
            self._locked_users = set()
            self._alerts = []
            self._timeline = []
            self._save_json_list(self.blocklist_path, [])
            self._save_json_list(self.test_ips_path, [])
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
            details = entry.get("details") or {}
            is_test_ip = bool(details.get("isTestIp"))
            if not is_test_ip:
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

    @staticmethod
    def _normalize_ip(ip: str) -> str:
        value = str(ip or "")
        return value[7:] if value.startswith("::ffff:") else value

    def _is_private_or_local_ip(self, ip: str) -> bool:
        normalized = self._normalize_ip(ip)
        try:
            parsed = ipaddress.ip_address(normalized)
        except ValueError:
            return False
        return parsed.is_private or parsed.is_loopback or parsed.is_link_local

    @staticmethod
    def _decode_for_signatures(value: str) -> str:
        # Decode URL-encoded attack payloads so signature matching catches
        # both raw and encoded forms (e.g., "union select" vs "union%20select").
        text = str(value or "")
        for _ in range(2):
            decoded = unquote_plus(text)
            if decoded == text:
                break
            text = decoded
        return text.lower()

    def _record_incident(self, event_type: str, event: dict[str, Any], score: int, details: dict[str, Any]) -> None:
        ip = event.get("ip", "unknown")
        user_id = event.get("userId") or "anonymous"
        is_test_ip = ip in self._test_ips
        details_payload = dict(details or {})
        if is_test_ip:
            details_payload["isTestIp"] = True
            details_payload["description"] = "Test IP traffic detected. Alert recorded and auto-block skipped."

        if not is_test_ip:
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
            "details": details_payload,
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
                "details": details_payload,
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
        # Test IPs are excluded so training traffic still generates alerts
        # without polluting the blocklist.
        if ip and ip != "unknown":
            should_block = True
            if ip in self._test_ips:
                should_block = False
                actions.append("TEST_IP_NO_BLOCK")
            if should_block:
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

    def _is_duplicate_signature_alert(self, alert_type: str, ip: str, method: str, endpoint: str, now: float) -> bool:
        key = (alert_type, ip, method, endpoint)
        seen_at = self._recent_signature_alerts.get(key)
        if seen_at is not None and (now - seen_at) <= 2.0:
            return True
        self._recent_signature_alerts[key] = now
        return False

    def _detect(self, event: dict[str, Any]) -> None:
        ip = event.get("ip", "unknown")
        endpoint_raw = event.get("endpoint") or ""
        endpoint = str(endpoint_raw).lower()
        decoded_endpoint = self._decode_for_signatures(str(endpoint_raw))
        method = (event.get("method") or "").upper()
        error_type = (event.get("errorType") or "").lower()
        metadata = event.get("metadata") or {}
        now = time.time()

        # Keep honeypot correlation cache short-lived to avoid stale suppression.
        stale_keys = [key for key, ts in self._recent_honeypot_events.items() if (now - ts) > 10.0]
        for key in stale_keys:
            self._recent_honeypot_events.pop(key, None)
        stale_signature_keys = [key for key, ts in self._recent_signature_alerts.items() if (now - ts) > 10.0]
        for key in stale_signature_keys:
            self._recent_signature_alerts.pop(key, None)

        if event.get("event") == "HONEYPOT_TRIGGER":
            self._mark_honeypot_event(ip, endpoint, method, now)

        if event.get("event") == "LOGIN_FAIL":
            dq = self._failed_logins[ip]
            dq.append(now)
            while dq and (now - dq[0]) > 300:
                dq.popleft()
            last_burst_at = self._last_failed_login_burst_alert_at[ip]
            if len(dq) >= 5 and (now - last_burst_at) > 10:
                self._record_incident("FAILED_LOGIN_BURST", event, self.weights["FAILED_LOGIN_BURST"], {"attempts5m": len(dq)})
                self._last_failed_login_burst_alert_at[ip] = now

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

        # Skip immediate REQUEST_AUDIT for a just-seen honeypot hit to avoid
        # duplicate path-traversal alerts for the same request.
        is_honeypot_followup = self._is_honeypot_followup_audit(event, now)
        traversal_signals = ["../", "..\\", "%2e%2e", "%252e%252e", "..%2f", "..%5c"]
        context_blob = self._decode_for_signatures(json.dumps(metadata)) + " " + endpoint + " " + decoded_endpoint + " " + error_type
        if (
            not is_honeypot_followup
            and any(signal in context_blob for signal in traversal_signals)
            and not self._is_duplicate_signature_alert("PATH_TRAVERSAL_ATTEMPT", ip, method, endpoint, now)
        ):
            self._record_incident("PATH_TRAVERSAL_ATTEMPT", event, self.weights["PATH_TRAVERSAL_ATTEMPT"], {"endpoint": endpoint})

        # Count honeypot probes once, based only on the dedicated honeypot event
        # emitted by the webapp route itself. REQUEST_AUDIT lines for the same
        # request should not generate duplicate honeypot alerts.
        if event.get("event") == "HONEYPOT_TRIGGER":
            self._record_incident("HONEYPOT_TRIGGER", event, self.weights["HONEYPOT_TRIGGER"], {"endpoint": endpoint})

        # Admin management actions are timeline-only events (not active alerts).
        if event.get("event") == "REGISTER_SUCCESS":
            self._timeline.append(
                {
                    "timestamp": self._now().isoformat(),
                    "event": "ADMIN_CREATE_USER",
                    "ip": ip,
                    "userId": event.get("userId") or "anonymous",
                    "scoreImpact": 0,
                    "cumulativeRisk": self._risk_by_ip.get(ip, 0),
                    "actionsTaken": [],
                    "details": {
                        "targetUserId": metadata.get("createdUserId"),
                        "targetUsername": metadata.get("createdUsername"),
                        "targetRole": metadata.get("role"),
                        "actorUsername": metadata.get("actorUsername"),
                    },
                }
            )
            self._persist_state()

        if event.get("event") == "USER_DELETE":
            self._timeline.append(
                {
                    "timestamp": self._now().isoformat(),
                    "event": "ADMIN_DELETE_USER",
                    "ip": ip,
                    "userId": event.get("userId") or "anonymous",
                    "scoreImpact": 0,
                    "cumulativeRisk": self._risk_by_ip.get(ip, 0),
                    "actionsTaken": [],
                    "details": {
                        "targetUserId": metadata.get("deletedUserId"),
                        "targetUsername": metadata.get("targetUsername"),
                        "actorUsername": metadata.get("actorUsername"),
                    },
                }
            )
            self._persist_state()

        if event.get("event") == "USER_PASSWORD_RESET":
            self._timeline.append(
                {
                    "timestamp": self._now().isoformat(),
                    "event": "ADMIN_RESET_USER_PASS",
                    "ip": ip,
                    "userId": event.get("userId") or "anonymous",
                    "scoreImpact": 0,
                    "cumulativeRisk": self._risk_by_ip.get(ip, 0),
                    "actionsTaken": [],
                    "details": {
                        "targetUserId": metadata.get("targetUserId"),
                        "targetUsername": metadata.get("targetUsername"),
                    },
                }
            )
            self._persist_state()

        # Request-rate detections are based on request audit events only.
        # Also ignore admin user-management endpoints to avoid noisy false positives
        # during legitimate admin operations (delete/reset/change password flows).
        if event.get("event") == "REQUEST_AUDIT":
            is_admin_mgmt_endpoint = (
                endpoint.startswith("/api/auth/users")
                or endpoint.startswith("/api/auth/change-password")
            )
            if not is_admin_mgmt_endpoint:
                req_dq = self._request_times[ip]
                req_dq.append(now)
                while req_dq and (now - req_dq[0]) > 60:
                    req_dq.popleft()

                # Keep global thresholds conservative to avoid noisy dashboard traffic,
                # but allow lower lab thresholds for explicit /api/health burst tests.
                if endpoint.startswith("/api/health"):
                    excessive_threshold = 40
                    abnormal_threshold = 80
                else:
                    excessive_threshold = 80
                    abnormal_threshold = 140

                rpm = len(req_dq)

                # Emit once when traffic crosses threshold, then suppress repeats
                # until it drops back below threshold (new burst => new alert).
                if rpm > excessive_threshold:
                    if not self._excessive_rate_active_by_ip[ip]:
                        self._record_incident("EXCESSIVE_API_CALLS", event, self.weights["EXCESSIVE_API_CALLS"], {"rpm": rpm})
                        self._excessive_rate_active_by_ip[ip] = True
                else:
                    self._excessive_rate_active_by_ip[ip] = False

                if rpm > abnormal_threshold:
                    if not self._abnormal_rate_active_by_ip[ip]:
                        self._record_incident(
                            "ABNORMAL_REQUEST_FREQUENCY", event, self.weights["ABNORMAL_REQUEST_FREQUENCY"], {"rpm": rpm}
                        )
                        self._abnormal_rate_active_by_ip[ip] = True
                else:
                    self._abnormal_rate_active_by_ip[ip] = False


    def ingest_line(self, line: str) -> None:
        line = line.strip()
        if not line:
            return
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            with self._lock:
                self._json_parse_errors += 1
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

    def clear_alerts(self, actor_user_id: str = "anonymous", actor_username: str | None = None, actor_role: str | None = None) -> int:
        with self._lock:
            cleared = len(self._alerts)
            self._alerts = []
            self._timeline = []
            self._rebuild_risk_from_timeline()
            self._timeline.append(
                {
                    "timestamp": self._now().isoformat(),
                    "event": "CLEAR_ALL_ALERTS",
                    "ip": "unknown",
                    "userId": actor_user_id or "anonymous",
                    "scoreImpact": 0,
                    "cumulativeRisk": 0,
                    "actionsTaken": [],
                    "details": {
                        "clearedAlerts": cleared,
                        "actorUsername": actor_username,
                        "actorRole": actor_role,
                    },
                }
            )
            self._persist_state()
            return cleared

    def block_ip(self, ip: str, source: str = "manual") -> bool:
        ipaddress.ip_address(ip)
        with self._lock:
            if ip in self._test_ips:
                raise ValueError("Test IP cannot be added to blocklist")
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

    def add_test_ip(self, ip: str, source: str = "dashboard") -> bool:
        ipaddress.ip_address(ip)
        with self._lock:
            added = ip not in self._test_ips
            removed_from_blocklist = ip in self._blocked_ips
            self._test_ips.add(ip)
            if removed_from_blocklist:
                self._blocked_ips.remove(ip)
            if added or removed_from_blocklist:
                self._timeline.append(
                    {
                        "timestamp": self._now().isoformat(),
                        "event": "TEST_IP_ADDED",
                        "ip": ip,
                        "userId": "system",
                        "scoreImpact": 0,
                        "cumulativeRisk": self._risk_by_ip.get(ip, 0),
                        "source": source,
                        "details": {"removedFromBlocklist": removed_from_blocklist},
                    }
                )
            self._persist_state()
            logger.info("test_ip_add ip=%s source=%s added=%s removed_from_blocklist=%s", ip, source, added, removed_from_blocklist)
            return added

    def remove_test_ip(self, ip: str, source: str = "dashboard") -> bool:
        ipaddress.ip_address(ip)
        with self._lock:
            if ip not in self._test_ips:
                return False
            self._test_ips.remove(ip)
            self._timeline.append(
                {
                    "timestamp": self._now().isoformat(),
                    "event": "TEST_IP_REMOVED",
                    "ip": ip,
                    "userId": "system",
                    "scoreImpact": 0,
                    "cumulativeRisk": self._risk_by_ip.get(ip, 0),
                    "source": source,
                }
            )
            self._persist_state()
            logger.info("test_ip_remove ip=%s source=%s removed=true", ip, source)
            return True

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

    def delete_alert(
        self,
        alert_id: str,
        actor_user_id: str = "anonymous",
        actor_username: str | None = None,
        actor_role: str | None = None,
    ) -> bool:
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
            target_ip = str(target.get("ip") or "unknown")
            self._timeline.append(
                {
                    "timestamp": self._now().isoformat(),
                    "event": "CLEAR_ALERT_EVENT",
                    "ip": target_ip,
                    "userId": actor_user_id or "anonymous",
                    "scoreImpact": 0,
                    "cumulativeRisk": self._risk_by_ip.get(target_ip, 0),
                    "actionsTaken": [],
                    "details": {
                        "deletedAlertId": alert_id,
                        "deletedAlertType": target.get("type"),
                        "actorUsername": actor_username,
                        "actorRole": actor_role,
                    },
                }
            )
            self._persist_state()
            return True

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            try:
                log_size = self.log_path.stat().st_size
            except OSError:
                log_size = 0
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
                "testIps": sorted(self._test_ips),
                "lockedUsers": sorted(self._locked_users),
                "health": {
                    "logFilePosition": self._file_position,
                    "logFileSize": log_size,
                    "ingestBacklogBytes": max(0, log_size - self._file_position),
                    "jsonParseErrors": self._json_parse_errors,
                },
            }
