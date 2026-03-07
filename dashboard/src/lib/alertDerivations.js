import { getIpDisplayInfo, normalizeEventName } from "./formatters.js";

export function isTimelineOnlyManagementEvent(endpointValue) {
  const endpoint = String(endpointValue || "").toLowerCase();
  return endpoint.includes("/api/auth/users") || endpoint.includes("/api/auth/change-password");
}

export function shouldShowInAlertPanels(alert) {
  if (!alert || alert.type === "BLACKLISTED_IP_ACCESS") {
    return false;
  }
  if (alert.type === "PRIV_ESC_ATTEMPT") {
    return true;
  }
  return !isTimelineOnlyManagementEvent(alert.endpoint);
}

export function getTimestampSecondBucket(isoTs) {
  const dt = new Date(isoTs);
  if (Number.isNaN(dt.getTime())) {
    return String(isoTs || "").slice(0, 19);
  }
  return new Date(Math.floor(dt.getTime() / 1000) * 1000).toISOString().slice(0, 19);
}

export function groupAlertsByEvent(inputAlerts) {
  const byKey = new Map();

  for (const alert of inputAlerts) {
    const eventName = normalizeEventName(alert.type);
    const ipValue = getIpDisplayInfo(alert.ip).value || "unknown";
    const secondBucket = getTimestampSecondBucket(alert.timestamp);
    const groupKey = `${eventName}|${ipValue}|${secondBucket}`;

    if (!byKey.has(groupKey)) {
      byKey.set(groupKey, {
        groupId: `grp-${alert.id}`,
        eventName,
        ipValue,
        secondBucket,
        alerts: [alert]
      });
      continue;
    }

    byKey.get(groupKey).alerts.push(alert);
  }

  return [...byKey.values()].sort(
    (a, b) => new Date(b.alerts[0]?.timestamp || 0).getTime() - new Date(a.alerts[0]?.timestamp || 0).getTime()
  );
}

function levelFor(score) {
  if (score >= 120) {
    return "CRITICAL";
  }
  if (score >= 70) {
    return "HIGH";
  }
  if (score >= 35) {
    return "MEDIUM";
  }
  return "LOW";
}

export function buildTestRiskByIp(timeline) {
  const scores = new Map();
  for (const entry of timeline) {
    const details = entry?.details || {};
    if (!details.isTestIp) {
      continue;
    }
    const ip = String(entry.ip || "unknown");
    const impact = Number(entry.scoreImpact || 0);
    scores.set(ip, (scores.get(ip) || 0) + impact);
  }
  return [...scores.entries()]
    .map(([ip, score]) => ({ ip, score, riskLevel: levelFor(score) }))
    .sort((a, b) => b.score - a.score || a.ip.localeCompare(b.ip));
}

export function buildAttackPatterns(inputAlerts) {
  const counts = new Map();
  for (const alert of inputAlerts) {
    const label = normalizeEventName(alert.type);
    counts.set(label, (counts.get(label) || 0) + 1);
  }
  return [...counts.entries()]
    .map(([pattern, count]) => ({ pattern, count }))
    .sort((a, b) => b.count - a.count || a.pattern.localeCompare(b.pattern));
}

export function buildVisibleTimeline(timeline, userRole) {
  const isAdminViewer = userRole === "admin";
  return timeline.filter((entry) => {
    const eventName = normalizeEventName(String(entry.event || ""));
    const isTestIncident = Boolean(entry?.details?.isTestIp);
    const rawEvent = String(entry.event || "");
    const isAdminOnlyTimelineEvent = (
      rawEvent === "ADMIN_CREATE_USER"
      || rawEvent === "ADMIN_DELETE_USER"
      || rawEvent === "ADMIN_RESET_USER_PASS"
    );

    if (eventName === "TEST_IP_ADDED" || eventName === "TEST_IP_REMOVED") {
      return true;
    }

    if (isAdminOnlyTimelineEvent && !isAdminViewer) {
      return false;
    }

    if (isTestIncident) {
      return false;
    }

    return eventName !== "BLOCKED_IP_REQUEST";
  });
}
