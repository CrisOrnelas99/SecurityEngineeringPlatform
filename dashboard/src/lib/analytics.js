export function getAnalyticsWindowOptions(granularity) {
  if (granularity === "hourly") {
    return [
      { value: "24h", label: "Last 24h" },
      { value: "72h", label: "Last 72h" }
    ];
  }
  return [
    { value: "7d", label: "Last 7d" },
    { value: "30d", label: "Last 30d" }
  ];
}

export function getAnalyticsRangeMs(granularity, windowKey) {
  if (granularity === "hourly") {
    return windowKey === "72h" ? 72 * 60 * 60 * 1000 : 24 * 60 * 60 * 1000;
  }
  return windowKey === "30d" ? 30 * 24 * 60 * 60 * 1000 : 7 * 24 * 60 * 60 * 1000;
}

export function getAnalyticsEventTypes(timeline) {
  return [...new Set(timeline
    .filter((entry) => !Boolean(entry?.details?.isTestIp))
    .map((entry) => String(entry.event || ""))
    .filter(Boolean))]
    .sort((a, b) => a.localeCompare(b));
}

export function filterAnalyticsEvents(timeline, selectedTypes, rangeMs) {
  const now = Date.now();
  const start = now - rangeMs;
  return timeline
    .filter((entry) => {
      if (Boolean(entry?.details?.isTestIp)) {
        return false;
      }
      const eventType = String(entry.event || "");
      if (!selectedTypes.includes(eventType)) {
        return false;
      }
      const ts = new Date(entry.timestamp).getTime();
      if (Number.isNaN(ts)) {
        return false;
      }
      return ts >= start && ts <= now;
    })
    .sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime());
}

export function buildAnalyticsBucketRows(events, granularity) {
  const normalizeBucket = (ms) => {
    const dt = new Date(ms);
    if (granularity === "hourly") {
      dt.setMinutes(0, 0, 0);
    } else {
      dt.setHours(0, 0, 0, 0);
    }
    return dt.getTime();
  };

  const byBucket = new Map();
  for (const entry of events) {
    const ts = new Date(entry.timestamp).getTime();
    const bucketStart = normalizeBucket(ts);
    if (!byBucket.has(bucketStart)) {
      byBucket.set(bucketStart, { entries: [] });
    }
    const row = byBucket.get(bucketStart);
    row.entries.push(entry);
    row.byType = row.byType || {};
    const eventType = String(entry.event || "");
    row.byType[eventType] = (row.byType[eventType] || 0) + 1;
  }

  return [...byBucket.entries()]
    .map(([bucketStart, value]) => {
      const dt = new Date(bucketStart);
      const label = granularity === "hourly"
        ? `${dt.toLocaleDateString()} ${String(dt.getHours()).padStart(2, "0")}:00`
        : dt.toLocaleDateString();
      return {
        key: String(bucketStart),
        label,
        count: value.entries?.length || 0,
        byType: value.byType || {},
        entries: value.entries || []
      };
    })
    .sort((a, b) => Number(b.key) - Number(a.key));
}

export function buildAnalyticsCsv(analyticsBucketRows) {
  const headers = [
    "bucket",
    "timestamp",
    "timelineEvent",
    "ip",
    "userId",
    "scoreImpact",
    "cumulativeRisk",
    "actionsTaken",
    "details"
  ];
  const lines = [headers.join(",")];
  for (const row of analyticsBucketRows) {
    for (const entry of row.entries) {
      const cells = [
        `"${row.label.replaceAll("\"", "\"\"")}"`,
        `"${String(entry.timestamp || "").replaceAll("\"", "\"\"")}"`,
        `"${String(entry.event || "").replaceAll("\"", "\"\"")}"`,
        `"${String(entry.ip || "").replaceAll("\"", "\"\"")}"`,
        `"${String(entry.userId || "").replaceAll("\"", "\"\"")}"`,
        String(entry.scoreImpact ?? ""),
        String(entry.cumulativeRisk ?? ""),
        `"${(entry.actionsTaken || []).join(" | ").replaceAll("\"", "\"\"")}"`,
        `"${JSON.stringify(entry.details || {}).replaceAll("\"", "\"\"")}"`
      ];
      lines.push(cells.join(","));
    }
  }
  return lines.join("\n");
}
