import React from "react";

export default function AnalyticsPanel({
  granularity,
  setGranularity,
  windowKey,
  setWindowKey,
  windowOptions,
  eventTypes,
  selectedTypes,
  toggleType,
  selectAllTypes,
  clearAllTypes,
  bucketRows,
  totalCount,
  formatEventTime,
  getIpDisplayInfo,
  formatDetailValue,
  normalizeEventName,
  normalizeActionName,
  onDownloadCsv,
  onPrint
}) {
  return (
    <section className="grid cards analytics-layout" style={{ marginTop: "1rem" }}>
      <div className="card analytics-report-card">
        <div className="card-title-row">
          <h2>Alert Analytics</h2>
          <div className="item-actions">
            <button type="button" className="ghost-btn" onClick={onDownloadCsv}>Download CSV</button>
            <button type="button" className="ghost-btn" onClick={onPrint}>Print</button>
          </div>
        </div>

        <div className="actions" style={{ marginBottom: "0.5rem" }}>
          <button
            type="button"
            className={granularity === "hourly" ? "active-tab" : "ghost-btn"}
            onClick={() => setGranularity("hourly")}
          >
            Hourly
          </button>
          <button
            type="button"
            className={granularity === "daily" ? "active-tab" : "ghost-btn"}
            onClick={() => setGranularity("daily")}
          >
            Daily
          </button>
          <select value={windowKey} onChange={(e) => setWindowKey(e.target.value)}>
            {windowOptions.map((opt) => (
              <option key={opt.value} value={opt.value}>{opt.label}</option>
            ))}
          </select>
        </div>

        <div className="small" style={{ marginBottom: "0.75rem" }}>
          Total alerts in range: {totalCount}
        </div>

        <div className="list">
          {bucketRows.map((row) => (
            <div className="item" key={row.key}>
              <div className="item-row">
                <strong>{row.label}</strong>
                <span className="small">{row.count} alert{row.count === 1 ? "" : "s"}</span>
              </div>
              <div className="analytics-entries" style={{ marginTop: "0.45rem" }}>
                {row.entries.map((entry, idx) => (
                  <div className="item" key={`${entry.timestamp}-${entry.event}-${idx}`}>
                    <div className="item-row">
                      <div>{normalizeEventName(entry.event)}</div>
                      <div className="small">{formatEventTime(entry.timestamp)}</div>
                    </div>
                    <div className="small">
                      {getIpDisplayInfo(entry.ip).version}: {getIpDisplayInfo(entry.ip).value} | user: {entry.userId || "anonymous"}
                    </div>
                    <div className="small">
                      Score Impact: +{entry.scoreImpact ?? 0} | Cumulative Risk: {entry.cumulativeRisk ?? "n/a"}
                    </div>
                    <div className="small">
                      Action Taken: {(entry.actionsTaken || []).length ? entry.actionsTaken.map(normalizeActionName).join(", ") : "NONE"}
                    </div>
                    <div className="small">
                      Details: {Object.entries(entry.details || {}).length
                        ? Object.entries(entry.details || {}).map(([k, v]) => `${k}=${formatDetailValue(k, v)}`).join(" | ")
                        : "none"}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          ))}
          {!bucketRows.length ? <div className="item"><div className="small">No alerts in selected range.</div></div> : null}
        </div>
      </div>

      <div className="card analytics-filter-card">
        <div className="card-title-row">
          <h2>Event Type Filter</h2>
          <div className="item-actions">
            <button type="button" className="ghost-btn" onClick={selectAllTypes}>Select All</button>
            <button type="button" className="ghost-btn" onClick={clearAllTypes}>Clear</button>
          </div>
        </div>
        <div className="list">
          {eventTypes.map((type) => (
            <label className="item item-row" key={type} style={{ cursor: "pointer" }}>
              <span>{type}</span>
              <input
                type="checkbox"
                checked={selectedTypes.includes(type)}
                onChange={() => toggleType(type)}
              />
            </label>
          ))}
          {!eventTypes.length ? <div className="item"><div className="small">No event types available.</div></div> : null}
        </div>
      </div>
    </section>
  );
}
