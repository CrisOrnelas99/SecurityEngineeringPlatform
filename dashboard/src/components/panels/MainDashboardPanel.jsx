import React from "react";

export default function MainDashboardPanel({
  groupedRealAlerts,
  clearAllAlerts,
  alertStatus,
  formatEventTime,
  getIpDisplayInfo,
  expandedAlerts,
  toggleAlertDetails,
  deleteAlertById,
  normalizeActionName,
  renderAlertDetails,
  risk,
  topIp,
  blockedIps,
  blockIpInput,
  setBlockIpInput,
  addBlockedIp,
  blockStatus,
  unblockIp,
  attackPatterns,
  visibleTimeline,
  expandedTimeline,
  toggleTimelineDetails,
  renderTimelineDetails,
  normalizeEventName,
  isAdmin,
  onOpenTestDashboard
}) {
  return (
    <section style={{ marginTop: "1rem" }}>
      {isAdmin ? (
        <div className="actions" style={{ justifyContent: "flex-end", margin: "0 0 0.6rem 0" }}>
          <button type="button" className="danger-btn" onClick={clearAllAlerts}>Clear Alerts</button>
        </div>
      ) : null}
      <div className="grid cards main-dashboard-layout">
        <div className="card card-active-alerts">
        <div className="card-title-row">
          <h2>Active Alerts ({groupedRealAlerts.length})</h2>
          <div className="item-actions" />
        </div>
        {alertStatus ? <p className="small">{alertStatus}</p> : null}
        <div className="list">
          {groupedRealAlerts.map((group) => (
            <div className="item" key={group.groupId}>
              <div className="item-row">
                <div>
                  <span className={`badge ${group.alerts[0].riskLevel}`}>{group.alerts[0].riskLevel}</span> {group.eventName}
                </div>
                <div className="item-actions" />
              </div>
              <div className="small">
                Latest: {formatEventTime(group.alerts[0].timestamp)} | {getIpDisplayInfo(group.alerts[0].ip).version}: {getIpDisplayInfo(group.alerts[0].ip).value}
              </div>
              {group.alerts[0]?.details?.description ? (
                <div className="small">Description: {group.alerts[0].details.description}</div>
              ) : null}
              <div className="list" style={{ marginTop: "0.5rem" }}>
                {group.alerts.map((alert) => (
                  <div className="item" key={alert.id}>
                    <div className="item-row">
                      <div className="small">{formatEventTime(alert.timestamp)}</div>
                      <div className="item-actions">
                        <button
                          type="button"
                          className="ghost-btn"
                          onClick={() => toggleAlertDetails(alert.id)}
                        >
                          {expandedAlerts[alert.id] ? "Hide" : "Details"}
                        </button>
                        <button
                          type="button"
                          className="alert-delete-btn"
                          title="Delete alert"
                          onClick={() => deleteAlertById(alert.id)}
                        >
                          X
                        </button>
                      </div>
                    </div>
                    <div className="small">
                      {getIpDisplayInfo(alert.ip).version}: {getIpDisplayInfo(alert.ip).value} | user: {alert.userId}
                    </div>
                    {alert?.details?.description ? (
                      <div className="small">Description: {alert.details.description}</div>
                    ) : null}
                    <div className="small">
                      Action Taken: {(alert.actionsTaken || []).length ? alert.actionsTaken.map(normalizeActionName).join(", ") : "NONE"}
                    </div>
                    {expandedAlerts[alert.id] ? renderAlertDetails(alert) : null}
                  </div>
                ))}
              </div>
            </div>
          ))}
          {!groupedRealAlerts.length ? (
            <div className="item"><div className="small">No active alerts.</div></div>
          ) : null}
        </div>
        </div>

        <div className="card card-risk">
        <h2>Risk Scores By IP ({risk.riskByIp.length})</h2>
        <div className="list">
          {risk.riskByIp.map((entry) => (
            <div className="item" key={entry.ip}>
              <div>{getIpDisplayInfo(entry.ip).version}: {getIpDisplayInfo(entry.ip).value}</div>
              <div className="small">score: {entry.score} <span className={`badge ${entry.riskLevel}`}>{entry.riskLevel}</span></div>
            </div>
          ))}
          {!risk.riskByIp.length ? (
            <div className="item"><div className="small">No risk entries.</div></div>
          ) : null}
        </div>
        {topIp && (
          <p className="small">
            Highest risk source: {getIpDisplayInfo(topIp.ip).version} {getIpDisplayInfo(topIp.ip).value} ({topIp.score})
          </p>
        )}
        </div>

        <div className="card card-blocked">
        <h2>Blocked IPs ({blockedIps.length})</h2>
        <div className="actions">
          <input
            className="inline-input"
            value={blockIpInput}
            onChange={(e) => setBlockIpInput(e.target.value)}
            placeholder="127.0.0.1 or ::1"
          />
          <button type="button" className="ghost-btn" onClick={addBlockedIp}>Block IP</button>
        </div>
        {blockStatus ? <p className="small">{blockStatus}</p> : null}
        <div className="list">
          {blockedIps.map((ip) => (
            <div className="item item-row" key={ip}>
              <span>{getIpDisplayInfo(ip).version}: {getIpDisplayInfo(ip).value}</span>
              <button type="button" className="alert-delete-btn" onClick={() => unblockIp(ip)}>Unblock</button>
            </div>
          ))}
          {!blockedIps.length ? (
            <div className="item"><div className="small">No blocked IPs.</div></div>
          ) : null}
        </div>
        </div>

        <div className="card card-patterns">
        <h2>Attack Patterns ({attackPatterns.length})</h2>
        <div className="list">
          {attackPatterns.map((pattern) => (
            <div className="item" key={pattern.pattern}>{pattern.pattern} ({pattern.count})</div>
          ))}
          {!attackPatterns.length ? (
            <div className="item"><div className="small">No attack patterns.</div></div>
          ) : null}
        </div>
        </div>

        <div className="card card-timeline">
        <div className="card-title-row">
          <h2>Incident Timeline ({visibleTimeline.length})</h2>
        </div>
        <div className="list">
          {visibleTimeline.map((entry, idx) => (
            <div className="item" key={`${entry.timestamp}-${idx}`}>
              <div className="item-row">
                <div>{normalizeEventName(entry.event)}</div>
                <button
                  type="button"
                  className="ghost-btn"
                  onClick={() => toggleTimelineDetails(`${entry.timestamp}-${idx}`)}
                >
                  {expandedTimeline[`${entry.timestamp}-${idx}`] ? "Hide" : "Details"}
                </button>
              </div>
              <div className="small">
                {formatEventTime(entry.timestamp)} | {getIpDisplayInfo(entry.ip).version}: {getIpDisplayInfo(entry.ip).value} | +{entry.scoreImpact}
              </div>
              {expandedTimeline[`${entry.timestamp}-${idx}`] ? renderTimelineDetails(entry) : null}
            </div>
          ))}
          {!visibleTimeline.length ? (
            <div className="item"><div className="small">No timeline events.</div></div>
          ) : null}
        </div>
        </div>
      </div>
      {isAdmin ? (
        <div className="card" style={{ marginTop: "1rem" }}>
          <div className="card-title-row">
            <h2>Admin Test Tools</h2>
            <button type="button" className="ghost-btn" onClick={onOpenTestDashboard}>
              Open Test Dashboard
            </button>
          </div>
          <p className="small">Use the test page for test IPs and validation events.</p>
        </div>
      ) : null}
    </section>
  );
}
