import React from "react";

export default function TestDashboardPanel({
  authState,
  groupedTestAlerts,
  clearTestAlerts,
  alertStatus,
  formatEventTime,
  getIpDisplayInfo,
  expandedAlerts,
  toggleAlertDetails,
  deleteAlertById,
  normalizeActionName,
  renderAlertDetails,
  testAlerts,
  testRiskByIp,
  testIps,
  testIpInput,
  setTestIpInput,
  addTestIp,
  blockStatus,
  removeTestIp,
  testAttackPatterns
}) {
  if (authState.user?.role !== "admin") {
    return (
      <section className="card">
        <h2>Test</h2>
        <p className="small">Admin access required.</p>
      </section>
    );
  }

  return (
    <section className="grid cards test-dashboard-layout" style={{ marginTop: "1rem" }}>
      <div className="card card-test-alerts">
        <div className="card-title-row">
          <h2>Test Alerts ({groupedTestAlerts.length})</h2>
          <div className="item-actions">
            <button type="button" className="danger-btn" onClick={clearTestAlerts}>
              Clear Alerts
            </button>
          </div>
        </div>
        {alertStatus ? <p className="small">{alertStatus}</p> : null}
        <div className="list">
          {groupedTestAlerts.map((group) => (
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
              <div className="small">Test IP traffic.</div>
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
                    <div className="small">Test IP traffic.</div>
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
          {!testAlerts.length ? (
            <div className="item"><div className="small">No test alerts.</div></div>
          ) : null}
        </div>
      </div>

      <div className="card card-test-risk">
        <h2>Test Risk Scores By IP ({testRiskByIp.length})</h2>
        <div className="list">
          {testRiskByIp.map((entry) => (
            <div className="item" key={entry.ip}>
              <div>{getIpDisplayInfo(entry.ip).version}: {getIpDisplayInfo(entry.ip).value}</div>
              <div className="small">score: {entry.score} <span className={`badge ${entry.riskLevel}`}>{entry.riskLevel}</span></div>
            </div>
          ))}
          {!testRiskByIp.length ? (
            <div className="item"><div className="small">No test risk entries.</div></div>
          ) : null}
        </div>
      </div>

      <div className="card card-test-ips">
        <h2>Test IPs ({testIps.length})</h2>
        <div className="actions">
          <input
            className="inline-input"
            value={testIpInput}
            onChange={(e) => setTestIpInput(e.target.value)}
            placeholder="127.0.0.1 or ::1"
          />
          <button type="button" className="ghost-btn" onClick={addTestIp}>Add Test IP</button>
        </div>
        {blockStatus ? <p className="small">{blockStatus}</p> : null}
        <div className="list">
          {testIps.map((ip) => (
            <div className="item item-row" key={`test-${ip}`}>
              <span>{getIpDisplayInfo(ip).version}: {getIpDisplayInfo(ip).value}</span>
              <button type="button" className="alert-delete-btn" onClick={() => removeTestIp(ip)}>Remove</button>
            </div>
          ))}
          {!testIps.length ? (
            <div className="item"><div className="small">No test IPs configured.</div></div>
          ) : null}
        </div>
      </div>

      <div className="card card-test-patterns">
        <h2>Test Attack Patterns ({testAttackPatterns.length})</h2>
        <div className="list">
          {testAttackPatterns.map((pattern) => (
            <div className="item" key={pattern.pattern}>{pattern.pattern} ({pattern.count})</div>
          ))}
          {!testAttackPatterns.length ? (
            <div className="item"><div className="small">No test attack patterns.</div></div>
          ) : null}
        </div>
      </div>
    </section>
  );
}
